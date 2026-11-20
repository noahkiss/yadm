package render

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
)

// Engine renders templates.
type Engine interface {
	Render(name string, src []byte, ctx model.Context) ([]byte, error)
}

// Error is a template error with its position.
type Error struct {
	Name string
	Line int
	Col  int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s:%d:%d: %s", e.Name, e.Line, e.Col, e.Msg) }

// New returns the engine. v checks condition names inside {% if %} and the
// fact and collector names of {{ machine.facts.KEY }} and {{ observed.NAME }}.
func New(v cond.Vocabulary) Engine { return engine{v: v} }

type engine struct{ v cond.Vocabulary }

// Render parses the whole template first, so a malformed block or an unknown
// name fails even inside a branch this machine does not take. It then
// evaluates the template for ctx. The output ends with exactly one newline:
// trailing newlines collapse to one, and one is added when missing.
func (e engine) Render(name string, src []byte, ctx model.Context) ([]byte, error) {
	nodes, err := parse(name, src, e.v)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := eval(name, nodes, ctx, &out); err != nil {
		return nil, err
	}
	b := bytes.TrimRight(out.Bytes(), "\n")
	return append(b, '\n'), nil
}

// Validate parses a template without rendering it. It reports the same
// syntax and name errors Render would, for any machine.
func Validate(name string, src []byte, v cond.Vocabulary) error {
	_, err := parse(name, src, v)
	return err
}

type pos struct{ line, col int }

type node interface{}

type textNode []byte

type varKind int

const (
	varLiteral varKind = iota
	varHome
	varUser
	varMachineID
	varMachineName
	varMachineOS
	varMachineArch
	varFact
	varObserved
)

type varNode struct {
	kind varKind
	arg  string // literal text, fact key or collector name
	at   pos
}

type branch struct {
	cond cond.Expr // nil for else
	body []node
}

type ifNode struct {
	branches []branch
	at       pos
}

// literals are the only strings {{ "..." }} may hold: the delimiters themselves.
var literals = map[string]bool{"{{": true, "}}": true, "{%": true, "%}": true, "{#": true, "#}": true}

type parser struct {
	name string
	src  []byte
	v    cond.Vocabulary
}

func (p *parser) posOf(off int) pos {
	line := 1 + bytes.Count(p.src[:off], []byte("\n"))
	col := off - (bytes.LastIndexByte(p.src[:off], '\n') + 1) + 1
	return pos{line, col}
}

func (p *parser) errAt(off int, format string, a ...any) error {
	at := p.posOf(off)
	return &Error{Name: p.name, Line: at.line, Col: at.col, Msg: fmt.Sprintf(format, a...)}
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// frame is an open {% if %} while parsing.
type frame struct {
	n       *ifNode
	off     int
	hasElse bool
	parent  *[]node
}

func parse(name string, src []byte, v cond.Vocabulary) ([]node, error) {
	p := &parser{name: name, src: src, v: v}
	var root []node
	cur := &root
	var stack []*frame
	textStart := 0
	lastTagEnd := 0
	i := 0
	for i < len(src) {
		j := bytes.IndexByte(src[i:], '{')
		if j < 0 {
			break
		}
		open := i + j
		if open+1 >= len(src) {
			break
		}
		kind := src[open+1]
		if kind != '{' && kind != '%' && kind != '#' {
			i = open + 1
			continue
		}
		closeDelim := map[byte]string{'{': "}}", '%': "%}", '#': "#}"}[kind]
		bodyStart := open + 2
		end, err := p.findClose(bodyStart, kind, closeDelim)
		if err != nil {
			return nil, err
		}
		tagEnd := end + 2
		body := string(src[bodyStart:end])

		// A block or comment tag alone on its line takes the whole line with it.
		textEnd := open
		if kind != '{' {
			ls := bytes.LastIndexByte(src[:open], '\n') + 1
			alone := ls >= lastTagEnd
			for k := ls; alone && k < open; k++ {
				alone = isBlank(src[k])
			}
			k := tagEnd
			for k < len(src) && isBlank(src[k]) {
				k++
			}
			if alone && (k == len(src) || src[k] == '\n') {
				textEnd = ls
				if k < len(src) {
					k++
				}
				tagEnd = k
			}
		}
		if textEnd > textStart {
			*cur = append(*cur, textNode(src[textStart:textEnd]))
		}

		switch kind {
		case '#':
			// comment: emits nothing
		case '{':
			n, err := p.variable(body, bodyStart)
			if err != nil {
				return nil, err
			}
			*cur = append(*cur, n)
		case '%':
			word, rest := splitWord(body)
			restOff := bodyStart + strings.Index(body, word) + len(word)
			switch word {
			case "if":
				c, err := p.cond(rest, restOff)
				if err != nil {
					return nil, err
				}
				n := &ifNode{branches: []branch{{cond: c}}, at: p.posOf(open)}
				*cur = append(*cur, n)
				stack = append(stack, &frame{n: n, off: open, parent: cur})
				cur = &n.branches[0].body
			case "elif":
				if len(stack) == 0 {
					return nil, p.errAt(open, "elif without if")
				}
				f := stack[len(stack)-1]
				if f.hasElse {
					return nil, p.errAt(open, "elif after else")
				}
				c, err := p.cond(rest, restOff)
				if err != nil {
					return nil, err
				}
				f.n.branches = append(f.n.branches, branch{cond: c})
				cur = &f.n.branches[len(f.n.branches)-1].body
			case "else":
				if len(stack) == 0 {
					return nil, p.errAt(open, "else without if")
				}
				if strings.TrimSpace(rest) != "" {
					return nil, p.errAt(restOff, "else takes no condition")
				}
				f := stack[len(stack)-1]
				if f.hasElse {
					return nil, p.errAt(open, "second else")
				}
				f.hasElse = true
				f.n.branches = append(f.n.branches, branch{})
				cur = &f.n.branches[len(f.n.branches)-1].body
			case "endif":
				if len(stack) == 0 {
					return nil, p.errAt(open, "endif without if")
				}
				if strings.TrimSpace(rest) != "" {
					return nil, p.errAt(restOff, "endif takes nothing")
				}
				f := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				cur = f.parent
			case "":
				return nil, p.errAt(open, "empty block tag")
			default:
				return nil, p.errAt(bodyStart+strings.Index(body, word), "unknown directive %q", word)
			}
		}
		i = tagEnd
		textStart = tagEnd
		lastTagEnd = tagEnd
	}
	if len(stack) > 0 {
		return nil, p.errAt(stack[len(stack)-1].off, "if without endif")
	}
	if textStart < len(src) {
		*cur = append(*cur, textNode(src[textStart:]))
	}
	return root, nil
}

// findClose finds the closing delimiter of a tag that opens at from-2. A tag
// may not span lines. Inside {{ }}, a double-quoted literal may hold "}}".
func (p *parser) findClose(from int, kind byte, delim string) (int, error) {
	src := p.src
	k := from
	if kind == '{' {
		for k < len(src) && isBlank(src[k]) {
			k++
		}
		if k < len(src) && src[k] == '"' {
			q := bytes.IndexAny(src[k+1:], "\"\n")
			if q < 0 || src[k+1+q] == '\n' {
				return 0, p.errAt(k, "unterminated string")
			}
			k = k + 1 + q + 1
		}
	}
	for ; k+1 < len(src); k++ {
		if src[k] == '\n' {
			break
		}
		if src[k] == delim[0] && src[k+1] == delim[1] {
			return k, nil
		}
	}
	return 0, p.errAt(from-2, "unterminated %q: want %q on the same line", "{"+string(kind), delim)
}

func splitWord(s string) (word, rest string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

func (p *parser) cond(src string, off int) (cond.Expr, error) {
	if strings.TrimSpace(src) == "" {
		return nil, p.errAt(off, "if needs a condition")
	}
	e, err := cond.Parse(src, p.v)
	if err != nil {
		var ce *cond.Error
		if errors.As(err, &ce) {
			return nil, p.errAt(off+ce.Offset, "%s", ce.Msg)
		}
		return nil, p.errAt(off, "%v", err)
	}
	return e, nil
}

func (p *parser) variable(body string, off int) (node, error) {
	lead := len(body) - len(strings.TrimLeft(body, " \t"))
	s := strings.TrimSpace(body)
	at := p.posOf(off + lead)
	n := varNode{at: at}
	switch {
	case s == "":
		return nil, p.errAt(off-2, "empty expression")
	case strings.HasPrefix(s, `"`):
		lit, ok := strings.CutSuffix(s[1:], `"`)
		if !ok || !literals[lit] {
			return nil, p.errAt(off+lead, "a string may only be one of the delimiters, such as \"{{\"")
		}
		n.kind, n.arg = varLiteral, lit
	case s == "home":
		n.kind = varHome
	case s == "user":
		n.kind = varUser
	case s == "machine.id":
		n.kind = varMachineID
	case s == "machine.name":
		n.kind = varMachineName
	case s == "machine.os":
		n.kind = varMachineOS
	case s == "machine.arch":
		n.kind = varMachineArch
	case strings.HasPrefix(s, "machine.facts."):
		k := strings.TrimPrefix(s, "machine.facts.")
		if !validName(k) {
			return nil, p.errAt(off+lead, "bad fact key %q", k)
		}
		if !p.v.FactKeys[k] {
			return nil, p.errAt(off+lead, "unknown fact %q", k)
		}
		n.kind, n.arg = varFact, k
	case strings.HasPrefix(s, "observed."):
		c := strings.TrimPrefix(s, "observed.")
		if !validName(c) {
			return nil, p.errAt(off+lead, "bad collector name %q", c)
		}
		if !p.v.Collectors[c] {
			return nil, p.errAt(off+lead, "unknown collector %q", c)
		}
		n.kind, n.arg = varObserved, c
	default:
		return nil, p.errAt(off+lead, "unknown variable %q", s)
	}
	return n, nil
}

// validName rejects names with spaces, filters or other punctuation.
func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		ok := r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'
		if !ok {
			return false
		}
	}
	return true
}

func eval(name string, nodes []node, ctx model.Context, out *bytes.Buffer) error {
	for _, n := range nodes {
		switch n := n.(type) {
		case textNode:
			out.Write(n)
		case varNode:
			s, err := value(n, ctx)
			if err != nil {
				return &Error{Name: name, Line: n.at.line, Col: n.at.col, Msg: err.Error()}
			}
			out.WriteString(s)
		case *ifNode:
			for _, b := range n.branches {
				if b.cond == nil || b.cond.Eval(ctx) {
					if err := eval(name, b.body, ctx, out); err != nil {
						return err
					}
					break
				}
			}
		}
	}
	return nil
}

func value(n varNode, ctx model.Context) (string, error) {
	m := ctx.Machine
	switch n.kind {
	case varLiteral:
		return n.arg, nil
	case varHome:
		if ctx.Home == "" {
			return "", errors.New("home is not set")
		}
		return ctx.Home, nil
	case varUser:
		if ctx.User == "" {
			return "", errors.New("user is not set")
		}
		return ctx.User, nil
	case varMachineID:
		return string(m.ID), nil
	case varMachineName:
		return m.Name, nil
	case varMachineOS:
		return m.OS, nil
	case varMachineArch:
		return m.Arch, nil
	case varFact:
		v, ok := m.Facts[n.arg]
		if !ok {
			return "", fmt.Errorf("fact %q is not declared for machine %q", n.arg, m.Name)
		}
		return v, nil
	case varObserved:
		f, ok := ctx.Observed[n.arg]
		if !ok {
			return "", fmt.Errorf("collector %q has no observed value on this machine", n.arg)
		}
		if f.Error != "" {
			return "", fmt.Errorf("collector %q failed: %s", n.arg, f.Error)
		}
		return strings.Join(f.Items, "\n"), nil
	}
	return "", fmt.Errorf("internal: unknown variable kind %d", n.kind)
}
