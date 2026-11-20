package cond

import (
	"fmt"
	"slices"
	"strings"

	"github.com/noahkiss/yadm/internal/model"
)

// Vocabulary lists the names a condition may mention. Build it from the fleet file.
type Vocabulary struct {
	Types      map[string]bool
	FactKeys   map[string]bool
	Collectors map[string]bool
	// Enclaves lists the types declared as enclaves. Conditions never read
	// it; package manifest uses it to check `enclave` and `seal` names.
	// Nil means unknown, and that check is skipped.
	Enclaves map[string]bool
}

// Expr is a parsed condition.
type Expr interface {
	Eval(ctx model.Context) bool
	String() string
}

// Error reports a parse failure at a byte offset in the source string.
type Error struct {
	Src    string
	Offset int
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("condition %q at %d: %s", e.Src, e.Offset, e.Msg) }

// maxDepth bounds nesting so a hostile condition cannot exhaust the stack.
const maxDepth = 64

// Parse parses src and checks every name against v. An empty src means Always.
// A src that holds only whitespace is an error.
func Parse(src string, v Vocabulary) (Expr, error) {
	if src == "" {
		return Always(), nil
	}
	p := &parser{src: src, v: v}
	if err := p.lex(); err != nil {
		return nil, err
	}
	if len(p.toks) == 0 {
		return nil, p.errAt(0, "empty condition")
	}
	e, err := p.parseOr(0)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		t := p.toks[p.pos]
		return nil, p.errAt(t.off, fmt.Sprintf("unexpected %q", t.text))
	}
	return e, nil
}

// Always returns the condition that matches every machine.
func Always() Expr { return always{} }

type always struct{}

func (always) Eval(model.Context) bool { return true }
func (always) String() string          { return "true" }

type never struct{}

func (never) Eval(model.Context) bool { return false }
func (never) String() string          { return "false" }

// Precedence levels for String: higher binds tighter.
const (
	precOr = iota + 1
	precAnd
	precUnary
)

func prec(e Expr) int {
	switch e.(type) {
	case orExpr:
		return precOr
	case andExpr:
		return precAnd
	}
	return precUnary
}

func wrap(e Expr, min int) string {
	if prec(e) < min {
		return "(" + e.String() + ")"
	}
	return e.String()
}

type notExpr struct{ x Expr }

func (n notExpr) Eval(c model.Context) bool { return !n.x.Eval(c) }
func (n notExpr) String() string            { return "!" + wrap(n.x, precUnary) }

type andExpr struct{ l, r Expr }

func (a andExpr) Eval(c model.Context) bool { return a.l.Eval(c) && a.r.Eval(c) }
func (a andExpr) String() string            { return wrap(a.l, precAnd) + " & " + wrap(a.r, precUnary) }

type orExpr struct{ l, r Expr }

func (o orExpr) Eval(c model.Context) bool { return o.l.Eval(c) || o.r.Eval(c) }
func (o orExpr) String() string            { return wrap(o.l, precOr) + " | " + wrap(o.r, precAnd) }

type typeTerm struct{ name string }

func (t typeTerm) Eval(c model.Context) bool { return c.Machine.HasType(model.TypeName(t.name)) }
func (t typeTerm) String() string            { return "type:" + t.name }

type osTerm struct{ name string }

func (t osTerm) Eval(c model.Context) bool { return c.Machine.OS == t.name }
func (t osTerm) String() string            { return "os:" + t.name }

type archTerm struct{ name string }

func (t archTerm) Eval(c model.Context) bool { return c.Machine.Arch == t.name }
func (t archTerm) String() string            { return "arch:" + t.name }

type machineTerm struct{ name string }

func (t machineTerm) Eval(c model.Context) bool {
	return c.Machine.Name == t.name || slices.Contains(c.Machine.Nicknames, t.name)
}
func (t machineTerm) String() string { return "machine:" + t.name }

type factTerm struct {
	key, val string
	hasVal   bool
}

func (t factTerm) Eval(c model.Context) bool {
	v, ok := c.Machine.Facts[t.key]
	if !ok {
		return false
	}
	return !t.hasVal || v == t.val
}

func (t factTerm) String() string {
	if t.hasVal {
		return "fact:" + t.key + "=" + t.val
	}
	return "fact:" + t.key
}

type observedTerm struct{ collector, item string }

func (t observedTerm) Eval(c model.Context) bool {
	f, ok := c.Observed[t.collector]
	return ok && slices.Contains(f.Items, t.item)
}
func (t observedTerm) String() string { return "observed:" + t.collector + "=" + t.item }

type token struct {
	off  int
	text string // one of ! & | ( ) or a word
}

type parser struct {
	src  string
	v    Vocabulary
	toks []token
	pos  int
}

func (p *parser) errAt(off int, msg string) error { return &Error{Src: p.src, Offset: off, Msg: msg} }

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func isOp(c byte) bool { return c == '!' || c == '&' || c == '|' || c == '(' || c == ')' }

func (p *parser) lex() error {
	s := p.src
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case isSpace(c):
			i++
		case isOp(c):
			p.toks = append(p.toks, token{off: i, text: s[i : i+1]})
			i++
		default:
			j := i
			for j < len(s) && !isSpace(s[j]) && !isOp(s[j]) {
				if s[j] < 0x21 || s[j] == 0x7f {
					return p.errAt(j, "control character")
				}
				j++
			}
			p.toks = append(p.toks, token{off: i, text: s[i:j]})
			i = j
		}
	}
	return nil
}

func (p *parser) peek() (token, bool) {
	if p.pos < len(p.toks) {
		return p.toks[p.pos], true
	}
	return token{off: len(p.src)}, false
}

func (p *parser) parseOr(depth int) (Expr, error) {
	l, err := p.parseAnd(depth)
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.text != "|" {
			return l, nil
		}
		p.pos++
		r, err := p.parseAnd(depth)
		if err != nil {
			return nil, err
		}
		l = orExpr{l, r}
	}
}

func (p *parser) parseAnd(depth int) (Expr, error) {
	l, err := p.parseUnary(depth)
	if err != nil {
		return nil, err
	}
	for {
		t, ok := p.peek()
		if !ok || t.text != "&" {
			return l, nil
		}
		p.pos++
		r, err := p.parseUnary(depth)
		if err != nil {
			return nil, err
		}
		l = andExpr{l, r}
	}
}

func (p *parser) parseUnary(depth int) (Expr, error) {
	if depth > maxDepth {
		t, _ := p.peek()
		return nil, p.errAt(t.off, "condition nests too deeply")
	}
	t, ok := p.peek()
	if !ok {
		return nil, p.errAt(t.off, "expected a term, found the end")
	}
	switch t.text {
	case "!":
		p.pos++
		x, err := p.parseUnary(depth + 1)
		if err != nil {
			return nil, err
		}
		return notExpr{x}, nil
	case "(":
		p.pos++
		x, err := p.parseOr(depth + 1)
		if err != nil {
			return nil, err
		}
		c, ok := p.peek()
		if !ok || c.text != ")" {
			return nil, p.errAt(c.off, "expected \")\"")
		}
		p.pos++
		return x, nil
	case "&", "|", ")":
		return nil, p.errAt(t.off, fmt.Sprintf("expected a term, found %q", t.text))
	}
	p.pos++
	return p.term(t)
}

func (p *parser) term(t token) (Expr, error) {
	switch t.text {
	case "true":
		return always{}, nil
	case "false":
		return never{}, nil
	}
	kind, arg, ok := strings.Cut(t.text, ":")
	if !ok {
		return nil, p.errAt(t.off, fmt.Sprintf("unknown term %q: want kind:value", t.text))
	}
	argOff := t.off + len(kind) + 1
	if arg == "" {
		return nil, p.errAt(argOff, fmt.Sprintf("%s: needs a value", kind))
	}
	plain := func() error {
		if strings.Contains(arg, "=") {
			return p.errAt(argOff+strings.Index(arg, "="), fmt.Sprintf("%s: unexpected \"=\"", kind))
		}
		return nil
	}
	switch kind {
	case "type":
		if err := plain(); err != nil {
			return nil, err
		}
		if !p.v.Types[arg] {
			return nil, p.errAt(argOff, fmt.Sprintf("unknown type %q", arg))
		}
		return typeTerm{arg}, nil
	case "os":
		if err := plain(); err != nil {
			return nil, err
		}
		return osTerm{arg}, nil
	case "arch":
		if err := plain(); err != nil {
			return nil, err
		}
		return archTerm{arg}, nil
	case "machine":
		if err := plain(); err != nil {
			return nil, err
		}
		return machineTerm{arg}, nil
	case "fact":
		key, val, hasVal := strings.Cut(arg, "=")
		if key == "" {
			return nil, p.errAt(argOff, "fact: needs a key")
		}
		if hasVal && val == "" {
			return nil, p.errAt(argOff+len(key)+1, "fact: \"=\" needs a value")
		}
		if !p.v.FactKeys[key] {
			return nil, p.errAt(argOff, fmt.Sprintf("unknown fact %q", key))
		}
		return factTerm{key: key, val: val, hasVal: hasVal}, nil
	case "observed":
		col, item, hasItem := strings.Cut(arg, "=")
		if col == "" {
			return nil, p.errAt(argOff, "observed: needs a collector")
		}
		if !p.v.Collectors[col] {
			return nil, p.errAt(argOff, fmt.Sprintf("unknown collector %q", col))
		}
		if !hasItem || item == "" {
			return nil, p.errAt(argOff+len(col), "observed: needs \"=ITEM\"")
		}
		return observedTerm{collector: col, item: item}, nil
	}
	return nil, p.errAt(t.off, fmt.Sprintf("unknown term kind %q", kind))
}
