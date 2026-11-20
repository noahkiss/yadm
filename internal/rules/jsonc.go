package rules

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// jsonFormat edits JSON and JSONC (comments and trailing commas) in place.
type jsonFormat struct{}

type jparser struct {
	b     []byte
	depth int
}

func (jsonFormat) parse(b []byte) (*node, error) {
	p := &jparser{b: b}
	i := langJSON.skipGap(b, 0)
	root := newNode("", kObject)
	n, j, err := p.value(i, root)
	if err != nil {
		return nil, err
	}
	if j = langJSON.skipGap(b, j); j != len(b) {
		return nil, fmt.Errorf("json: unexpected %q at byte %d", b[j], j)
	}
	// The root node is the document value.
	n.parent = nil
	n.start, n.end = n.vStart, n.vEnd
	return n, nil
}

func (p *jparser) errAt(i int, what string) error {
	return fmt.Errorf("json: %s at byte %d", what, i)
}

// value parses a value at i into a node (key left empty) and returns the
// position after it.
func (p *jparser) value(i int, _ *node) (*node, int, error) {
	b := p.b
	if i >= len(b) {
		return nil, i, p.errAt(i, "unexpected end of input")
	}
	switch c := b[i]; {
	case c == '{' || c == '[':
		p.depth++
		if p.depth > 512 {
			return nil, i, p.errAt(i, "nesting too deep")
		}
		defer func() { p.depth-- }()
		k := kObject
		closeCh := byte('}')
		if c == '[' {
			k, closeCh = kArray, ']'
		}
		n := newNode("", k)
		n.vStart, n.open = i, i
		j := langJSON.skipGap(b, i+1)
		idx := 0
		for {
			if j >= len(b) {
				return nil, j, p.errAt(j, "unterminated container")
			}
			if b[j] == closeCh {
				n.close, n.vEnd = j, j+1
				return n, j + 1, nil
			}
			var key string
			mstart := j
			if k == kObject {
				if b[j] != '"' {
					return nil, j, p.errAt(j, "expected key")
				}
				s, e, err := p.str(j)
				if err != nil {
					return nil, j, err
				}
				key = s
				j = langJSON.skipGap(b, e)
				if j >= len(b) || b[j] != ':' {
					return nil, j, p.errAt(j, "expected ':'")
				}
				j = langJSON.skipGap(b, j+1)
				if n.child(key) != nil {
					return nil, mstart, fmt.Errorf("json: duplicate key %q at byte %d", key, mstart)
				}
			} else {
				key = strconv.Itoa(idx)
			}
			ch, e, err := p.value(j, n)
			if err != nil {
				return nil, e, err
			}
			ch.key, ch.start, ch.end = key, mstart, ch.vEnd
			n.add(ch)
			idx++
			j = langJSON.skipGap(b, e)
			if j < len(b) && b[j] == ',' {
				j = langJSON.skipGap(b, j+1)
				continue
			}
			if j < len(b) && b[j] == closeCh {
				continue
			}
			return nil, j, p.errAt(j, "expected ',' or close")
		}
	case c == '"':
		s, e, err := p.str(i)
		if err != nil {
			return nil, i, err
		}
		n := newNode("", kString)
		n.str, n.vStart, n.vEnd = s, i, e
		return n, e, nil
	default:
		j := i
		for j < len(b) && (b[j] == '-' || b[j] == '+' || b[j] == '.' || (b[j] >= '0' && b[j] <= '9') || (b[j] >= 'a' && b[j] <= 'z') || (b[j] >= 'A' && b[j] <= 'Z')) {
			j++
		}
		lit := string(b[i:j])
		if lit == "" {
			return nil, i, p.errAt(i, "unexpected character")
		}
		if lit != "true" && lit != "false" && lit != "null" {
			var f json.Number
			if err := json.Unmarshal([]byte(lit), &f); err != nil {
				return nil, i, p.errAt(i, "bad literal")
			}
		}
		n := newNode("", kOther)
		n.vStart, n.vEnd = i, j
		return n, j, nil
	}
}

// str decodes a JSON string starting at i and returns it and the end offset.
func (p *jparser) str(i int) (string, int, error) {
	b := p.b
	j := i + 1
	for j < len(b) {
		switch b[j] {
		case '\\':
			j += 2
			continue
		case '"':
			var s string
			if err := json.Unmarshal(b[i:j+1], &s); err != nil {
				return "", i, p.errAt(i, "bad string")
			}
			return s, j + 1, nil
		case '\n':
			return "", i, p.errAt(j, "newline in string")
		}
		j++
	}
	return "", i, p.errAt(i, "unterminated string")
}

func (jsonFormat) quote(s string) []byte {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case utf8.RuneError:
			sb.WriteString(`�`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return []byte(sb.String())
}

func (f jsonFormat) del(b []byte, n *node, ownComments bool) ([]byte, error) {
	if n.parent == nil {
		return nil, fmt.Errorf("cannot delete the document root")
	}
	return langJSON.listDelete(b, n.parent.children, n.index(), ownComments)
}

func (f jsonFormat) setString(b []byte, n *node, s string) ([]byte, error) {
	return splice(b, n.vStart, n.vEnd, f.quote(s)), nil
}

func (f jsonFormat) replace(b []byte, n *node, srcB []byte, src *node) ([]byte, error) {
	raw := reindent(srcB[src.vStart:src.vEnd], indentAt(srcB, src.start), indentAt(b, n.start))
	return splice(b, n.vStart, n.vEnd, raw), nil
}

func (f jsonFormat) insert(b []byte, parent *node, at slot, rest []string, srcB []byte, src *node) ([]byte, error) {
	if parent.kind != kObject && parent.kind != kArray {
		return nil, fmt.Errorf("json: cannot insert below a scalar at %s", joinPath(parent.path()))
	}
	if parent.kind == kArray && len(rest) != 1 {
		return nil, errUnsupported
	}
	raw := srcB[src.vStart:src.vEnd]
	srcIndent := indentAt(srcB, src.start)
	prev, next := at.indexes()
	unit := indentUnit(b)
	return langJSON.listInsert(b, parent.open, parent.close, parent.children, prev, next, at, unit, func(ind string) string {
		if len(rest) == 1 && src.parent != nil && src.parent.kind == parent.kind && src.start >= 0 {
			// The member as the source spelled it, spacing included.
			return string(reindent(srcB[src.start:src.end], srcIndent, ind))
		}
		v := string(reindent(raw, srcIndent, ind))
		if parent.kind == kArray {
			return v
		}
		// Missing parents are built as compact objects.
		for k := len(rest) - 1; k >= 1; k-- {
			v = "{" + string(f.quote(rest[k])) + ": " + v + "}"
		}
		return string(f.quote(rest[0])) + ": " + v
	})
}
