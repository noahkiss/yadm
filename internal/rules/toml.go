package rules

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// tomlRole says how a TOML node is written, which decides how it is edited.
type tomlRole uint8

const (
	tNone        tomlRole = iota
	tRoot                 // the document
	tHeader               // a [table] or one [[array]] element: a section
	tImplicit             // a table only named as the parent of a header
	tDotted               // a table defined by a dotted key
	tKV                   // a key = value line in a section
	tInline               // a member of an inline table
	tElem                 // an element of an inline array
	tArrayTables          // the array behind [[name]] headers
)

// tomlFormat is the TOML span editor. go-toml's unstable parser supplies the
// syntax tree and key-value spans; container spans come from scanning.
type tomlFormat struct{}

type tbuild struct {
	b       []byte
	p       *unstable.Parser
	root    *node
	headers []*node // in document order, with start = section start
}

func (tomlFormat) parse(b []byte) (*node, error) {
	// Decoding with go-toml catches semantic errors (redefinitions) that the
	// unstable parser leaves to its caller.
	var v map[string]any
	if err := toml.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("toml: %w", err)
	}
	p := &unstable.Parser{KeepComments: true}
	p.Reset(b)
	tb := &tbuild{b: b, p: p, root: newNode("", kObject)}
	tb.root.role = tRoot
	tb.root.start, tb.root.end = 0, len(b)
	cur := tb.root
	for p.NextExpression() {
		e := p.Expression()
		switch e.Kind {
		case unstable.Comment:
		case unstable.Table, unstable.ArrayTable:
			keys, firstKey := tb.keys(e.Key())
			n, err := tb.header(keys, e.Kind == unstable.ArrayTable)
			if err != nil {
				return nil, err
			}
			br := firstKey
			for br > 0 && b[br] != '[' {
				br--
			}
			if e.Kind == unstable.ArrayTable && br > 0 && b[br-1] == '[' {
				br--
			}
			n.start = lineStart(b, br)
			tb.headers = append(tb.headers, n)
			cur = n
		case unstable.KeyValue:
			if _, err := tb.keyValue(cur, e, tKV); err != nil {
				return nil, err
			}
		}
	}
	if err := p.Error(); err != nil {
		return nil, fmt.Errorf("toml: %w", err)
	}
	for i, h := range tb.headers {
		end := len(b)
		if i+1 < len(tb.headers) {
			end = langTOML.ownedCommentStart(b, tb.headers[i+1].start)
			if end < h.start {
				end = tb.headers[i+1].start
			}
		}
		h.end = end
	}
	return tb.root, nil
}

func (tb *tbuild) keys(it unstable.Iterator) ([]string, int) {
	var out []string
	first := -1
	for it.Next() {
		k := it.Node()
		if first < 0 {
			first = int(k.Raw.Offset)
		}
		out = append(out, string(k.Data))
	}
	return out, first
}

// descend returns the child for one header path segment, creating an
// implicit table, and steps into the last element of an array of tables.
func descend(n *node, k string) *node {
	c := n.child(k)
	if c == nil {
		c = newNode(k, kObject)
		c.role = tImplicit
		n.add(c)
	}
	if c.role == tArrayTables && len(c.children) > 0 {
		return c.children[len(c.children)-1]
	}
	return c
}

func (tb *tbuild) header(keys []string, array bool) (*node, error) {
	n := tb.root
	for _, k := range keys[:len(keys)-1] {
		n = descend(n, k)
	}
	last := keys[len(keys)-1]
	if array {
		arr := n.child(last)
		if arr == nil {
			arr = newNode(last, kArray)
			arr.role = tArrayTables
			n.add(arr)
		}
		if arr.role != tArrayTables {
			return nil, fmt.Errorf("toml: %s is not an array of tables", strings.Join(keys, "."))
		}
		el := newNode(strconv.Itoa(len(arr.children)), kObject)
		el.role = tHeader
		arr.add(el)
		return el, nil
	}
	c := n.child(last)
	if c == nil {
		c = newNode(last, kObject)
		n.add(c)
	}
	c.role = tHeader
	return c, nil
}

// keyValue adds a key-value expression below parent.
func (tb *tbuild) keyValue(parent *node, e *unstable.Node, role tomlRole) (*node, error) {
	keys, _ := tb.keys(e.Key())
	n := parent
	for _, k := range keys[:len(keys)-1] {
		c := n.child(k)
		if c == nil {
			c = newNode(k, kObject)
			c.role = tDotted
			n.add(c)
		}
		n = c
	}
	if len(keys) > 1 && role == tInline {
		role = tNone // a dotted member of an inline table is not a list item
	}
	start := int(e.Raw.Offset)
	end := start + int(e.Raw.Length)
	// The value starts after '=' that follows the last key.
	var lastKey *unstable.Node
	it := e.Key()
	for it.Next() {
		lastKey = it.Node()
	}
	j := int(lastKey.Raw.Offset + lastKey.Raw.Length)
	for j < end && tb.b[j] != '=' {
		j++
	}
	j++
	for j < end && isSpace(tb.b[j]) {
		j++
	}
	v, err := tb.value(e.Value(), j, end)
	if err != nil {
		return nil, err
	}
	v.key = keys[len(keys)-1]
	v.role = role
	v.start, v.end = start, end
	n.add(v)
	return v, nil
}

// value builds a node for a value spanning [s, e).
func (tb *tbuild) value(a *unstable.Node, s, e int) (*node, error) {
	switch a.Kind {
	case unstable.String:
		n := newNode("", kString)
		n.str = string(a.Data)
		n.vStart, n.vEnd = s, e
		return n, nil
	case unstable.Array:
		n := newNode("", kArray)
		n.vStart, n.vEnd, n.open, n.close = s, e, s, e-1
		j := s + 1
		idx := 0
		for c := a.Child(); c != nil; c = c.Next() {
			if c.Kind == unstable.Comment {
				continue
			}
			j = langTOML.skipGap(tb.b, j)
			es := j
			var ee int
			switch c.Kind {
			case unstable.Array, unstable.InlineTable:
				ee = skipContainer(tb.b, es)
			default:
				es = int(c.Raw.Offset)
				ee = es + int(c.Raw.Length)
			}
			ch, err := tb.value(c, es, ee)
			if err != nil {
				return nil, err
			}
			ch.key = strconv.Itoa(idx)
			ch.role = tElem
			ch.start, ch.end = es, ee
			n.add(ch)
			idx++
			j = langTOML.skipGap(tb.b, ee)
			if j < len(tb.b) && tb.b[j] == ',' {
				j++
			}
		}
		return n, nil
	case unstable.InlineTable:
		n := newNode("", kObject)
		n.vStart, n.vEnd, n.open, n.close = s, e, s, e-1
		for c := a.Child(); c != nil; c = c.Next() {
			if c.Kind != unstable.KeyValue {
				continue
			}
			if _, err := tb.keyValue(n, c, tInline); err != nil {
				return nil, err
			}
		}
		return n, nil
	default:
		n := newNode("", kOther)
		n.vStart, n.vEnd = s, e
		return n, nil
	}
}

// skipContainer returns the offset after the array or inline table at i.
func skipContainer(b []byte, i int) int {
	depth := 0
	for i < len(b) {
		switch c := b[i]; c {
		case '[', '{':
			depth++
			i++
		case ']', '}':
			depth--
			i++
			if depth == 0 {
				return i
			}
		case '#':
			i = lineEnd(b, i)
		case '"', '\'':
			i = skipString(b, i)
		default:
			i++
		}
	}
	return i
}

func skipString(b []byte, i int) int {
	q := b[i]
	triple := i+2 < len(b) && b[i+1] == q && b[i+2] == q
	if triple {
		j := i + 3
		for j < len(b) {
			if q == '"' && b[j] == '\\' {
				j += 2
				continue
			}
			if j+2 < len(b) && b[j] == q && b[j+1] == q && b[j+2] == q {
				j += 3
				for j < len(b) && b[j] == q {
					j++
				}
				return j
			}
			j++
		}
		return j
	}
	j := i + 1
	for j < len(b) {
		if q == '"' && b[j] == '\\' {
			j += 2
			continue
		}
		if b[j] == q {
			return j + 1
		}
		j++
	}
	return j
}

func (tomlFormat) quote(s string) []byte {
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
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&sb, `\u%04X`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
	return []byte(sb.String())
}

func hasControl(s string) bool {
	for _, r := range s {
		if (r < 0x20 && r != '\t') || r == 0x7f {
			return true
		}
	}
	return false
}

func tomlKey(path []string) string {
	parts := make([]string, len(path))
	for i, k := range path {
		bare := k != ""
		for j := 0; j < len(k); j++ {
			c := k[j]
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				bare = false
				break
			}
		}
		if bare {
			parts[i] = k
		} else {
			parts[i] = string(tomlFormat{}.quote(k))
		}
	}
	return strings.Join(parts, ".")
}

type span struct{ from, to int }

// lineSpan is the whole-line range of a key-value line.
func lineSpan(b []byte, n *node, own bool) span {
	from, to := n.start, n.end
	if onlySpaceBefore(b, from) {
		from = lineStart(b, from)
		if own {
			from = langTOML.ownedCommentStart(b, from)
		}
	}
	if langTOML.restBlank(b, to) {
		to = nextLine(b, to)
	}
	return span{from, to}
}

// sectionSpans lists the byte ranges holding n and everything below it.
func sectionSpans(b []byte, n *node, own bool) []span {
	var out []span
	n.walk(func(c *node) {
		switch c.role {
		case tHeader:
			from := c.start
			if own && c == n {
				from = langTOML.ownedCommentStart(b, from)
			}
			out = append(out, span{from, c.end})
		case tKV:
			out = append(out, lineSpan(b, c, own && c == n))
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].from < out[j].from })
	var merged []span
	for _, s := range out {
		if len(merged) > 0 && s.from <= merged[len(merged)-1].to {
			if s.to > merged[len(merged)-1].to {
				merged[len(merged)-1].to = s.to
			}
			continue
		}
		merged = append(merged, s)
	}
	return merged
}

func (f tomlFormat) del(b []byte, n *node, own bool) ([]byte, error) {
	switch n.role {
	case tInline, tElem:
		return langTOML.listDelete(b, n.parent.children, n.index(), own)
	case tKV:
		s := lineSpan(b, n, own)
		return splice(b, s.from, s.to, nil), nil
	case tHeader, tImplicit, tDotted, tArrayTables:
		if n.role == tDotted && n.parent != nil && n.parent.open >= 0 {
			return nil, errUnsupported
		}
		spans := sectionSpans(b, n, own)
		out := b
		for i := len(spans) - 1; i >= 0; i-- {
			out = splice(out, spans[i].from, spans[i].to, nil)
		}
		return out, nil
	}
	return nil, errUnsupported
}

func (f tomlFormat) setString(b []byte, n *node, s string) ([]byte, error) {
	if n.vStart < 0 {
		return nil, errUnsupported
	}
	// Keep a literal string literal when the new value allows it, so sealing
	// and opening round-trip the quoting.
	raw := b[n.vStart:n.vEnd]
	if len(raw) >= 2 && raw[0] == '\'' && raw[1] != '\'' && !strings.ContainsAny(s, "'\r\n") && !hasControl(s) {
		return splice(b, n.vStart, n.vEnd, []byte("'"+s+"'")), nil
	}
	return splice(b, n.vStart, n.vEnd, f.quote(s)), nil
}

func (f tomlFormat) replace(b []byte, n *node, srcB []byte, src *node) ([]byte, error) {
	if n.vStart < 0 && src.vStart < 0 {
		// Tables: swap the section text in place when it differs.
		dspans, sspans := sectionSpans(b, n, false), sectionSpans(srcB, src, false)
		var dt, st []byte
		for _, s := range dspans {
			dt = append(dt, b[s.from:s.to]...)
		}
		for _, s := range sspans {
			st = append(st, srcB[s.from:s.to]...)
		}
		if string(dt) == string(st) {
			return b, nil
		}
		if len(dspans) == 0 {
			return nil, errUnsupported
		}
		out := b
		for i := len(dspans) - 1; i >= 1; i-- {
			out = splice(out, dspans[i].from, dspans[i].to, nil)
		}
		return splice(out, dspans[0].from, dspans[0].to, st), nil
	}
	if n.vStart < 0 || src.vStart < 0 {
		return nil, errUnsupported
	}
	raw := reindent(srcB[src.vStart:src.vEnd], indentAt(srcB, src.start), indentAt(b, n.start))
	return splice(b, n.vStart, n.vEnd, raw), nil
}

// sectionKVEnd returns the first and last key-value lines that belong directly
// to section node s (root or header), or nil when it has none.
func sectionKVEnd(s *node) (first, last *node) {
	var walk func(n *node)
	walk = func(n *node) {
		for _, c := range n.children {
			switch c.role {
			case tKV:
				if first == nil || c.start < first.start {
					first = c
				}
				if last == nil || c.end > last.end {
					last = c
				}
			case tDotted:
				walk(c)
			}
		}
	}
	walk(s)
	return first, last
}

func firstKV(n *node) *node {
	if n.role == tKV {
		return n
	}
	if n.role == tDotted {
		f, _ := sectionKVEnd(n)
		return f
	}
	return nil
}

func (f tomlFormat) insert(b []byte, parent *node, at slot, rest []string, srcB []byte, src *node) ([]byte, error) {
	// An inline container takes a list item.
	if parent.open >= 0 {
		if src.vStart < 0 {
			return nil, errUnsupported
		}
		raw := srcB[src.vStart:src.vEnd]
		prev, next := at.indexes()
		if parent.kind == kArray {
			if len(rest) != 1 {
				return nil, errUnsupported
			}
			return langTOML.listInsert(b, parent.open, parent.close, parent.children, prev, next, at.gap, indentUnit(b), func(string) string { return string(raw) })
		}
		for _, c := range parent.children {
			if c.role != tInline {
				return nil, errUnsupported
			}
		}
		return langTOML.listInsert(b, parent.open, parent.close, parent.children, prev, next, at.gap, indentUnit(b), func(string) string {
			return tomlKey(rest) + " = " + string(raw)
		})
	}
	if parent.role == tArrayTables || parent.kind != kObject {
		return nil, errUnsupported
	}
	// A section-level insert: climb to the section that owns parent.
	sec := parent
	keyPath := append([]string(nil), rest...)
	for sec.role == tDotted || sec.role == tImplicit {
		keyPath = append([]string{sec.key}, keyPath...)
		sec = sec.parent
	}
	if src.vStart < 0 {
		// A whole table moves as its section text, appended at the end.
		var text []byte
		for _, s := range sectionSpans(srcB, src, true) {
			text = append(text, srcB[s.from:s.to]...)
		}
		out := append([]byte(nil), b...)
		if len(out) > 0 && out[len(out)-1] != '\n' {
			out = append(out, eolAt(b, len(b))...)
		}
		if len(text) > 0 && text[len(text)-1] != '\n' {
			text = append(text, eolAt(b, len(b))...)
		}
		return append(out, text...), nil
	}
	raw := srcB[src.vStart:src.vEnd]
	line := func(ind, eol string) []byte {
		return []byte(ind + tomlKey(keyPath) + " = " + string(reindent(raw, indentAt(srcB, src.start), ind)) + eol)
	}
	if at.prev != nil && at.prev.role == tKV && sec == parent && onlySpaceBefore(b, at.prev.start) {
		e := lineSpan(b, at.prev, false).to
		if len(at.gap) > 0 && bytes.HasPrefix(b[e:], at.gap) {
			e += len(at.gap)
		}
		if e < len(b) || (len(b) > 0 && b[len(b)-1] == '\n') {
			return splice(b, e, e, line(indentAt(b, at.prev.start), eolAt(b, at.prev.start))), nil
		}
	}
	if at.prev == nil && at.next != nil && sec == parent {
		if kv := firstKV(at.next); kv != nil && onlySpaceBefore(b, kv.start) {
			from := lineStart(b, kv.start)
			return splice(b, from, from, line(indentAt(b, kv.start), eolAt(b, kv.start))), nil
		}
	}
	_, last := sectionKVEnd(sec)
	if last != nil {
		at := lineSpan(b, last, false).to
		eol := eolAt(b, last.start)
		if at == len(b) && (len(b) == 0 || b[len(b)-1] != '\n') {
			return append(append(append([]byte(nil), b...), eol...), line(indentAt(b, last.start), "")...), nil
		}
		return splice(b, at, at, line(indentAt(b, last.start), eol)), nil
	}
	if sec.role == tRoot {
		eol := eolAt(b, 0)
		if len(b) == 0 {
			return line("", eol), nil
		}
		return splice(b, 0, 0, line("", eol)), nil
	}
	// An empty section: right after its header line.
	hl := nextLine(b, sec.start)
	eol := eolAt(b, sec.start)
	if hl == len(b) && b[len(b)-1] != '\n' {
		return append(append(append([]byte(nil), b...), eol...), line("", "")...), nil
	}
	return splice(b, hl, hl, line("", eol)), nil
}
