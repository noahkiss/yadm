package rules

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

type kind uint8

const (
	kObject kind = iota
	kArray
	kString
	kOther
)

// node is one key or element of a parsed JSON, JSONC or TOML document, with
// the byte spans the editors need. A span of -1 is unknown.
type node struct {
	key      string
	kind     kind
	str      string // decoded value when kind == kString
	children []*node
	parent   *node

	start, end   int // the member: key start (or value start) to value end
	vStart, vEnd int // the value
	open, close  int // bracket positions of an inline container

	role tomlRole // TOML only
}

func newNode(key string, k kind) *node {
	return &node{key: key, kind: k, start: -1, end: -1, vStart: -1, vEnd: -1, open: -1, close: -1}
}

func (n *node) child(k string) *node {
	for _, c := range n.children {
		if c.key == k {
			return c
		}
	}
	return nil
}

func (n *node) add(c *node) {
	c.parent = n
	n.children = append(n.children, c)
}

func (n *node) path() []string {
	var out []string
	for c := n; c.parent != nil; c = c.parent {
		out = append([]string{c.key}, out...)
	}
	return out
}

// index of n among its parent's children.
func (n *node) index() int {
	for i, c := range n.parent.children {
		if c == n {
			return i
		}
	}
	return -1
}

// walk visits n and every descendant in document order.
func (n *node) walk(f func(*node)) {
	f(n)
	for _, c := range n.children {
		c.walk(f)
	}
}

// slot is where an insert goes: after prev, else before next, else at the
// end. Both are children of the insert's parent, or nil.
type slot struct {
	prev, next *node
	gap        []byte // comment lines between prev and the item in the source
}

func (s slot) indexes() (int, int) {
	p, n := -1, -1
	if s.prev != nil {
		p = s.prev.index()
	}
	if s.next != nil {
		n = s.next.index()
	}
	return p, n
}

// errUnsupported marks an edit the span editors do not perform. Callers see it
// wrapped in model.ErrNotImplemented.
var errUnsupported = errors.New("edit not supported")

// format is a format-preserving editor. Every method returns the full new
// document; callers re-parse after each edit.
type format interface {
	parse(b []byte) (*node, error)
	quote(s string) []byte
	// del removes n. ownComments also removes the comment lines directly
	// above it.
	del(b []byte, n *node, ownComments bool) ([]byte, error)
	// setString replaces the value of n with a string.
	setString(b []byte, n *node, s string) ([]byte, error)
	// replace replaces the value of n with the value of src from srcB.
	replace(b []byte, n *node, srcB []byte, src *node) ([]byte, error)
	// insert adds src (from srcB) below parent, at path rest relative to
	// parent, after the sibling at.prev or else before at.next.
	insert(b []byte, parent *node, at slot, rest []string, srcB []byte, src *node) ([]byte, error)
}

func formatFor(f string) (format, error) {
	switch f {
	case "json", "jsonc":
		return jsonFormat{}, nil
	case "toml":
		return tomlFormat{}, nil
	}
	return nil, fmt.Errorf("format %q has no key rules", f)
}

func splice(b []byte, from, to int, with []byte) []byte {
	out := make([]byte, 0, len(b)-(to-from)+len(with))
	out = append(out, b[:from]...)
	out = append(out, with...)
	return append(out, b[to:]...)
}

// lang describes comment syntax for the lexical helpers.
type lang struct {
	line  string // line comment token
	block bool   // /* */ comments
}

var (
	langJSON = lang{line: "//", block: true}
	langTOML = lang{line: "#"}
)

func isSpace(c byte) bool { return c == ' ' || c == '\t' }

func lineStart(b []byte, i int) int {
	for i > 0 && b[i-1] != '\n' {
		i--
	}
	return i
}

// lineEnd returns the index of the '\n' ending the line containing i, or len(b).
func lineEnd(b []byte, i int) int {
	if j := bytes.IndexByte(b[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(b)
}

func nextLine(b []byte, i int) int {
	e := lineEnd(b, i)
	if e < len(b) {
		return e + 1
	}
	return e
}

func onlySpaceBefore(b []byte, i int) bool {
	for j := lineStart(b, i); j < i; j++ {
		if !isSpace(b[j]) {
			return false
		}
	}
	return true
}

func indentAt(b []byte, i int) string {
	s := lineStart(b, i)
	j := s
	for j < len(b) && isSpace(b[j]) {
		j++
	}
	return string(b[s:j])
}

func eolAt(b []byte, i int) string {
	e := lineEnd(b, i)
	if e > 0 && e < len(b) && b[e-1] == '\r' {
		return "\r\n"
	}
	if e == len(b) {
		// last line: use the document's first line ending
		if k := bytes.IndexByte(b, '\n'); k > 0 && b[k-1] == '\r' {
			return "\r\n"
		}
	}
	return "\n"
}

// skipGap skips whitespace, newlines and comments from i.
func (l lang) skipGap(b []byte, i int) int {
	for i < len(b) {
		c := b[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.HasPrefix(string(b[i:min(len(b), i+len(l.line))]), l.line):
			i = lineEnd(b, i)
		case l.block && c == '/' && i+1 < len(b) && b[i+1] == '*':
			if k := bytes.Index(b[i+2:], []byte("*/")); k >= 0 {
				i = i + 2 + k + 2
			} else {
				return len(b)
			}
		default:
			return i
		}
	}
	return i
}

// restBlank reports whether the line from i on holds only spaces and a
// comment.
func (l lang) restBlank(b []byte, i int) bool {
	e := lineEnd(b, i)
	for i < e {
		c := b[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case strings.HasPrefix(string(b[i:e]), l.line):
			return true
		case l.block && c == '/' && i+1 < e && b[i+1] == '*':
			k := bytes.Index(b[i+2:e], []byte("*/"))
			if k < 0 {
				return false
			}
			i = i + 2 + k + 2
		default:
			return false
		}
	}
	return true
}

// commentLine reports whether the line starting at s is a comment-only line.
func (l lang) commentLine(b []byte, s int) bool {
	t := strings.TrimSpace(string(b[s:lineEnd(b, s)]))
	return strings.HasPrefix(t, l.line) || (l.block && strings.HasPrefix(t, "/*") && strings.HasSuffix(t, "*/"))
}

// ownedCommentStart moves start up over comment-only lines directly above.
func (l lang) ownedCommentStart(b []byte, start int) int {
	for start > 0 {
		prev := lineStart(b, start-1)
		if !l.commentLine(b, prev) {
			break
		}
		start = prev
	}
	return start
}

// commaAfter returns the index of a comma following position i (across gaps),
// or -1.
func (l lang) commaAfter(b []byte, i int) int {
	j := l.skipGap(b, i)
	if j < len(b) && b[j] == ',' {
		return j
	}
	return -1
}

// listDelete removes items[i] from a comma-separated list.
func (l lang) listDelete(b []byte, items []*node, i int, ownComments bool) ([]byte, error) {
	it := items[i]
	if it.start < 0 || it.end < 0 {
		return nil, errUnsupported
	}
	q := l.commaAfter(b, it.end)
	after := it.end
	if q >= 0 {
		after = q + 1
	}
	prevComma := -1
	if q < 0 && i > 0 {
		prevComma = l.commaAfter(b, items[i-1].end)
	}
	if onlySpaceBefore(b, it.start) && l.restBlank(b, after) {
		from := lineStart(b, it.start)
		if ownComments {
			from = l.ownedCommentStart(b, from)
		}
		out := splice(b, from, nextLine(b, after), nil)
		if prevComma >= 0 {
			out = splice(out, prevComma, prevComma+1, nil)
		}
		return out, nil
	}
	switch {
	case q >= 0:
		to := q + 1
		for to < len(b) && isSpace(b[to]) {
			to++
		}
		return splice(b, it.start, to, nil), nil
	case prevComma >= 0:
		return splice(b, prevComma, it.end, nil), nil
	default:
		return splice(b, it.start, it.end, nil), nil
	}
}

// listInsert inserts an item into a comma-separated list between open and
// close: after items[prev] when prev >= 0, else before items[next] when
// next >= 0, else at the end. text builds the item from the indentation it
// will sit at.
func (l lang) listInsert(b []byte, open, close int, items []*node, prev, next int, gap []byte, unit string, text func(indent string) string) ([]byte, error) {
	if open < 0 || close < 0 {
		return nil, errUnsupported
	}
	if len(items) == 0 {
		if bytes.IndexByte(b[open:close], '\n') >= 0 {
			ind := indentAt(b, close) + unit
			return splice(b, open+1, open+1, []byte(eolAt(b, open)+ind+text(ind))), nil
		}
		return splice(b, open+1, open+1, []byte(text(""))), nil
	}
	if prev < 0 && next >= 0 {
		it := items[next]
		if it.start < 0 {
			return nil, errUnsupported
		}
		if onlySpaceBefore(b, it.start) {
			ind := indentAt(b, it.start)
			return splice(b, lineStart(b, it.start), lineStart(b, it.start), []byte(ind+text(ind)+","+eolAt(b, it.start))), nil
		}
		return splice(b, it.start, it.start, []byte(text("")+", ")), nil
	}
	if prev < 0 {
		prev = len(items) - 1
	}
	anchor := items[prev]
	if anchor.start < 0 || anchor.end < 0 {
		return nil, errUnsupported
	}
	q := l.commaAfter(b, anchor.end)
	if onlySpaceBefore(b, anchor.start) && ((q < 0 && l.restBlank(b, anchor.end)) || (q >= 0 && l.restBlank(b, q+1))) {
		ind := indentAt(b, anchor.start)
		eol := eolAt(b, anchor.end)
		at := nextLine(b, anchor.end)
		if q >= 0 {
			at = nextLine(b, q)
		}
		// Comment lines that sat between the two items in the source stay
		// above the inserted item.
		if len(gap) > 0 && bytes.HasPrefix(b[at:], gap) {
			at += len(gap)
		}
		if q >= 0 {
			return splice(b, at, at, []byte(ind+text(ind)+","+eol)), nil
		}
		out := splice(b, at, at, []byte(ind+text(ind)+eol))
		return splice(out, anchor.end, anchor.end, []byte(",")), nil
	}
	if q >= 0 {
		return splice(b, q+1, q+1, []byte(" "+text("")+",")), nil
	}
	return splice(b, anchor.end, anchor.end, []byte(", "+text(""))), nil
}

// reindent shifts the continuation lines of raw from one indentation to another.
func reindent(raw []byte, from, to string) []byte {
	if from == to || bytes.IndexByte(raw, '\n') < 0 {
		return raw
	}
	lines := strings.Split(string(raw), "\n")
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], from) {
			lines[i] = to + lines[i][len(from):]
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// indentUnit guesses the document's indentation step.
func indentUnit(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimLeft(line, " \t")
		if t != "" && len(t) < len(line) {
			return line[:len(line)-len(t)]
		}
	}
	return "  "
}
