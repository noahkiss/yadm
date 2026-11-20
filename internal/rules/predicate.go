package rules

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// A predicate drop names array elements by their content instead of their
// index: `hooks.*[?command~=tool run]` selects, in every array that
// `hooks.*` matches, each element whose `command` field contains
// "tool run". The elements it selects are machine-local: capture removes
// them, and apply puts the live target's back in their place. Other elements
// of the array stay owned by the source as before.
//
//	ARRAY "[?" FIELD OP VALUE "]"
//	OP = "~=" (contains) | "==" (equals)
//
// FIELD is a key path inside the element, `*` included, so a nested field
// such as `hooks.*.command` matches when any value it reaches satisfies the
// test. An empty FIELD tests the element itself. VALUE runs to the closing
// bracket and is compared as written: a string field compares its decoded
// text, any other scalar its source spelling.

// predOps are the predicate operators, longest first.
var predOps = []string{"~=", "=="}

// predRule is one parsed predicate drop.
type predRule struct {
	src   string
	arr   pattern
	field *pattern // nil: the element itself
	op    string
	value string
}

// splitPredicate reports whether s is a predicate drop and parses it.
func splitPredicate(s string) (predRule, bool, error) {
	i := strings.Index(s, "[?")
	if i < 0 {
		return predRule{}, false, nil
	}
	if !strings.HasSuffix(s, "]") {
		return predRule{}, true, fmt.Errorf("drop %q: a predicate ends with \"]\"", s)
	}
	arr, err := parsePattern(s[:i])
	if err != nil {
		return predRule{}, true, fmt.Errorf("drop %q: %w", s, err)
	}
	body := s[i+2 : len(s)-1]
	at, op := -1, ""
	for j := 0; j+1 < len(body); j++ {
		for _, o := range predOps {
			if strings.HasPrefix(body[j:], o) {
				at, op = j, o
				break
			}
		}
		if at >= 0 {
			break
		}
	}
	if at < 0 {
		return predRule{}, true, fmt.Errorf("drop %q: a predicate needs ~= or ==", s)
	}
	r := predRule{src: s, arr: arr, op: op, value: body[at+len(op):]}
	if f := body[:at]; f != "" {
		fp, err := parsePattern(f)
		if err != nil {
			return predRule{}, true, fmt.Errorf("drop %q: field: %w", s, err)
		}
		r.field = &fp
	}
	if r.value == "" {
		return predRule{}, true, fmt.Errorf("drop %q: a predicate needs a value", s)
	}
	return r, true, nil
}

// matches reports whether element el of document b satisfies the predicate.
func (r predRule) matches(b []byte, el *node) bool {
	cands := []*node{el}
	if r.field != nil {
		cands = matchAll(el, *r.field)
	}
	for _, n := range cands {
		var text string
		switch {
		case n.kind == kString:
			text = n.str
		case n.kind == kOther && n.vStart >= 0 && n.vEnd <= len(b):
			text = string(b[n.vStart:n.vEnd])
		default:
			continue
		}
		if r.op == "==" && text == r.value || r.op == "~=" && strings.Contains(text, r.value) {
			return true
		}
	}
	return false
}

// predArrays returns every array the rules' array patterns match, in
// document order, each once.
func predArrays(root *node, rules []predRule) []*node {
	var out []*node
	seen := map[*node]bool{}
	for _, r := range rules {
		for _, n := range matchAll(root, r.arr) {
			if n.kind == kArray && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// predMatched reports, for each element of arr, whether a rule whose array
// pattern matches arr selects it.
func predMatched(b []byte, arr *node, rules []predRule) []bool {
	p := arr.path()
	out := make([]bool, len(arr.children))
	for _, r := range rules {
		if !r.arr.matches(p) {
			continue
		}
		for i, el := range arr.children {
			if !out[i] && r.matches(b, el) {
				out[i] = true
			}
		}
	}
	return out
}

// predPaths returns the concrete paths of every selected element of b, in
// document order.
func predPaths(f format, b []byte, rules []predRule) ([][]string, error) {
	root, err := f.parse(b)
	if err != nil {
		return nil, err
	}
	var out [][]string
	for _, arr := range predArrays(root, rules) {
		for i, m := range predMatched(b, arr, rules) {
			if m {
				out = append(out, arr.children[i].path())
			}
		}
	}
	return out, nil
}

// restorePredicates removes the selected elements from base and puts live's
// selected elements back in their places. A selected element goes right
// after the unselected element that precedes it in live, found in base by
// value; failing that, after as many owned elements as preceded it in live,
// capped by what base has. A capture followed by an apply therefore returns
// the same bytes, and an owned element added or removed upstream does not
// move the local ones. An array that base lacks is not created.
func (c *compiled) restorePredicates(base, live []byte) ([]byte, error) {
	gone, err := predPaths(c.f, base, c.preds)
	if err != nil {
		return nil, err
	}
	if base, err = deletePaths(c.f, base, gone, false); err != nil {
		return nil, err
	}
	lroot, err := c.f.parse(live)
	if err != nil {
		return nil, err
	}
	for _, arr := range predArrays(lroot, c.preds) {
		path := arr.path()
		broot, err := c.f.parse(base)
		if err != nil {
			return nil, err
		}
		barr := find(broot, path)
		if barr == nil || barr.kind != kArray {
			continue
		}
		owned := len(barr.children)
		sel := predMatched(live, arr, c.preds)
		unsel, inserted := 0, 0
		last := -1 // index in base of the element placed last
		var anchor *node
		for i, m := range sel {
			el := arr.children[i]
			if !m {
				unsel++
				anchor = el
				continue
			}
			at := min(unsel, owned) + inserted
			if anchor == nil {
				at = inserted
			} else if j := findElement(c.f, base, path, live, anchor, last+1); j >= 0 {
				at = j + 1
			}
			at = max(at, last+1)
			if base, err = insertElement(c.f, base, path, at, live, el); err != nil {
				return nil, err
			}
			inserted++
			last = at
		}
	}
	return base, nil
}

// findElement returns the index of the first element at or after from in
// the array at path of b whose value reads as el's in srcB, ignoring blanks,
// or -1.
func findElement(f format, b []byte, path []string, srcB []byte, el *node, from int) int {
	if el.vStart < 0 {
		return -1
	}
	root, err := f.parse(b)
	if err != nil {
		return -1
	}
	arr := find(root, path)
	if arr == nil {
		return -1
	}
	want := squeeze(srcB[el.vStart:el.vEnd])
	for j := max(from, 0); j < len(arr.children); j++ {
		c := arr.children[j]
		if c.vStart >= 0 && squeeze(b[c.vStart:c.vEnd]) == want {
			return j
		}
	}
	return -1
}

// squeeze drops blanks and line breaks, so two spellings of one value that
// differ only in layout compare equal.
func squeeze(b []byte) string {
	return strings.Join(strings.Fields(string(b)), "")
}

// insertElement inserts src (an array element of srcB) into the array at
// path in dst, at index at. Comment lines that sat directly above src in
// srcB, and that dst kept when the element left, stay above it; comment
// lines that belong to the following element stay with that element.
func insertElement(f format, dst []byte, path []string, at int, srcB []byte, src *node) ([]byte, error) {
	l := langTOML
	if _, ok := f.(jsonFormat); ok {
		l = langJSON
	}
	return edit(f, dst, func(root *node) ([]byte, error) {
		par := find(root, path)
		if par == nil || par.kind != kArray {
			return nil, fmt.Errorf("array %s is gone", joinPath(path))
		}
		var sl slot
		sl.tail = commentTail(f, srcB, src)
		if i := src.index(); i > 0 {
			sl.gap = commentGap(f, srcB, src.parent.children[i-1], src)
		}
		if at > 0 && at <= len(par.children) {
			sl.prev = par.children[at-1]
			return f.insert(dst, par, sl, []string{src.key}, srcB, src)
		}
		if len(par.children) == 0 {
			return f.insert(dst, par, sl, []string{src.key}, srcB, src)
		}
		next := par.children[0]
		if next.start < 0 || src.start < 0 || src.vStart < 0 || !onlySpaceBefore(dst, next.start) || !onlySpaceBefore(srcB, src.start) {
			sl.next = next
			return f.insert(dst, par, sl, []string{src.key}, srcB, src)
		}
		// The first element: it goes above the comment lines that belong
		// to next, and below the ones srcB had above src itself.
		lead := srcB[l.ownedCommentStart(srcB, lineStart(srcB, src.start)):lineStart(srcB, src.start)]
		pos := l.ownedCommentStart(dst, lineStart(dst, next.start))
		if pos < par.open {
			pos = lineStart(dst, next.start)
		}
		if len(lead) > 0 && bytes.HasPrefix(dst[pos:], lead) {
			pos += len(lead)
		}
		ind := indentAt(dst, next.start)
		text := reindent(srcB[src.start:src.end], indentAt(srcB, src.start), ind)
		return splice(dst, pos, pos, []byte(ind+string(text)+","+string(sl.tail)+eolAt(dst, next.start))), nil
	})
}
