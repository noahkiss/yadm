package rules

import (
	"bytes"
	"sort"
	"strconv"
	"strings"
)

// Structural is the key-level three-way merger for JSON, JSONC and TOML. It
// satisfies the sync package's Structural interface.
type Structural struct{}

// Merge3 implements the sync package's Structural interface with Merge3.
func (Structural) Merge3(format string, volatile []string, base, ours, theirs []byte) ([]byte, bool, error) {
	return Merge3(format, volatile, base, ours, theirs)
}

// mergeOp is one change theirs made that the merge carries onto ours.
type mergeOp struct {
	path []string
	del  bool
}

// Merge3 merges a structured file key by key. It starts from ours, so ours'
// layout and comments stay byte for byte, and carries over each key theirs
// changed relative to base with the span editors: a replaced value, an
// inserted key or a deleted key. Objects and tables merge per key; arrays and
// scalars are single values. Edits to different keys never conflict.
//
// A key covered by a volatile path (keep and drop syntax) is machine-local:
// the result keeps ours, and a difference there is never a conflict.
//
// ok is false, with a nil error, when the merge cannot decide: a format
// without key rules, a side that does not parse, a key both sides changed
// differently (a delete against a change included), or an edit the span
// editors do not perform. err is non-nil only for a bad volatile path.
func Merge3(format string, volatile []string, base, ours, theirs []byte) ([]byte, bool, error) {
	f, err := formatFor(format)
	if err != nil {
		return nil, false, nil
	}
	vol, err := parsePatterns(volatile)
	if err != nil {
		return nil, false, err
	}
	if bytes.Equal(ours, theirs) {
		return ours, true, nil
	}
	bRoot, err := f.parse(base)
	if err != nil {
		return nil, false, nil
	}
	oRoot, err := f.parse(ours)
	if err != nil {
		return nil, false, nil
	}
	tRoot, err := f.parse(theirs)
	if err != nil {
		return nil, false, nil
	}
	m := &merger{vol: vol, base: base, ours: ours, theirs: theirs}
	if !isObject(bRoot) || !isObject(oRoot) || !isObject(tRoot) {
		// A non-object document is one value.
		bc, oc, tc := m.canon(bRoot, base, nil), m.canon(oRoot, ours, nil), m.canon(tRoot, theirs, nil)
		switch {
		case tc == bc || oc == tc:
			return ours, true, nil
		case oc == bc:
			return theirs, true, nil
		}
		return nil, false, nil
	}
	if !m.diff(bRoot, oRoot, tRoot, nil) {
		return nil, false, nil
	}
	if len(m.ops) == 0 {
		return ours, true, nil
	}
	out := ours
	var dels [][]string
	for _, op := range m.ops {
		if op.del {
			dels = append(dels, op.path)
			continue
		}
		if out, err = put(f, out, op.path, theirs, false); err != nil {
			return nil, false, nil
		}
	}
	if len(dels) > 0 {
		if out, err = deletePaths(f, out, dels, false); err != nil {
			return nil, false, nil
		}
	}
	// Fail closed: every carried key must now read as theirs.
	root, err := f.parse(out)
	if err != nil {
		return nil, false, nil
	}
	for _, op := range m.ops {
		got := find(root, op.path)
		want := find(tRoot, op.path)
		if op.del {
			if got != nil {
				return nil, false, nil
			}
			continue
		}
		if got == nil || m.canon(got, out, op.path) != m.canon(want, theirs, op.path) {
			return nil, false, nil
		}
	}
	return out, true, nil
}

type merger struct {
	vol                []pattern
	base, ours, theirs []byte
	ops                []mergeOp
}

func isObject(n *node) bool { return n != nil && n.kind == kObject }

// diff compares one object on the three sides and records theirs' changes.
// It reports false on a conflict. b may be nil (both sides added the object).
func (m *merger) diff(b, o, t *node, path []string) bool {
	var keys []string
	seen := map[string]bool{}
	for _, n := range []*node{t, o, b} {
		if n == nil {
			continue
		}
		for _, c := range n.children {
			if !seen[c.key] {
				seen[c.key] = true
				keys = append(keys, c.key)
			}
		}
	}
	for _, k := range keys {
		p := append(append([]string{}, path...), k)
		if cover(m.vol, p) == covFull {
			continue
		}
		bc, oc, tc := child(b, k), child(o, k), child(t, k)
		if isObject(oc) && isObject(tc) && (bc == nil || isObject(bc)) {
			if !m.diff(bc, oc, tc, p) {
				return false
			}
			continue
		}
		bv, ov, tv := m.canon(bc, m.base, p), m.canon(oc, m.ours, p), m.canon(tc, m.theirs, p)
		switch {
		case tv == bv, ov == tv:
			// theirs unchanged, or both sides agree: keep ours
		case ov == bv:
			m.ops = append(m.ops, mergeOp{path: p, del: tc == nil})
		default:
			return false
		}
	}
	return true
}

func child(n *node, k string) *node {
	if n == nil {
		return nil
	}
	return n.child(k)
}

// canon is a comparable form of a value: object key order does not count,
// array order does, scalars compare by their source spelling (strings by
// their decoded value). Volatile keys below path are left out. A missing
// node is "".
func (m *merger) canon(n *node, b []byte, path []string) string {
	if n == nil {
		return ""
	}
	var sb strings.Builder
	m.canonInto(&sb, n, b, path)
	return sb.String()
}

func (m *merger) canonInto(sb *strings.Builder, n *node, b []byte, path []string) {
	switch n.kind {
	case kObject:
		kids := append([]*node{}, n.children...)
		sort.SliceStable(kids, func(i, j int) bool { return kids[i].key < kids[j].key })
		sb.WriteString("{")
		for _, c := range kids {
			p := append(append([]string{}, path...), c.key)
			if len(m.vol) > 0 && cover(m.vol, p) == covFull {
				continue
			}
			sb.WriteString(strconv.Quote(c.key))
			sb.WriteString(":")
			m.canonInto(sb, c, b, p)
			sb.WriteString(",")
		}
		sb.WriteString("}")
	case kArray:
		sb.WriteString("[")
		for _, c := range n.children {
			m.canonInto(sb, c, b, append(append([]string{}, path...), c.key))
			sb.WriteString(",")
		}
		sb.WriteString("]")
	case kString:
		sb.WriteString("s")
		sb.WriteString(strconv.Quote(n.str))
	default:
		sb.WriteString("v")
		if n.vStart >= 0 && n.vEnd <= len(b) {
			sb.WriteString(strconv.Quote(string(bytes.TrimSpace(b[n.vStart:n.vEnd]))))
		}
	}
}
