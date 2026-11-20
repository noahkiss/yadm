package rules

import (
	"fmt"
	"strings"
)

// seg is one segment of a key-path pattern.
type seg struct {
	lit  string
	wild bool
}

// pattern is a parsed key path: segments separated by unescaped dots, `*` for
// any one segment, `\.`, `\*` and `\\` for literal characters.
type pattern struct {
	src  string
	segs []seg
}

func parsePattern(s string) (pattern, error) {
	if s == "" {
		return pattern{}, fmt.Errorf("empty key path")
	}
	var segs []seg
	var cur strings.Builder
	escaped := false // the current segment holds an escape
	flush := func() error {
		t := cur.String()
		if t == "" && !escaped {
			return fmt.Errorf("key path %q has an empty segment", s)
		}
		if t == "*" && !escaped {
			segs = append(segs, seg{wild: true})
		} else {
			segs = append(segs, seg{lit: t})
		}
		cur.Reset()
		escaped = false
		return nil
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return pattern{}, fmt.Errorf("key path %q ends in a backslash", s)
			}
			i++
			cur.WriteByte(s[i])
			escaped = true
		case c == '.':
			if err := flush(); err != nil {
				return pattern{}, err
			}
		default:
			cur.WriteByte(c)
		}
	}
	if err := flush(); err != nil {
		return pattern{}, err
	}
	return pattern{src: s, segs: segs}, nil
}

func parsePatterns(list []string) ([]pattern, error) {
	out := make([]pattern, 0, len(list))
	for _, s := range list {
		p, err := parsePattern(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// joinPath renders a concrete path as an escaped key path.
func joinPath(path []string) string {
	parts := make([]string, len(path))
	for i, k := range path {
		r := strings.NewReplacer(`\`, `\\`, `.`, `\.`, `*`, `\*`)
		parts[i] = r.Replace(k)
	}
	return strings.Join(parts, ".")
}

// matches reports whether p matches exactly the concrete path.
func (p pattern) matches(path []string) bool {
	if len(path) != len(p.segs) {
		return false
	}
	for i, s := range p.segs {
		if !s.wild && s.lit != path[i] {
			return false
		}
	}
	return true
}

// coverage of a path by a pattern set.
type coverage int

const (
	covNone    coverage = iota // no pattern reaches this path
	covPartial                 // a pattern may match below this path
	covFull                    // a pattern matches this path or an ancestor
)

func cover(pats []pattern, path []string) coverage {
	res := covNone
	for _, p := range pats {
		n := len(p.segs)
		if n > len(path) {
			n = len(path)
		}
		ok := true
		for i := 0; i < n; i++ {
			if !p.segs[i].wild && p.segs[i].lit != path[i] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if len(p.segs) <= len(path) {
			return covFull
		}
		res = covPartial
	}
	return res
}

// find returns the node at a concrete path, or nil.
func find(root *node, path []string) *node {
	n := root
	for _, k := range path {
		n = n.child(k)
		if n == nil {
			return nil
		}
	}
	return n
}

// matchAll returns every node matched by p, in document order.
func matchAll(root *node, p pattern) []*node {
	var out []*node
	var walk func(n *node, i int)
	walk = func(n *node, i int) {
		if i == len(p.segs) {
			out = append(out, n)
			return
		}
		s := p.segs[i]
		for _, c := range n.children {
			if s.wild || c.key == s.lit {
				walk(c, i+1)
			}
		}
	}
	walk(root, 0)
	return out
}
