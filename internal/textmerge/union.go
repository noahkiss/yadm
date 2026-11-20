package textmerge

import (
	"bytes"
	"strings"
)

// Union is the line-set merge of a `merge = "union"` file: every line
// either side has, minus lines either side removed from base, each line
// once. Order: ours, then the lines only theirs has.
func Union(base, ours, theirs []byte) []byte {
	split := func(b []byte) []string {
		s := strings.TrimSuffix(string(b), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	set := func(ls []string) map[string]bool {
		m := map[string]bool{}
		for _, l := range ls {
			m[l] = true
		}
		return m
	}
	b, o, th := split(base), split(ours), split(theirs)
	inB, inO, inT := set(b), set(o), set(th)
	removed := func(l string) bool { return inB[l] && (!inO[l] || !inT[l]) }
	var out []string
	seen := map[string]bool{}
	for _, l := range append(o, th...) {
		if seen[l] || removed(l) {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	if len(out) == 0 {
		return []byte{}
	}
	var buf bytes.Buffer
	buf.WriteString(strings.Join(out, "\n"))
	buf.WriteByte('\n')
	return buf.Bytes()
}
