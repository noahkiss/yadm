package textmerge

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
)

// ErrBinary reports an input that looks binary (it holds a NUL byte in its
// first 8000 bytes, the heuristic git uses). Binary files are not merged,
// diffed or patched line by line.
var ErrBinary = errors.New("textmerge: binary input")

// ErrPatch reports that a hand edit does not apply to the template.
var ErrPatch = errors.New("textmerge: edit does not apply to the template")

// Conflict markers.
const (
	MarkerOurs   = "<<<<<<< ours"
	MarkerSep    = "======="
	MarkerTheirs = ">>>>>>> theirs"
)

// Region is one conflicted region of a three-way merge. OursStart and
// OursEnd are 0-based line indexes into ours, end exclusive.
type Region struct {
	OursStart, OursEnd int
	Base, Ours, Theirs []byte
}

// IsBinary reports whether b looks binary.
func IsBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(b[:n], 0) >= 0
}

// lines splits b into lines that keep their terminators, so CRLF and a
// missing final newline survive a round trip.
func lines(b []byte) []string {
	var out []string
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, string(b))
			break
		}
		out = append(out, string(b[:i+1]))
		b = b[i+1:]
	}
	return out
}

func join(ls []string) []byte {
	var n int
	for _, l := range ls {
		n += len(l)
	}
	out := make([]byte, 0, n)
	for _, l := range ls {
		out = append(out, l...)
	}
	return out
}

type opKind byte

const (
	opEq  opKind = ' '
	opDel opKind = '-'
	opIns opKind = '+'
)

type op struct {
	kind opKind
	a, b int // line index in a (eq, del) and b (eq, ins)
}

// diffLines returns a shortest edit script from a to b (Myers).
func diffLines(a, b []string) []op {
	ids := map[string]int{}
	intern := func(ls []string) []int {
		out := make([]int, len(ls))
		for i, l := range ls {
			id, ok := ids[l]
			if !ok {
				id = len(ids)
				ids[l] = id
			}
			out[i] = id
		}
		return out
	}
	x, y := intern(a), intern(b)
	// Trim the common prefix and suffix to keep the search small.
	pre := 0
	for pre < len(x) && pre < len(y) && x[pre] == y[pre] {
		pre++
	}
	suf := 0
	for suf < len(x)-pre && suf < len(y)-pre && x[len(x)-1-suf] == y[len(y)-1-suf] {
		suf++
	}
	mid := myers(x[pre:len(x)-suf], y[pre:len(y)-suf])
	ops := make([]op, 0, pre+len(mid)+suf)
	for i := 0; i < pre; i++ {
		ops = append(ops, op{opEq, i, i})
	}
	for _, o := range mid {
		ops = append(ops, op{o.kind, o.a + pre, o.b + pre})
	}
	for i := 0; i < suf; i++ {
		ops = append(ops, op{opEq, len(x) - suf + i, len(y) - suf + i})
	}
	return ops
}

// maxEdit bounds the Myers search. Past it the inputs differ so much that a
// delete-all, insert-all script is as useful as a minimal one, and the search
// would cost quadratic memory.
const maxEdit = 1000

func trivial(n, m int) []op {
	out := make([]op, 0, n+m)
	for i := 0; i < n; i++ {
		out = append(out, op{opDel, i, 0})
	}
	for j := 0; j < m; j++ {
		out = append(out, op{opIns, n, j})
	}
	return out
}

func myers(a, b []int) []op {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil
	}
	max := n + m
	off := max
	v := make([]int, 2*max+2)
	var trace [][]int
	var dEnd int
outer:
	for d := 0; d <= max; d++ {
		if d > maxEdit {
			return trivial(n, m)
		}
		// Keep only the diagonals round d reads: k in [-d, d].
		trace = append(trace, append([]int(nil), v[off-d:off+d+1]...))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[off+k] = x
			if x >= n && y >= m {
				dEnd = d
				break outer
			}
		}
	}
	// Backtrack.
	var rev []op
	x, y := n, m
	for d := dEnd; d > 0; d-- {
		w := trace[d]
		vv := func(k int) int { return w[k+d] }
		k := x - y
		var pk int
		if k == -d || (k != d && vv(k-1) < vv(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := vv(pk)
		py := px - pk
		for x > px && y > py {
			x--
			y--
			rev = append(rev, op{opEq, x, y})
		}
		if x == px {
			y--
			rev = append(rev, op{opIns, x, y})
		} else {
			x--
			rev = append(rev, op{opDel, x, y})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, op{opEq, x, y})
	}
	out := make([]op, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

// hunk is a run of ops with context.
type hunk struct {
	ops []op
}

func hunks(ops []op, ctx int) []hunk {
	var out []hunk
	var ranges [][2]int
	for i := 0; i < len(ops); {
		if ops[i].kind == opEq {
			i++
			continue
		}
		j := i
		for j < len(ops) && ops[j].kind != opEq {
			j++
		}
		s, e := max(0, i-ctx), min(len(ops), j+ctx)
		if n := len(ranges); n > 0 && s <= ranges[n-1][1] {
			ranges[n-1][1] = e
		} else {
			ranges = append(ranges, [2]int{s, e})
		}
		i = j
	}
	for _, r := range ranges {
		out = append(out, hunk{ops: ops[r[0]:r[1]]})
	}
	return out
}

// Diff returns a unified diff of a and b with the given labels and 3 lines
// of context. Equal inputs give an empty string. A line without a final
// newline is marked as git marks it.
func Diff(aLabel, bLabel string, a, b []byte) (string, error) {
	if IsBinary(a) || IsBinary(b) {
		return "", ErrBinary
	}
	if bytes.Equal(a, b) {
		return "", nil
	}
	al, bl := lines(a), lines(b)
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", aLabel, bLabel)
	for _, h := range hunks(diffLines(al, bl), 3) {
		aStart, bStart, aN, bN := -1, -1, 0, 0
		for _, o := range h.ops {
			if o.kind != opIns {
				if aStart < 0 {
					aStart = o.a
				}
				aN++
			}
			if o.kind != opDel {
				if bStart < 0 {
					bStart = o.b
				}
				bN++
			}
		}
		if aStart < 0 {
			aStart = h.ops[0].a
		}
		if bStart < 0 {
			bStart = h.ops[0].b
		}
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", rng(aStart, aN), rng(bStart, bN))
		for _, o := range h.ops {
			var l string
			if o.kind == opIns {
				l = bl[o.b]
			} else {
				l = al[o.a]
			}
			sb.WriteByte(byte(o.kind))
			sb.WriteString(l)
			if !strings.HasSuffix(l, "\n") {
				sb.WriteString("\n\\ No newline at end of file\n")
			}
		}
	}
	return sb.String(), nil
}

func rng(start, n int) string {
	switch n {
	case 0:
		return fmt.Sprintf("%d,0", start)
	case 1:
		return fmt.Sprintf("%d", start+1)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}

// matches maps each base line to the line it matches in other, or -1.
func matches(base, other []string) []int {
	m := make([]int, len(base))
	for i := range m {
		m[i] = -1
	}
	for _, o := range diffLines(base, other) {
		if o.kind == opEq {
			m[o.a] = o.b
		}
	}
	return m
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Merge3 merges ours and theirs over base line by line. With no conflicts it
// returns the merged bytes. With conflicts it returns the merged bytes with
// conflict markers and the regions; callers that store the result must not
// commit marker text and hold the file instead.
func Merge3(base, ours, theirs []byte) (merged []byte, conflicts []Region, err error) {
	if IsBinary(base) || IsBinary(ours) || IsBinary(theirs) {
		return nil, nil, ErrBinary
	}
	O, A, B := lines(base), lines(ours), lines(theirs)
	ma, mb := matches(O, A), matches(O, B)
	eol := "\n"
	if strings.Count(string(ours), "\r\n")*2 > strings.Count(string(ours), "\n") {
		eol = "\r\n"
	}
	var out []string
	io, ia, ib := 0, 0, 0
	for io < len(O) || ia < len(A) || ib < len(B) {
		j := 0
		for io+j < len(O) && ia+j < len(A) && ib+j < len(B) && ma[io+j] == ia+j && mb[io+j] == ib+j {
			j++
		}
		if j > 0 {
			out = append(out, O[io:io+j]...)
			io, ia, ib = io+j, ia+j, ib+j
			continue
		}
		o, a, b := len(O), len(A), len(B)
		for k := io; k < len(O); k++ {
			if ma[k] >= 0 && mb[k] >= 0 {
				o, a, b = k, ma[k], mb[k]
				break
			}
		}
		co, ca, cb := O[io:o], A[ia:a], B[ib:b]
		switch {
		case equal(ca, co):
			out = append(out, cb...)
		case equal(cb, co), equal(ca, cb):
			out = append(out, ca...)
		default:
			conflicts = append(conflicts, Region{OursStart: ia, OursEnd: a, Base: join(co), Ours: join(ca), Theirs: join(cb)})
			out = append(out, MarkerOurs+eol)
			out = append(out, terminated(ca, eol)...)
			out = append(out, MarkerSep+eol)
			out = append(out, terminated(cb, eol)...)
			out = append(out, MarkerTheirs+eol)
		}
		io, ia, ib = o, a, b
	}
	return join(out), conflicts, nil
}

// terminated makes sure the last line ends with a newline, so a marker that
// follows starts on its own line.
func terminated(ls []string, eol string) []string {
	if len(ls) == 0 || strings.HasSuffix(ls[len(ls)-1], "\n") {
		return ls
	}
	out := append([]string(nil), ls...)
	out[len(out)-1] += eol
	return out
}

// PatchTemplate carries a hand edit of a rendered file back into its
// template. It diffs lastRender against target and applies each hunk to tmpl
// where the hunk's removed and context lines occur verbatim in tmpl. It fails
// when any hunk does not apply cleanly; the caller then re-renders and checks
// the round trip before accepting the result.
//
// A hunk applies at exactly one place in tmpl, after the previous hunk. When
// its full context (3 lines) does not match, the context shrinks to 2 and
// then 1 line; a hunk that only removes lines may also match with none. A
// hunk whose lines occur at more than one place is ambiguous and fails.
func PatchTemplate(tmpl, lastRender, target []byte) ([]byte, error) {
	if IsBinary(tmpl) || IsBinary(lastRender) || IsBinary(target) {
		return nil, ErrBinary
	}
	if bytes.Equal(lastRender, target) {
		return tmpl, nil
	}
	T, R, G := lines(tmpl), lines(lastRender), lines(target)
	ops := diffLines(R, G)
	var out []string
	pos := 0
	for _, h := range hunks(ops, 3) {
		at, old, repl, err := place(T, pos, h.ops, R, G)
		if err != nil {
			return nil, err
		}
		out = append(out, T[pos:at]...)
		out = append(out, repl...)
		pos = at + len(old)
	}
	out = append(out, T[pos:]...)
	return join(out), nil
}

// place finds where a hunk applies in T at or after pos, trying smaller
// contexts. It returns the position, the matched old lines and their
// replacement.
func place(T []string, pos int, ops []op, R, G []string) (int, []string, []string, error) {
	first, last := -1, -1
	for i, o := range ops {
		if o.kind != opEq {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	lead, trail := first, len(ops)-1-last
	hasDel := false
	for _, o := range ops[first : last+1] {
		if o.kind == opDel {
			hasDel = true
		}
	}
	for ctx := 3; ctx >= 0; ctx-- {
		if ctx == 0 && !hasDel {
			break
		}
		l, t := min(lead, ctx), min(trail, ctx)
		if ctx < 3 && l == lead && t == trail {
			continue // same as a larger context
		}
		sub := ops[first-l : last+1+t]
		var old, repl []string
		for _, o := range sub {
			switch o.kind {
			case opEq:
				old = append(old, R[o.a])
				repl = append(repl, G[o.b])
			case opDel:
				old = append(old, R[o.a])
			case opIns:
				repl = append(repl, G[o.b])
			}
		}
		if len(old) == 0 {
			// Pure insertion with no context: only an empty template fits.
			if len(T) == 0 {
				return 0, nil, repl, nil
			}
			return 0, nil, nil, fmt.Errorf("%w: an insertion has no context", ErrPatch)
		}
		found := -1
		for i := pos; i+len(old) <= len(T); i++ {
			if equal(T[i:i+len(old)], old) {
				if found >= 0 {
					return 0, nil, nil, fmt.Errorf("%w: a hunk matches more than one place", ErrPatch)
				}
				found = i
			}
		}
		if found >= 0 {
			return found, old, repl, nil
		}
	}
	return 0, nil, nil, fmt.Errorf("%w: a hunk's lines do not occur in the template", ErrPatch)
}
