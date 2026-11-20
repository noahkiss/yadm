package rules

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Spec is the intra-file part of a manifest entry.
//
// Source is the source path of the file the rules apply to. Every sealed
// value and region is bound to it (crypt.PartName), so a token copied into
// another file fails to open. Sealing or opening with an empty Source fails.
type Spec struct {
	Format  manifest.Format
	Keep    []string
	Drop    []string
	Seal    map[string]model.EnclaveName
	Regions bool
	Source  model.SourcePath
}

// SpecOf extracts the intra-file rules from a manifest entry. The caller
// sets Source to the resolved source path.
func SpecOf(e manifest.Entry) Spec {
	return Spec{Format: e.Format, Keep: e.Keep, Drop: e.Drop, Seal: e.Seal, Regions: e.Regions, Source: e.Source}
}

// SpecFor is SpecOf for a resolved entry, with its resolved source path.
func SpecFor(r manifest.Resolved) Spec {
	s := SpecOf(r.Entry)
	s.Source = r.Source
	return s
}

// ErrNoSource reports a seal or open with no source path in the Spec.
var ErrNoSource = errors.New("rules: the spec names no source path to bind sealed parts to")

// partName is the AD name of a sealed value (concrete key path) or region
// (label) in the file at src.
func partName(src model.SourcePath, keyOrLabel string) (string, error) {
	if src == "" {
		return "", ErrNoSource
	}
	return crypt.PartName(src, keyOrLabel), nil
}

// Empty reports whether the spec has no intra-file rules.
func (s Spec) Empty() bool {
	return len(s.Keep) == 0 && len(s.Drop) == 0 && len(s.Seal) == 0 && !s.Regions
}

// Sealer seals and opens parts of files. crypt.Set implements it.
//
// A value's plaintext is the decoded string, without quotes. keyPath is
// crypt.PartName of the source path and the concrete key path (escaped and
// dot-joined; never the manifest pattern), so each value has its own
// binding. A region's label argument is crypt.PartName of the source path
// and the region label. A region body is the exact bytes between the marker
// lines. SealRegion returns "yadm:sealed 1 <epoch> <base64>" without a
// comment prefix.
type Sealer interface {
	CanOpen(e model.EnclaveName) bool
	SealValue(e model.EnclaveName, keyPath string, plaintext []byte) (string, error)
	OpenValue(e model.EnclaveName, keyPath, token string) ([]byte, error)
	SealRegion(e model.EnclaveName, label string, body []byte) (string, error)
	OpenRegion(e model.EnclaveName, label, token string) ([]byte, error)
}

// ViolationKind classifies a seal-guard refusal.
type ViolationKind string

// Violation kinds. Each one makes apply hold the file with model.HoldSealGuard.
const (
	SealedKeyRemoved  ViolationKind = "sealed_key_removed"  // target lost a sealed key or its parent
	SealedValueLeaked ViolationKind = "sealed_value_leaked" // a sealed plaintext appears outside its seal path
	RegionMarkerLost  ViolationKind = "region_marker_lost"  // a region's markers are gone or unbalanced
	ParseFailed       ViolationKind = "parse_failed"        // the target no longer parses in its format
	SealedNotString   ViolationKind = "sealed_not_string"   // a sealed key holds a non-string value
	SealNotMember     ViolationKind = "seal_not_member"     // a non-member's target holds a value at a sealed key
	RegionNotMember   ViolationKind = "region_not_member"   // a non-member's target holds text in a sealed region
)

// Violation is one reason capture refused. It never carries plaintext.
type Violation struct {
	Path   string        `json:"path"` // key path or region label
	Kind   ViolationKind `json:"kind"`
	Detail string        `json:"detail,omitempty"`
}

// ErrRoundTrip reports that ToSource built a source whose ToTarget differs
// from the target. The caller holds the file as uncapturable.
var ErrRoundTrip = errors.New("rules: captured source does not reproduce the target")

// valuePrefix starts a sealed value token (crypt.ValuePrefix).
const valuePrefix = "yadm:1:"

// minLeakLen is the shortest plaintext the leak check looks for as a bare
// substring. A shorter sealed value is looked for only as a whole quoted
// string ("abc" or 'abc'), which unrelated text rarely matches. A shorter
// region line is not looked for at all: lines such as "}" or "fi" occur
// everywhere, so the check would hold files for nothing.
const minLeakLen = 8

type sealRule struct {
	pat     pattern
	enclave model.EnclaveName
}

type compiled struct {
	src   model.SourcePath
	f     format
	keep  []pattern
	drop  []pattern
	seals []sealRule
	owned []pattern // keep plus seal: what the source holds in keep mode
}

func (s Spec) structured() bool { return len(s.Keep) > 0 || len(s.Drop) > 0 || len(s.Seal) > 0 }

func compile(spec Spec) (*compiled, error) {
	f, err := formatFor(string(spec.Format))
	if err != nil {
		return nil, err
	}
	c := &compiled{f: f, src: spec.Source}
	if c.keep, err = parsePatterns(spec.Keep); err != nil {
		return nil, err
	}
	if c.drop, err = parsePatterns(spec.Drop); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(spec.Seal))
	for k := range spec.Seal {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p, err := parsePattern(k)
		if err != nil {
			return nil, err
		}
		if spec.Seal[k] == "" {
			return nil, fmt.Errorf("seal %q names no enclave", k)
		}
		for _, d := range c.drop {
			if d.prefixOf(p) {
				return nil, fmt.Errorf("seal %q is covered by drop %q", k, d.src)
			}
		}
		c.seals = append(c.seals, sealRule{pat: p, enclave: spec.Seal[k]})
		c.owned = append(c.owned, p)
	}
	c.owned = append(c.owned, c.keep...)
	return c, nil
}

// prefixOf reports whether every path matched by q lies at or below a path
// matched by p.
func (p pattern) prefixOf(q pattern) bool {
	if len(p.segs) > len(q.segs) {
		return false
	}
	for i, s := range p.segs {
		if !s.wild && (q.segs[i].wild || q.segs[i].lit != s.lit) {
			return false
		}
	}
	return true
}

func pathKey(p []string) string { return strings.Join(p, "\x00") }

// matchPaths returns the concrete paths matched by any of pats, outermost
// only, in document order.
func matchPaths(root *node, pats []pattern) [][]string {
	var nodes []*node
	seen := map[*node]bool{}
	for _, p := range pats {
		for _, n := range matchAll(root, p) {
			if !seen[n] {
				seen[n] = true
				nodes = append(nodes, n)
			}
		}
	}
	var out [][]string
	for _, n := range nodes {
		covered := false
		for a := n.parent; a != nil; a = a.parent {
			if seen[a] {
				covered = true
				break
			}
		}
		if !covered && n.parent != nil {
			out = append(out, n.path())
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return pos(root, out[i]) < pos(root, out[j]) })
	return out
}

// ErrArrayElement reports a drop or seal path that names an array element.
// Element indexes shift when an element leaves, so such a rule could not
// round-trip; drop or seal the whole array, or a key inside an element.
var ErrArrayElement = errors.New("rules: drop and seal paths cannot name an array element")

// stablePaths is matchPaths for drop and seal rules: it refuses a match that
// is an array element.
func stablePaths(root *node, pats []pattern) ([][]string, error) {
	paths := matchPaths(root, pats)
	for _, p := range paths {
		if n := find(root, p); n != nil && n.parent != nil && n.parent.kind == kArray {
			return nil, fmt.Errorf("%w: %s", ErrArrayElement, joinPath(p))
		}
	}
	return paths, nil
}

func pos(root *node, p []string) int {
	n := find(root, p)
	for n != nil && n.start < 0 && len(n.children) > 0 {
		n = n.children[0]
	}
	if n == nil {
		return -1
	}
	return n.start
}

// edit runs one edit and re-parses the result, failing closed.
func edit(f format, b []byte, fn func(root *node) ([]byte, error)) ([]byte, error) {
	root, err := f.parse(b)
	if err != nil {
		return nil, err
	}
	out, err := fn(root)
	if err != nil {
		if errors.Is(err, errUnsupported) {
			return nil, fmt.Errorf("%w: %v", model.ErrNotImplemented, err)
		}
		return nil, err
	}
	if _, err := f.parse(out); err != nil {
		return nil, fmt.Errorf("edit produced an invalid document: %w", err)
	}
	return out, nil
}

func deletePaths(f format, b []byte, paths [][]string, own bool) ([]byte, error) {
	// Later paths first, so earlier array indexes stay valid.
	for i := len(paths) - 1; i >= 0; i-- {
		p := paths[i]
		var err error
		b, err = edit(f, b, func(root *node) ([]byte, error) {
			n := find(root, p)
			if n == nil {
				return b, nil
			}
			return f.del(b, n, own)
		})
		if err != nil {
			return nil, err
		}
	}
	return b, nil
}

// put writes the node at path from srcB into dst: it replaces an existing
// value or inserts it next to the sibling that follows it in srcB.
//
// With shift, a path whose last segment indexes an array is inserted at that
// index, moving later elements up, instead of replacing the element there:
// restoring a dropped or sealed element puts back what was removed.
func put(f format, dst []byte, path []string, srcB []byte, shift bool) ([]byte, error) {
	srcRoot, err := f.parse(srcB)
	if err != nil {
		return nil, err
	}
	src := find(srcRoot, path)
	if src == nil {
		return dst, nil
	}
	return edit(f, dst, func(root *node) ([]byte, error) {
		if par := find(root, path[:len(path)-1]); shift && par != nil && par.kind == kArray && src.parent.kind == kArray {
			last := path[len(path)-1]
			var at slot
			if idx, err := strconv.Atoi(last); err == nil && idx > 0 {
				at.prev = par.child(strconv.Itoa(idx - 1))
			}
			if at.prev == nil {
				at.next = par.child(last)
			}
			return f.insert(dst, par, at, path[len(path)-1:], srcB, src)
		}
		if n := find(root, path); n != nil {
			if n.vStart >= 0 && src.vStart >= 0 {
				if bytes.Equal(dst[n.vStart:n.vEnd], srcB[src.vStart:src.vEnd]) {
					return dst, nil
				}
				return f.replace(dst, n, srcB, src)
			}
			if n.vStart < 0 && src.vStart < 0 {
				return f.replace(dst, n, srcB, src)
			}
			out, err := f.del(dst, n, false)
			if err != nil {
				return nil, err
			}
			return put(f, out, path, srcB, shift)
		}
		parent := root
		depth := 0
		for depth < len(path)-1 {
			c := parent.child(path[depth])
			if c == nil {
				break
			}
			parent, depth = c, depth+1
		}
		var at slot
		at.tail = commentTail(f, srcB, src)
		if depth == len(path)-1 {
			sib := src.parent.children
			if i := src.index(); i > 0 {
				at.sepBefore = inlineSep(srcB, sib[i-1].end, src.start)
			}
			if i := src.index(); i+1 < len(sib) {
				at.sepAfter = inlineSep(srcB, src.end, sib[i+1].start)
			}
			for i := src.index() - 1; i >= 0 && at.prev == nil; i-- {
				at.prev = parent.child(sib[i].key)
				if at.prev != nil && i == src.index()-1 {
					at.gap = commentGap(f, srcB, sib[i], src)
				}
			}
			for i := src.index() + 1; i < len(sib) && at.next == nil; i++ {
				at.next = parent.child(sib[i].key)
			}
		}
		return f.insert(dst, parent, at, path[depth:], srcB, src)
	})
}

// commentGap returns the whole comment lines between sibling prev and n in b,
// or nil when there are none or anything else sits there.
func commentGap(f format, b []byte, prev, n *node) []byte {
	if prev.end < 0 || n.start < 0 || !onlySpaceBefore(b, n.start) {
		return nil
	}
	l := langTOML
	if _, ok := f.(jsonFormat); ok {
		l = langJSON
	}
	from := prev.end
	if q := l.commaAfter(b, from); q >= 0 && q < n.start {
		from = q + 1
	}
	if !l.restBlank(b, from) {
		return nil
	}
	from = nextLine(b, from)
	to := lineStart(b, n.start)
	if from >= to {
		return nil
	}
	for s := from; s < to; s = nextLine(b, s) {
		if !l.commentLine(b, s) {
			return nil
		}
	}
	return b[from:to]
}

// inlineSep returns b[from:to] when it is a separator on one line holding a
// comma, or nil.
func inlineSep(b []byte, from, to int) []byte {
	if from < 0 || to < from || to > len(b) {
		return nil
	}
	s := b[from:to]
	if bytes.Count(s, []byte(",")) != 1 || len(bytes.Trim(s, ", \t")) != 0 {
		return nil
	}
	return s
}

// commentTail returns the spaces and comment after n (and its comma) on n's
// last line, or nil.
func commentTail(f format, b []byte, n *node) []byte {
	if n.end < 0 {
		return nil
	}
	l := langTOML
	if _, ok := f.(jsonFormat); ok {
		l = langJSON
	}
	from := n.end
	if q := l.commaAfter(b, from); q >= 0 && lineEnd(b, q) == lineEnd(b, from) {
		from = q + 1
	}
	e := lineEnd(b, from)
	if e > from && b[e-1] == '\r' {
		e--
	}
	t := b[from:e]
	if !l.restBlank(b, from) || len(bytes.TrimSpace(t)) == 0 {
		return nil
	}
	return t
}

// ToTarget produces the bytes to write to the target. live is the current
// target content, or nil when the target does not exist.
func ToTarget(source, live []byte, spec Spec, s Sealer) ([]byte, error) {
	out := source
	if spec.Regions {
		var err error
		if out, err = regionsToTarget(out, spec.Source, s); err != nil {
			return nil, err
		}
	}
	if !spec.structured() {
		return out, nil
	}
	c, err := compile(spec)
	if err != nil {
		return nil, err
	}
	if out, err = c.openSeals(out, s); err != nil {
		return nil, err
	}
	if live == nil {
		return out, nil
	}
	if _, err := c.f.parse(live); err != nil {
		return nil, fmt.Errorf("live target does not parse: %w", err)
	}
	base := out
	if len(c.keep) > 0 {
		if base, err = c.mergeOwned(live, out); err != nil {
			return nil, err
		}
	}
	if len(c.drop) > 0 {
		lroot, _ := c.f.parse(live)
		drops, err := stablePaths(lroot, c.drop)
		if err != nil {
			return nil, err
		}
		for _, p := range drops {
			if base, err = put(c.f, base, p, live, true); err != nil {
				return nil, err
			}
		}
	}
	return base, nil
}

// openSeals replaces each sealed token with its plaintext on a member and
// removes the key on a non-member.
func (c *compiled) openSeals(b []byte, s Sealer) ([]byte, error) {
	for _, r := range c.seals {
		root, err := c.f.parse(b)
		if err != nil {
			return nil, fmt.Errorf("source does not parse: %w", err)
		}
		paths, err := stablePaths(root, []pattern{r.pat})
		if err != nil {
			return nil, err
		}
		for i := len(paths) - 1; i >= 0; i-- {
			p := paths[i]
			b, err = edit(c.f, b, func(root *node) ([]byte, error) {
				n := find(root, p)
				if n.kind != kString || !strings.HasPrefix(n.str, valuePrefix) {
					return nil, fmt.Errorf("source key %s is sealed but holds no token", joinPath(p))
				}
				if !s.CanOpen(r.enclave) {
					return c.f.del(b, n, false)
				}
				name, err := partName(c.src, joinPath(p))
				if err != nil {
					return nil, err
				}
				pt, err := s.OpenValue(r.enclave, name, n.str)
				if err != nil {
					return nil, fmt.Errorf("open %s: %w", joinPath(p), err)
				}
				return c.f.setString(b, n, string(pt))
			})
			if err != nil {
				return nil, err
			}
		}
	}
	return b, nil
}

// mergeOwned writes the owned keys of src into live and removes owned keys
// that src no longer has. Keys the app owns stay as live has them.
func (c *compiled) mergeOwned(live, src []byte) ([]byte, error) {
	sroot, err := c.f.parse(src)
	if err != nil {
		return nil, err
	}
	out := live
	lroot0, err := c.f.parse(live)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	// putOwned writes src's value at p. When a drop path lies below p and
	// live already has p as an object, it writes p's children one by one
	// instead, so live's dropped keys under a kept key stay as they are.
	var putOwned func(p []string) error
	putOwned = func(p []string) error {
		sn, ln := find(sroot, p), find(lroot0, p)
		if sn != nil && ln != nil && sn.kind == kObject && ln.kind == kObject && cover(c.drop, p) == covPartial {
			for _, ch := range sn.children {
				cp := ch.path()
				if cover(c.drop, cp) == covFull {
					continue
				}
				if err := putOwned(cp); err != nil {
					return err
				}
			}
			return nil
		}
		out, err = put(c.f, out, p, src, false)
		return err
	}
	for _, p := range matchPaths(sroot, c.owned) {
		have[pathKey(p)] = true
		if err := putOwned(p); err != nil {
			return nil, err
		}
	}
	lroot, err := c.f.parse(out)
	if err != nil {
		return nil, err
	}
	var gone [][]string
	// stale collects owned keys live has and src lacks; dropped keys stay.
	var stale func(n *node)
	stale = func(n *node) {
		p := n.path()
		if cover(c.drop, p) == covFull {
			return
		}
		sn := find(sroot, p)
		if sn == nil {
			gone = append(gone, p)
			return
		}
		if n.kind == kObject && sn.kind == kObject && cover(c.drop, p) == covPartial {
			for _, ch := range n.children {
				stale(ch)
			}
		}
	}
	for _, p := range matchPaths(lroot, c.owned) {
		if have[pathKey(p)] {
			if n := find(lroot, p); n != nil {
				stale(n)
			}
			continue
		}
		if find(sroot, p) == nil && cover(c.drop, p) != covFull {
			gone = append(gone, p)
		}
	}
	sort.SliceStable(gone, func(i, j int) bool { return pos(lroot, gone[i]) < pos(lroot, gone[j]) })
	return deletePaths(c.f, out, gone, false)
}

// prune removes every key that no keep or seal path reaches.
func (c *compiled) prune(b []byte) ([]byte, error) {
	root, err := c.f.parse(b)
	if err != nil {
		return nil, err
	}
	var gone [][]string
	var visit func(n *node) bool // reports whether anything below n stays
	visit = func(n *node) bool {
		kept := false
		var drop [][]string
		for _, ch := range n.children {
			p := ch.path()
			switch cover(c.owned, p) {
			case covFull:
				kept = true
			case covPartial:
				if (ch.kind == kObject || ch.kind == kArray) && visit(ch) {
					kept = true
				} else {
					drop = append(drop, p)
				}
			default:
				drop = append(drop, p)
			}
		}
		if kept || n.parent == nil {
			gone = append(gone, drop...)
		}
		return kept
	}
	visit(root)
	sort.SliceStable(gone, func(i, j int) bool { return pos(root, gone[i]) < pos(root, gone[j]) })
	return deletePaths(c.f, b, gone, true)
}

// ToSource produces the bytes to store in the source from a live target.
// prevSource is the current source content; it supplies tokens this machine
// cannot open. A non-empty Violation list means "hold, do not commit"; the
// returned bytes are then nil.
func ToSource(target, prevSource []byte, spec Spec, s Sealer) ([]byte, []Violation, error) {
	if prevSource != nil {
		if t, err := ToTarget(prevSource, target, spec, s); err == nil && bytes.Equal(t, target) {
			return prevSource, nil, nil
		}
	}
	out := target
	var vio []Violation
	var plains []leakProbe
	if spec.Regions {
		var rp [][]byte
		var err error
		out, rp, vio, err = regionsToSource(out, prevSource, spec.Source, s)
		if err != nil {
			return nil, nil, err
		}
		if len(vio) > 0 {
			return nil, vio, nil
		}
		for _, body := range rp {
			for _, line := range splitLines(body) {
				plains = append(plains, leakProbe{path: "region", text: strings.TrimSpace(string(line)), region: true})
			}
		}
	}
	if spec.structured() {
		c, err := compile(spec)
		if err != nil {
			return nil, nil, err
		}
		if _, err := c.f.parse(out); err != nil {
			return nil, []Violation{{Path: "", Kind: ParseFailed, Detail: "the target does not parse as " + string(spec.Format)}}, nil
		}
		var prevRoot *node
		if prevSource != nil {
			if prevRoot, err = c.f.parse(prevSource); err != nil {
				return nil, nil, fmt.Errorf("previous source does not parse: %w", err)
			}
		}
		if len(c.drop) > 0 {
			root, _ := c.f.parse(out)
			drops, err := stablePaths(root, c.drop)
			if err != nil {
				return nil, nil, err
			}
			if out, err = deletePaths(c.f, out, drops, false); err != nil {
				return nil, nil, err
			}
		}
		if len(c.keep) > 0 {
			if out, err = c.prune(out); err != nil {
				return nil, nil, err
			}
		}
		var v []Violation
		var pl []leakProbe
		if out, v, pl, err = c.sealValues(out, prevSource, prevRoot, s); err != nil {
			return nil, nil, err
		}
		vio = append(vio, v...)
		plains = append(plains, pl...)
	}
	vio = append(vio, leaks(out, prevSource, plains)...)
	if len(vio) > 0 {
		return nil, vio, nil
	}
	back, err := ToTarget(out, target, spec, s)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrRoundTrip, err)
	}
	if !bytes.Equal(back, target) {
		return nil, nil, ErrRoundTrip
	}
	return out, nil, nil
}

type leakProbe struct {
	path   string
	text   string
	region bool // a line of a region body
}

// sealValues seals each value at a seal path, checks that none was lost,
// and on a non-member puts back the tokens from the previous source.
func (c *compiled) sealValues(b, prev []byte, prevRoot *node, s Sealer) ([]byte, []Violation, []leakProbe, error) {
	var vio []Violation
	var plains []leakProbe
	for _, r := range c.seals {
		root, err := c.f.parse(b)
		if err != nil {
			return nil, nil, nil, err
		}
		member := s.CanOpen(r.enclave)
		tpaths, err := stablePaths(root, []pattern{r.pat})
		if err != nil {
			return nil, nil, nil, err
		}
		inTarget := map[string]bool{}
		for _, p := range tpaths {
			inTarget[pathKey(p)] = true
		}
		var ppaths [][]string
		if prevRoot != nil {
			ppaths = matchPaths(prevRoot, []pattern{r.pat})
		}
		for _, p := range ppaths {
			if member {
				if pn := find(prevRoot, p); pn != nil && pn.kind == kString {
					if name, err := partName(c.src, joinPath(p)); err == nil {
						if pt, err := s.OpenValue(r.enclave, name, pn.str); err == nil {
							plains = append(plains, leakProbe{path: joinPath(p), text: string(pt)})
						}
					}
				}
			}
			if inTarget[pathKey(p)] {
				continue
			}
			if member {
				vio = append(vio, Violation{Path: joinPath(p), Kind: SealedKeyRemoved, Detail: "the target lost a sealed key or its parent"})
				continue
			}
			if b, err = put(c.f, b, p, prev, true); err != nil {
				return nil, nil, nil, err
			}
		}
		for i := len(tpaths) - 1; i >= 0; i-- {
			p := tpaths[i]
			root, err := c.f.parse(b)
			if err != nil {
				return nil, nil, nil, err
			}
			n := find(root, p)
			if !member {
				if prevRoot != nil {
					if pn := find(prevRoot, p); pn != nil && n.kind == kString && pn.kind == kString && pn.str == n.str {
						continue
					}
				}
				vio = append(vio, Violation{Path: joinPath(p), Kind: SealNotMember, Detail: "a non-member's target holds a value at a sealed key"})
				continue
			}
			if n.kind != kString {
				vio = append(vio, Violation{Path: joinPath(p), Kind: SealedNotString, Detail: "only string values can be sealed"})
				continue
			}
			name, err := partName(c.src, joinPath(p))
			if err != nil {
				return nil, nil, nil, err
			}
			tok, err := s.SealValue(r.enclave, name, []byte(n.str))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("seal %s: %w", joinPath(p), err)
			}
			plains = append(plains, leakProbe{path: joinPath(p), text: n.str})
			if b, err = edit(c.f, b, func(root *node) ([]byte, error) {
				return c.f.setString(b, find(root, p), tok)
			}); err != nil {
				return nil, nil, nil, err
			}
		}
	}
	return b, vio, plains, nil
}

// leaks reports plaintexts that appear in out but not in prev.
//
// Region lines are checked only against an earlier source: on a first
// capture (prev nil) nothing was sealed before, so a body line that also
// stands outside the region was never secret, and flagging it would hold
// the file on its first capture.
func leaks(out, prev []byte, probes []leakProbe) []Violation {
	var vio []Violation
	seen := map[string]bool{}
	for _, p := range probes {
		if p.text == "" || seen[p.path] || (p.region && prev == nil) {
			continue
		}
		short := len(p.text) < minLeakLen
		if short && p.region {
			continue
		}
		var forms []string
		for _, q := range [][]byte{jsonFormat{}.quote(p.text), tomlFormat{}.quote(p.text)} {
			if short {
				forms = append(forms, string(q)) // the whole quoted string only
			} else {
				forms = append(forms, string(q[1:len(q)-1]))
			}
		}
		if short {
			forms = append(forms, "'"+p.text+"'")
		} else {
			forms = append(forms, p.text)
		}
		for _, form := range forms {
			if bytes.Contains(out, []byte(form)) && !bytes.Contains(prev, []byte(form)) {
				seen[p.path] = true
				vio = append(vio, Violation{Path: p.path, Kind: SealedValueLeaked, Detail: "sealed plaintext appears outside its seal path"})
				break
			}
		}
	}
	return vio
}
