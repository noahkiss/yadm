package rules

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Spec is the intra-file part of a manifest entry.
type Spec struct {
	Format  manifest.Format
	Keep    []string
	Drop    []string
	Seal    map[string]model.EnclaveName
	Regions bool
}

// SpecOf extracts the intra-file rules from a manifest entry.
func SpecOf(e manifest.Entry) Spec {
	return Spec{Format: e.Format, Keep: e.Keep, Drop: e.Drop, Seal: e.Seal, Regions: e.Regions}
}

// Empty reports whether the spec has no intra-file rules.
func (s Spec) Empty() bool {
	return len(s.Keep) == 0 && len(s.Drop) == 0 && len(s.Seal) == 0 && !s.Regions
}

// Sealer seals and opens parts of files. crypt.Set implements it.
//
// A value's plaintext is the decoded string, without quotes. keyPath is the
// manifest seal key verbatim (a pattern such as "mcp.servers.*.env.TOKEN"),
// so every value it matches shares one binding. A region body is the exact
// bytes between the marker lines. SealRegion returns "yadm:sealed 1 <epoch>
// <base64>" without a comment prefix.
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

// minLeakLen is the shortest plaintext the leak check looks for. Shorter
// values match too much unrelated text to be a useful signal.
const minLeakLen = 8

type sealRule struct {
	pat     pattern
	enclave model.EnclaveName
}

type compiled struct {
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
	c := &compiled{f: f}
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
func put(f format, dst []byte, path []string, srcB []byte) ([]byte, error) {
	srcRoot, err := f.parse(srcB)
	if err != nil {
		return nil, err
	}
	src := find(srcRoot, path)
	if src == nil {
		return dst, nil
	}
	return edit(f, dst, func(root *node) ([]byte, error) {
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
			return put(f, out, path, srcB)
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
		if depth == len(path)-1 {
			sib := src.parent.children
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

// ToTarget produces the bytes to write to the target. live is the current
// target content, or nil when the target does not exist.
func ToTarget(source, live []byte, spec Spec, s Sealer) ([]byte, error) {
	out := source
	if spec.Regions {
		var err error
		if out, err = regionsToTarget(out, s); err != nil {
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
		for _, p := range matchPaths(lroot, c.drop) {
			if base, err = put(c.f, base, p, live); err != nil {
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
		paths := matchPaths(root, []pattern{r.pat})
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
				pt, err := s.OpenValue(r.enclave, r.pat.src, n.str)
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
	have := map[string]bool{}
	for _, p := range matchPaths(sroot, c.owned) {
		have[pathKey(p)] = true
		if out, err = put(c.f, out, p, src); err != nil {
			return nil, err
		}
	}
	lroot, err := c.f.parse(out)
	if err != nil {
		return nil, err
	}
	var gone [][]string
	for _, p := range matchPaths(lroot, c.owned) {
		if !have[pathKey(p)] && find(sroot, p) == nil {
			gone = append(gone, p)
		}
	}
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
		out, rp, vio, err = regionsToSource(out, prevSource, s)
		if err != nil {
			return nil, nil, err
		}
		if len(vio) > 0 {
			return nil, vio, nil
		}
		for _, body := range rp {
			for _, line := range splitLines(body) {
				plains = append(plains, leakProbe{path: "region", text: strings.TrimSpace(string(line))})
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
			if out, err = deletePaths(c.f, out, matchPaths(root, c.drop), false); err != nil {
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
		return nil, nil, fmt.Errorf("%w: %v", ErrRoundTrip, err)
	}
	if !bytes.Equal(back, target) {
		return nil, nil, ErrRoundTrip
	}
	return out, nil, nil
}

type leakProbe struct {
	path string
	text string
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
		tpaths := matchPaths(root, []pattern{r.pat})
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
					if pt, err := s.OpenValue(r.enclave, r.pat.src, pn.str); err == nil {
						plains = append(plains, leakProbe{path: joinPath(p), text: string(pt)})
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
			if b, err = put(c.f, b, p, prev); err != nil {
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
			tok, err := s.SealValue(r.enclave, r.pat.src, []byte(n.str))
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
func leaks(out, prev []byte, probes []leakProbe) []Violation {
	var vio []Violation
	seen := map[string]bool{}
	for _, p := range probes {
		if len(p.text) < minLeakLen || seen[p.path] {
			continue
		}
		forms := []string{p.text}
		for _, q := range [][]byte{jsonFormat{}.quote(p.text), tomlFormat{}.quote(p.text)} {
			forms = append(forms, string(q[1:len(q)-1]))
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
