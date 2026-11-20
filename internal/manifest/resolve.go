package manifest

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
)

// candidate is one (target, source) pair an entry would produce.
type candidate struct {
	target model.Target
	source model.SourcePath
}

// Collision is one target that more than one applying entry produces.
type Collision struct {
	Target  model.Target `json:"target"`
	Indexes []int        `json:"indexes"` // positions in Manifest.Entries, ascending
}

// CollisionError lists every collision of one resolve, sorted by target.
type CollisionError struct {
	Collisions []Collision
}

func (e *CollisionError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d colliding target(s):", FileName, len(e.Collisions))
	for _, c := range e.Collisions {
		fmt.Fprintf(&b, " %s (file %v);", c.Target, c.Indexes)
	}
	return strings.TrimSuffix(b.String(), ";")
}

// FileMode returns the mode to write the target with. An explicit `mode`
// wins. Otherwise a whole-file enclave entry gets 0600, and any other entry
// gets 0755 when its source is executable and 0644 when it is not.
func (r Resolved) FileMode(sourceExecutable bool) fs.FileMode {
	switch {
	case r.Entry.Mode != 0:
		return r.Entry.Mode
	case r.Entry.Enclave != "":
		return 0o600
	case sourceExecutable:
		return 0o755
	}
	return 0o644
}

// Quiet returns the entry's auto-commit quiet period.
func (m *Manifest) Quiet(e Entry) model.Duration {
	if e.Quiet != nil {
		return *e.Quiet
	}
	return m.Defaults.Quiet
}

// Validate checks every condition and enclave name in the manifest against
// the fleet's Vocabulary, whether or not it applies on this machine.
func (m *Manifest) Validate(v cond.Vocabulary) error {
	_, err := m.conditions(v)
	return err
}

type conds struct {
	entries, units, roots []cond.Expr
	tasks, checks         map[string]cond.Expr
}

func (m *Manifest) conditions(v cond.Vocabulary) (*conds, error) {
	var errs []error
	parse := func(where, src string) cond.Expr {
		e, err := cond.Parse(src, v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: when: %w", FileName, where, err))
			return nil
		}
		return e
	}
	enclave := func(where string, name model.EnclaveName) {
		if name == "" {
			return
		}
		if !v.Types[string(name)] {
			errs = append(errs, fmt.Errorf("%s: %s: unknown enclave %q", FileName, where, name))
		} else if v.Enclaves != nil && !v.Enclaves[string(name)] {
			errs = append(errs, fmt.Errorf("%s: %s: type %q is not an enclave", FileName, where, name))
		}
	}
	c := &conds{tasks: map[string]cond.Expr{}, checks: map[string]cond.Expr{}}
	for i, e := range m.Entries {
		where := fmt.Sprintf("file[%d] %q", i, e.Target)
		c.entries = append(c.entries, parse(where, e.When))
		enclave(where, e.Enclave)
		for _, k := range sortedKeys(e.Seal) {
			enclave(where+" seal "+k, e.Seal[k])
		}
	}
	for i, u := range m.Units {
		c.units = append(c.units, parse(fmt.Sprintf("unit[%d] %q", i, u.Target), u.When))
	}
	for i, r := range m.Roots {
		where := fmt.Sprintf("root[%d] %q", i, r.Path)
		c.roots = append(c.roots, parse(where, r.When))
		enclave(where, r.Enclave)
	}
	for _, name := range sortedKeys(m.Tasks) {
		c.tasks[name] = parse("tasks."+name, m.Tasks[name].When)
	}
	for _, name := range sortedKeys(m.Checks) {
		c.checks[name] = parse("checks."+name, m.Checks[name].When)
	}
	return c, errors.Join(errs...)
}

// defaultSource returns where an entry's files live: its source, or
// files/<target> or sealed/<enclave>/<target>. For a glob entry, it is the
// directory that stands for the target's fixed prefix.
func defaultSource(e Entry) (model.SourcePath, string) {
	t := string(e.Target)
	prefix := t
	if IsGlob(t) {
		prefix, _ = staticPrefix(t)
	}
	if e.Source != "" {
		return e.Source, prefix
	}
	base := "files"
	if e.Enclave != "" {
		base = "sealed/" + string(e.Enclave)
	}
	if prefix == "" {
		return model.SourcePath(base), prefix
	}
	return model.SourcePath(base + "/" + prefix), prefix
}

// candidates expands one entry against the source tree.
func candidates(e Entry, tree []model.SourcePath) []candidate {
	src, prefix := defaultSource(e)
	if !IsGlob(string(e.Target)) {
		return []candidate{{target: e.Target, source: src}}
	}
	var out []candidate
	dir := string(src) + "/"
	for _, p := range tree {
		rest, ok := strings.CutPrefix(string(p), dir)
		if !ok || rest == "" {
			continue
		}
		t := rest
		if prefix != "" {
			t = prefix + "/" + rest
		}
		if Match(string(e.Target), t) {
			out = append(out, candidate{target: model.Target(t), source: p})
		}
	}
	return out
}

// Resolve evaluates the manifest for one machine against the source tree.
//
// It first checks every condition and enclave name against v, whether or
// not it applies here. An entry applies when its `when` is true. Two
// applying entries that produce one target are a collision, whatever their
// kind: an explicit entry does not override a glob, and there is no
// precedence by order. Resolve reports every collision in one
// *CollisionError. tree lists the files in the source tree; glob entries
// expand against it. When tree is not nil, an applying non-glob entry whose
// source is absent is an error. A unit attaches to its target when its
// `when` is true and the target is in the plan; otherwise it is skipped.
func (m *Manifest) Resolve(ctx model.Context, tree []model.SourcePath, v cond.Vocabulary) (*Plan, error) {
	c, err := m.conditions(v)
	if err != nil {
		return nil, err
	}
	var inTree map[model.SourcePath]bool
	if tree != nil {
		inTree = make(map[model.SourcePath]bool, len(tree))
		for _, p := range tree {
			inTree[p] = true
		}
		tree = slices.Clone(tree)
		slices.Sort(tree)
	}
	p := &Plan{
		Targets: map[model.Target]Resolved{},
		Tasks:   map[string]TaskDef{},
		Checks:  map[string]CheckDef{},
		m:       m,
	}
	var errs []error
	owners := map[model.Target][]int{}
	for i, e := range m.Entries {
		cs := candidates(e, tree)
		ok := c.entries[i].Eval(ctx)
		p.cands = append(p.cands, cs)
		p.apply = append(p.apply, ok)
		if !ok {
			continue
		}
		for _, cd := range cs {
			if inTree != nil && !IsGlob(string(e.Target)) && !inTree[cd.source] {
				errs = append(errs, fmt.Errorf("%s: file[%d] %q: source %s is not in the source tree", FileName, i, e.Target, cd.source))
				continue
			}
			owners[cd.target] = append(owners[cd.target], i)
			p.Targets[cd.target] = Resolved{Target: cd.target, Source: cd.source, Entry: e, Index: i}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	var col []Collision
	for t, idx := range owners {
		if len(idx) > 1 {
			col = append(col, Collision{Target: t, Indexes: idx})
		}
	}
	if len(col) > 0 {
		slices.SortFunc(col, func(a, b Collision) int { return cmp.Compare(a.Target, b.Target) })
		return nil, &CollisionError{Collisions: col}
	}
	for i, u := range m.Units {
		if !c.units[i].Eval(ctx) {
			continue
		}
		r, ok := p.Targets[u.Target]
		if !ok {
			continue
		}
		if r.Unit != nil {
			return nil, fmt.Errorf("%s: unit[%d] %q: a second unit for one target", FileName, i, u.Target)
		}
		r.Unit = &u
		p.Targets[u.Target] = r
	}
	for i, r := range m.Roots {
		if c.roots[i].Eval(ctx) {
			p.Roots = append(p.Roots, r)
		}
	}
	for name, t := range m.Tasks {
		if c.tasks[name].Eval(ctx) {
			p.Tasks[name] = t
		}
	}
	for name, ch := range m.Checks {
		if c.checks[name].Eval(ctx) {
			p.Checks[name] = ch
		}
	}
	return p, nil
}

// Protected reports whether a target never auto-commits on its own: it
// matches BuiltinProtected or a manifest `protected` glob, or its entry has
// `review = true`. BuiltinProtected names source-root files, which are never
// targets; Protected matches them literally so a target of the same name is
// protected too.
func (p *Plan) Protected(t model.Target) bool {
	if r, ok := p.Targets[t]; ok && r.Entry.Review {
		return true
	}
	for _, g := range BuiltinProtected {
		if Match(g, string(t)) {
			return true
		}
	}
	if p.m != nil {
		for _, g := range p.m.Protected {
			if Match(g, string(t)) {
				return true
			}
		}
	}
	return false
}

// Root returns the deepest applying owned root that contains t, or nil.
func (p *Plan) Root(t model.Target) *Root {
	var best *Root
	for i, r := range p.Roots {
		if t == r.Path || strings.HasPrefix(string(t), string(r.Path)+"/") {
			if best == nil || len(r.Path) > len(best.Path) {
				best = &p.Roots[i]
			}
		}
	}
	if best == nil {
		return nil
	}
	cp := *best
	return &cp
}

// Why explains how the plan treats a target. Rejected lists, in manifest
// order, every entry that names the target but does not produce it here:
// its `when` is false, or it is a glob that matches the target but has no
// source file for it.
func (p *Plan) Why(t model.Target) (Explanation, error) {
	if err := validRel(string(t)); err != nil {
		return Explanation{}, err
	}
	if IsGlob(string(t)) {
		return Explanation{}, fmt.Errorf("%q: why takes a path, not a glob", t)
	}
	x := Explanation{Target: t, Protected: p.Protected(t), InRoot: p.Root(t)}
	if r, ok := p.Targets[t]; ok {
		x.Managed = true
		x.Resolved = &r
	}
	if p.m == nil {
		return x, nil
	}
	for i, e := range p.m.Entries {
		if x.Resolved != nil && x.Resolved.Index == i {
			continue
		}
		var produces bool
		for _, c := range p.cands[i] {
			if c.target == t {
				produces = true
				break
			}
		}
		glob := IsGlob(string(e.Target))
		names := produces || glob && Match(string(e.Target), string(t))
		if !names {
			continue
		}
		rej := Rejection{Index: i, When: e.When}
		switch {
		case !p.apply[i]:
			rej.Reason = fmt.Sprintf("when %q is false on this machine", e.When)
		case glob && !produces:
			src, prefix := defaultSource(e)
			rest := strings.TrimPrefix(strings.TrimPrefix(string(t), prefix), "/")
			rej.Reason = fmt.Sprintf("the glob matches, but the source tree has no %s/%s", src, rest)
		default:
			continue
		}
		x.Rejected = append(x.Rejected, rej)
	}
	return x, nil
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}
