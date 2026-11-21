package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
)

// Retagged is the source change of a retag.
type Retagged struct {
	// Capture holds the changes, the target's new source last. When the
	// entry applies on this machine, Paths and Scopes name the target, so
	// the commit gate reads the live file. When it does not (another
	// variant applies here, or none), Paths is empty: the live file is not
	// this entry's, and every change commits as a source change.
	Capture
	Source    model.SourcePath // the entry's source before the retag; empty for a track
	NewSource model.SourcePath
	OldWhen   string // the entry's when before the retag
	When      string // the entry's new when
}

// Retag builds one atomic source change for a target: the manifest entry's
// `when` and `enclave`, the move between files/ and sealed/<enclave>/ with
// the content opened and resealed, and nothing else. Only a member of every
// enclave involved can retag. The change is protected: it never auto-commits,
// and machines that lose the target remove it on their next apply (if it is
// unchanged there; a drifted copy is held).
//
// The new `when` keeps every term of the old one but the types
// (cond.Retype): `type:a & os:darwin` retagged to b becomes
// `type:b & os:darwin`. A `when` whose type terms are not one clean factor
// (under `!`, mixed into `|`, behind a `cond:` name) is refused with
// cond.ErrRetype; edit the manifest by hand.
//
// Retag works on the source head. A target with several literal entries
// (variants) needs opts.Source to pick one (ErrVariants). The edited
// manifest must not make two entries for the target apply on any fleet
// machine. A variant that does not apply here can move between enclaves
// only into one: unsealing needs the commit gate to read its plaintext,
// which this machine does not have. With no entry, it tracks an unmanaged
// file in $HOME: a new entry for the types and its live bytes (track). A
// file a glob entry covers is refused.
func (e *Engine) Retag(ctx context.Context, t model.Target, opts RetagOptions) (Retagged, error) {
	if len(opts.Types) == 0 {
		return Retagged{}, errors.New("retag: at least one type is required")
	}
	head, err := e.Store.Head(ctx)
	if err != nil {
		return Retagged{}, err
	}
	snap, err := e.snapshot(ctx, head)
	if err != nil {
		return Retagged{}, err
	}
	if snap.Manifest == nil {
		return Retagged{}, errors.New("retag: snapshot has no manifest")
	}
	idx, err := selectEntry(snap.Manifest, t, opts.Source)
	if err != nil {
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}
	if err := checkRetagTypes(snap, opts); err != nil {
		return Retagged{}, err
	}
	var types []string
	for _, ty := range opts.Types {
		types = append(types, string(ty))
	}
	if idx < 0 {
		when := strings.Join(prefixed("type:", types), " | ")
		c, err := e.track(ctx, head, snap, t, when, opts.Enclave, "retag")
		return Retagged{Capture: c, When: when}, err
	}
	entry := snap.Manifest.Entries[idx]
	oldEnc, newEnc := entry.Enclave, opts.Enclave
	for _, enc := range []model.EnclaveName{oldEnc, newEnc} {
		if enc != "" && !snap.canOpen(enc) {
			return Retagged{}, fmt.Errorf("retag %s: %w: %s", t, crypt.ErrNotMember, enc)
		}
	}
	here := false
	if snap.Plan != nil {
		r, ok := snap.Plan.Targets[t]
		here = ok && r.Index == idx
	}
	if !here && oldEnc != "" && newEnc != oldEnc {
		return Retagged{}, fmt.Errorf("retag %s: the entry with source %s does not apply on this machine, and moving it out of enclave %s needs the commit gate to read its plaintext here; retag it on a machine it applies to", t, effectiveSource(entry), oldEnc)
	}
	vocab, err := snapVocabulary(snap)
	if err != nil {
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}
	when, err := cond.Retype(entry.When, types, vocab)
	if err != nil {
		if errors.Is(err, cond.ErrRetype) {
			return Retagged{}, fmt.Errorf("retag %s: %w; write the new when in the manifest by hand", t, err)
		}
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}

	oldSrc := effectiveSource(entry)
	newSrc, err := moveSource(oldSrc, oldEnc, newEnc)
	if err != nil {
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}
	if newSrc != oldSrc {
		if err := destinationFree(snap, newSrc, idx); err != nil {
			return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
		}
	}
	raw, err := e.Store.ReadPath(ctx, head, oldSrc)
	if err != nil {
		return Retagged{}, err
	}
	newRaw, err := e.rebind(snap, entry, raw, oldSrc, newSrc, oldEnc, newEnc)
	if err != nil {
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}

	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return Retagged{}, err
	}
	srcLine := ""
	if entry.Source != "" {
		srcLine = string(newSrc)
	}
	nm, err := editEntry(mb, idx, map[string]string{"when": when, "enclave": string(newEnc), "source": srcLine})
	if err != nil {
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}
	var check manifest.Manifest
	if err := toml.Unmarshal(nm, &check); err != nil {
		return Retagged{}, fmt.Errorf("retag %s: edited manifest does not parse: %w", t, err)
	}
	if idx >= len(check.Entries) || check.Entries[idx].Target != t || check.Entries[idx].When != when ||
		check.Entries[idx].Enclave != newEnc || (entry.Source != "" && check.Entries[idx].Source != newSrc) {
		return Retagged{}, fmt.Errorf("retag %s: edited manifest does not say what was asked", t)
	}
	if err := e.checkEdited(ctx, head, snap, nm, t, newSrc); err != nil {
		return Retagged{}, fmt.Errorf("retag %s: %w", t, err)
	}

	mode := sourceMode(snap, oldSrc)
	changes := []store.Change{{Path: manifest.FileName, Blob: nm, Mode: gitModeFile}}
	if newSrc != oldSrc {
		changes = append(changes, store.Change{Path: oldSrc, Delete: true})
	}
	changes = append(changes, store.Change{Path: newSrc, Blob: newRaw, Mode: mode})

	scope := model.ScopeShared
	if newEnc != "" {
		scope = model.Scope(newEnc)
	}
	out := Retagged{Capture: Capture{Changes: changes}, Source: oldSrc, NewSource: newSrc, OldWhen: entry.When, When: when}
	if here {
		out.Paths = []model.Target{t}
		out.Scopes = map[model.Target]model.Scope{t: scope}
	}
	return out, nil
}

// ErrVariants reports a target with more than one literal manifest entry
// when the caller did not pick one by its source.
var ErrVariants = errors.New("more than one manifest entry names it")

// effectiveSource is the source a literal entry reads.
func effectiveSource(en manifest.Entry) model.SourcePath {
	if en.Source != "" {
		return en.Source
	}
	return defaultSource(en.Target, en.Enclave)
}

// selectEntry returns the position of t's literal [[file]] entry: the only
// one, or the one whose source is src. It returns -1 when no literal entry
// names t and src is empty. Several entries without src fail with
// ErrVariants, naming their sources; a src no entry of t reads fails.
func selectEntry(m *manifest.Manifest, t model.Target, src model.SourcePath) (int, error) {
	var all, hit []int
	for i, en := range m.Entries {
		if en.Target != t || manifest.IsGlob(string(en.Target)) {
			continue
		}
		all = append(all, i)
		if src != "" && effectiveSource(en) == src {
			hit = append(hit, i)
		}
	}
	srcs := func(idxs []int) string {
		s := make([]string, len(idxs))
		for i, x := range idxs {
			s[i] = string(effectiveSource(m.Entries[x]))
		}
		return strings.Join(s, ", ")
	}
	switch {
	case src == "" && len(all) == 0:
		return -1, nil
	case src == "" && len(all) == 1:
		return all[0], nil
	case src == "":
		return -1, fmt.Errorf("%w (sources %s); pick one with --source <source>", ErrVariants, srcs(all))
	case len(hit) == 1:
		return hit[0], nil
	case len(hit) > 1:
		return -1, fmt.Errorf("%d manifest entries name it with source %s; edit the manifest", len(hit), src)
	case len(all) == 0:
		return -1, fmt.Errorf("no manifest entry names it")
	}
	return -1, fmt.Errorf("no manifest entry for it reads %s (sources %s)", src, srcs(all))
}

// snapVocabulary is the fleet's vocabulary with the manifest's named
// conditions. Without a fleet it is the manifest's names alone.
func snapVocabulary(snap *Snapshot) (cond.Vocabulary, error) {
	var v cond.Vocabulary
	if snap.Fleet != nil {
		v = snap.Fleet.Vocabulary()
	}
	if snap.Manifest == nil {
		return v, nil
	}
	return snap.Manifest.Vocabulary(v)
}

func prefixed(p string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = p + s
	}
	return out
}

// destinationFree refuses a new source path dst that the source tree
// already holds or that an entry other than skip would read once it
// exists: a glob or another entry's source directory would take it over.
func destinationFree(snap *Snapshot, dst model.SourcePath, skip ...int) error {
	if _, ok := snap.Tree[dst]; ok {
		return fmt.Errorf("%s already exists in the source tree", dst)
	}
	for p := range snap.Tree {
		switch {
		case strings.HasPrefix(string(p), string(dst)+"/"):
			return fmt.Errorf("%s is a directory in the source tree", dst)
		case strings.HasPrefix(string(dst), string(p)+"/"):
			return fmt.Errorf("%s is a file in the source tree, so %s cannot be under it", p, dst)
		}
	}
	tree := append(slices.Collect(maps.Keys(snap.Tree)), dst)
	sort.Slice(tree, func(i, j int) bool { return tree[i] < tree[j] })
	for i, en := range snap.Manifest.Entries {
		if slices.Contains(skip, i) {
			continue
		}
		for _, r := range manifest.Expand(en, tree) {
			if r.Source == dst {
				return fmt.Errorf("entry %q would read %s", en.Target, dst)
			}
		}
	}
	return nil
}

// rebind returns the stored bytes raw of oldSrc as they must be stored at
// newSrc: a whole sealed file opened under oldSrc and oldEnc and sealed
// under newSrc and newEnc, sealed values and regions opened under oldSrc
// and sealed under newSrc. Every open accepts the enclave's current epoch
// only, so content a removed member planted under an old key is never
// resealed under the current one. A part this machine cannot open fails
// with crypt.ErrNotMember instead of being dropped. Plaintext stays in
// memory; the result is checked to open back to the same bytes.
func (e *Engine) rebind(snap *Snapshot, entry manifest.Entry, raw []byte, oldSrc, newSrc model.SourcePath, oldEnc, newEnc model.EnclaveName) ([]byte, error) {
	s := snap.strict()
	for _, enc := range []model.EnclaveName{oldEnc, newEnc} {
		if enc != "" && !s.canOpen(enc) {
			return nil, fmt.Errorf("%w: %s", crypt.ErrNotMember, enc)
		}
	}
	plain := raw
	if oldEnc != "" {
		var err error
		if plain, err = s.cr().OpenFile(oldEnc, oldSrc, raw); err != nil {
			return nil, fmt.Errorf("open %s: %w", oldSrc, err)
		}
	}
	// Sealed values and regions are bound to the source path: a move
	// opens them under the old path and seals them under the new one.
	if spec := rules.SpecOf(entry); newSrc != oldSrc && (len(spec.Seal) > 0 || spec.Regions) {
		if entry.Template {
			return nil, errors.New("a template with sealed values or regions cannot move; edit it by hand")
		}
		need := slices.Collect(maps.Values(spec.Seal))
		if spec.Regions {
			encs, err := rules.RegionEnclaves(plain)
			if err != nil {
				return nil, err
			}
			need = append(need, encs...)
		}
		for _, enc := range need {
			if !s.canOpen(enc) {
				return nil, fmt.Errorf("%w: %s (sealed parts of %s)", crypt.ErrNotMember, enc, oldSrc)
			}
		}
		from, to := spec, spec
		from.Source, to.Source = oldSrc, newSrc
		open, err := e.Rules.ToTarget(plain, nil, from, s.sealer())
		if err != nil {
			return nil, fmt.Errorf("open sealed parts: %w", err)
		}
		moved, vio, err := e.Rules.ToSource(open, nil, to, s.sealer())
		if err != nil || len(vio) > 0 {
			return nil, fmt.Errorf("reseal sealed parts: %v %v", err, vio)
		}
		back, err := e.Rules.ToTarget(moved, nil, to, s.sealer())
		if err != nil || !bytes.Equal(back, open) {
			return nil, fmt.Errorf("resealed parts of %s do not open back to the same content", newSrc)
		}
		plain = moved
	}
	if newEnc == "" {
		return plain, nil
	}
	out, err := s.cr().SealFile(newEnc, newSrc, plain)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return out, nil
}

// checkEdited validates an edited manifest nm against the fleet, and
// refuses it when two of its entries for t would apply on one fleet
// machine. newSrc is the source the edit points t's entry at.
func (e *Engine) checkEdited(ctx context.Context, head model.CommitID, snap *Snapshot, nm []byte, t model.Target, newSrc model.SourcePath) error {
	if snap.Fleet == nil {
		return nil
	}
	check, err := manifest.Parse(nm)
	if err != nil {
		return fmt.Errorf("edited manifest does not parse: %w", err)
	}
	if err := check.LoadIncludes(func(p model.SourcePath) ([]byte, error) { return e.Store.ReadPath(ctx, head, p) }); err != nil {
		return err
	}
	v, err := check.Vocabulary(snap.Fleet.Vocabulary())
	if err != nil {
		return err
	}
	if err := check.Validate(snap.Fleet.Vocabulary()); err != nil {
		return err
	}
	if t == "" {
		return nil
	}
	tree := slices.Collect(maps.Keys(snap.Tree))
	if newSrc != "" {
		tree = append(tree, newSrc)
	}
	sort.Slice(tree, func(i, j int) bool { return tree[i] < tree[j] })
	type cand struct {
		i int
		x cond.Expr
	}
	var cands []cand
	for i, en := range check.Entries {
		for _, r := range manifest.Expand(en, tree) {
			if r.Target != t {
				continue
			}
			x, err := cond.Parse(en.When, v)
			if err != nil {
				return err
			}
			cands = append(cands, cand{i, x})
			break
		}
	}
	if len(cands) < 2 {
		return nil
	}
	ids := slices.Sorted(maps.Keys(snap.Fleet.Machines))
	for _, id := range ids {
		mc := snap.Fleet.Machines[id]
		mc.ID = id
		ctx := model.Context{Machine: mc}
		var on []string
		for _, c := range cands {
			if c.x.Eval(ctx) {
				on = append(on, fmt.Sprintf("#%d %s", c.i, effectiveSourceOf(check.Entries[c.i], t)))
			}
		}
		if len(on) > 1 {
			name := mc.Name
			if name == "" {
				name = string(id)
			}
			return fmt.Errorf("%s would get %s from more than one entry (%s); make the variants' conditions exclusive", name, t, strings.Join(on, ", "))
		}
	}
	return nil
}

// effectiveSourceOf names an entry's source for target t in messages.
func effectiveSourceOf(en manifest.Entry, t model.Target) model.SourcePath {
	if manifest.IsGlob(string(en.Target)) {
		return model.SourcePath(en.Target)
	}
	return effectiveSource(en)
}

func checkRetagTypes(snap *Snapshot, opts RetagOptions) error {
	if snap.Fleet == nil {
		return nil
	}
	for _, ty := range opts.Types {
		if _, ok := snap.Fleet.Types[ty]; !ok {
			return fmt.Errorf("retag: unknown type %q", ty)
		}
	}
	if opts.Enclave != "" {
		if d, ok := snap.Fleet.Types[model.TypeName(opts.Enclave)]; !ok || !d.Enclave {
			return fmt.Errorf("retag: %q is not an enclave type", opts.Enclave)
		}
	}
	return nil
}

// Track starts syncing a file no manifest entry, glob or owned root
// covers: an unmanaged regular file in $HOME. It appends a [[file]] entry
// with opts.When (and the enclave) and captures the live bytes into the
// entry's source, sealed under sealed/<enclave>/ for an enclave, in one
// change. It refuses a path an entry, a glob or an owned root covers
// (naming which), a directory, and an enclave this machine is not a member
// of (crypt.ErrNotMember).
func (e *Engine) Track(ctx context.Context, t model.Target, opts TrackOptions) (Capture, error) {
	head, err := e.Store.Head(ctx)
	if err != nil {
		return Capture{}, err
	}
	snap, err := e.snapshot(ctx, head)
	if err != nil {
		return Capture{}, err
	}
	if snap.Manifest == nil {
		return Capture{}, errors.New("track: snapshot has no manifest")
	}
	for _, en := range snap.Manifest.Entries {
		if en.Target == t {
			return Capture{}, fmt.Errorf("track %s: %w: a manifest entry names it; change who gets it with yadm retag", t, ErrCovered)
		}
	}
	var root *manifest.Root
	for i, r := range snap.Manifest.Roots {
		prefix := strings.TrimSuffix(string(r.Path), "/") + "/"
		if strings.HasPrefix(string(t), prefix) && (root == nil || len(r.Path) > len(root.Path)) {
			root = &snap.Manifest.Roots[i]
		}
	}
	if root != nil {
		return Capture{}, fmt.Errorf("track %s: %w: owned root %q covers it; commit it with yadm commit, or give it its own entry with yadm retag", t, ErrCovered, root.Path)
	}
	if opts.Enclave != "" && snap.Fleet != nil {
		if d, ok := snap.Fleet.Types[model.TypeName(opts.Enclave)]; !ok || !d.Enclave {
			return Capture{}, fmt.Errorf("track %s: %q is not an enclave type", t, opts.Enclave)
		}
	}
	return e.track(ctx, head, snap, t, opts.When, opts.Enclave, "track")
}

// ErrCovered reports a path that a manifest entry, glob or owned root
// already covers, so track has nothing to add.
var ErrCovered = errors.New("already covered")

// track appends a [[file]] entry for t with when (and the enclave) and
// captures the live bytes into its source, in one change. A file a glob
// entry already produces is refused: edit the manifest. verb names the
// command in errors.
func (e *Engine) track(ctx context.Context, head model.CommitID, snap *Snapshot, t model.Target, when string, enc model.EnclaveName, verb string) (Capture, error) {
	for _, en := range snap.Manifest.Entries {
		if manifest.IsGlob(string(en.Target)) && manifest.Match(string(en.Target), string(t)) {
			return Capture{}, fmt.Errorf("%s %s: %w: glob entry %q covers it, so a second entry would collide; where it applies, capture the file under that entry with yadm commit %s; otherwise edit the manifest", verb, t, ErrCovered, en.Target, model.ShellQuote(string(t)))
		}
	}
	if snap.Manifest.Generated(t) {
		return Capture{}, fmt.Errorf("%s %s: a task generates it (outputs); it is never tracked", verb, t)
	}
	if enc != "" && !snap.canOpen(enc) {
		return Capture{}, fmt.Errorf("%s %s: %w: %s", verb, t, crypt.ErrNotMember, enc)
	}
	abs, err := e.abs(t)
	if err != nil {
		return Capture{}, err
	}
	lv, err := e.readTarget(ctx, abs)
	if err != nil {
		return Capture{}, err
	}
	switch {
	case lv.exists && lv.info.IsDir():
		return Capture{}, fmt.Errorf("%s %s: %w: it is a directory; share a directory with a [[root]] in the manifest", verb, t, ErrNotFile)
	case !lv.exists || !lv.info.Mode().IsRegular():
		return Capture{}, fmt.Errorf("%s %s: %w: no manifest entry names it, and it is not a regular file in $HOME to track", verb, t, ErrNotFile)
	}
	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return Capture{}, err
	}
	var add strings.Builder
	if len(mb) > 0 && mb[len(mb)-1] != '\n' {
		add.WriteString("\n")
	}
	fmt.Fprintf(&add, "\n[[file]]\ntarget = %s\n", tomlString(string(t)))
	if when != "" {
		fmt.Fprintf(&add, "when = %s\n", tomlString(when))
	}
	if enc != "" {
		fmt.Fprintf(&add, "enclave = %s\n", tomlString(string(enc)))
	}
	nm := append(append([]byte{}, mb...), add.String()...)
	check, err := manifest.Parse(nm)
	if err != nil {
		return Capture{}, fmt.Errorf("%s %s: edited manifest does not parse: %w", verb, t, err)
	}
	last := check.Entries[len(check.Entries)-1]
	if last.Target != t || last.When != when || last.Enclave != enc {
		return Capture{}, fmt.Errorf("%s %s: edited manifest does not say what was asked", verb, t)
	}
	if snap.Fleet != nil {
		// Every machine resolves the new entry: a typo in when would fail
		// them all, so it fails here first.
		if err := check.LoadIncludes(func(p model.SourcePath) ([]byte, error) { return e.Store.ReadPath(ctx, head, p) }); err != nil {
			return Capture{}, fmt.Errorf("%s %s: %w", verb, t, err)
		}
		if err := check.Validate(snap.Fleet.Vocabulary()); err != nil {
			return Capture{}, fmt.Errorf("%s %s: %w", verb, t, err)
		}
	}
	src := defaultSource(t, enc)
	for _, en := range snap.Manifest.Entries {
		if en.Source == src {
			return Capture{}, fmt.Errorf("%s %s: %w: entry %q already uses %s as its source", verb, t, ErrCovered, en.Target, src)
		}
	}
	// Retag gives a file an owned root already shares its own entry, over
	// the source the root holds; track starts only what nothing holds.
	if _, ok := snap.Tree[src]; ok && verb == "track" {
		return Capture{}, fmt.Errorf("%s %s: %w: %s already exists in the source tree", verb, t, ErrCovered, src)
	}
	blob := lv.bytes
	if enc != "" {
		if blob, err = snap.cr().SealFile(enc, src, lv.bytes); err != nil {
			return Capture{}, fmt.Errorf("%s %s: seal: %w", verb, t, err)
		}
	}
	mode := uint32(gitModeFile)
	if lv.info.Mode().Perm()&0o111 != 0 {
		mode = gitModeExec
	}
	scope := model.ScopeShared
	if enc != "" {
		scope = model.Scope(enc)
	}
	return Capture{
		Changes: []store.Change{{Path: manifest.FileName, Blob: nm, Mode: gitModeFile}, {Path: src, Blob: blob, Mode: mode}},
		Paths:   []model.Target{t},
		Scopes:  map[model.Target]model.Scope{t: scope},
	}, nil
}

// ErrNotFile reports a track of a path that is not a regular file.
var ErrNotFile = errors.New("not a regular file")

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	b, err := toml.Marshal(map[string]string{"v": s})
	if err != nil {
		return fmt.Sprintf("%q", s)
	}
	_, v, _ := strings.Cut(strings.TrimSpace(string(b)), "= ")
	return v
}

func defaultSource(t model.Target, enc model.EnclaveName) model.SourcePath {
	if enc != "" {
		return model.SourcePath("sealed/" + string(enc) + "/" + string(t))
	}
	return model.SourcePath("files/" + string(t))
}

// moveSource maps a source path between files/ and sealed/<enclave>/.
func moveSource(src model.SourcePath, from, to model.EnclaveName) (model.SourcePath, error) {
	s := string(src)
	var rest string
	switch {
	case from != "" && strings.HasPrefix(s, "sealed/"+string(from)+"/"):
		rest = strings.TrimPrefix(s, "sealed/"+string(from)+"/")
	case from == "" && strings.HasPrefix(s, "files/"):
		rest = strings.TrimPrefix(s, "files/")
	default:
		return "", fmt.Errorf("source %s is not under files/ or sealed/<enclave>/", src)
	}
	if to != "" {
		return model.SourcePath("sealed/" + string(to) + "/" + rest), nil
	}
	return model.SourcePath("files/" + rest), nil
}

var (
	reTable = regexp.MustCompile(`^\s*\[`)
	reFile  = regexp.MustCompile(`^\s*\[\[\s*file\s*\]\]`)
	reKey   = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=`)
)

// editEntry sets or removes top-level string keys in the idx-th [[file]]
// table of a manifest, touching no other line. An empty value removes the key.
func editEntry(src []byte, idx int, set map[string]string) ([]byte, error) {
	lines := strings.SplitAfter(string(src), "\n")
	start, n := -1, 0
	for i, l := range lines {
		if reFile.MatchString(l) {
			if n == idx {
				start = i
				break
			}
			n++
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("manifest has no [[file]] entry %d", idx)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if reTable.MatchString(lines[i]) {
			end = i
			break
		}
	}
	done := map[string]bool{}
	var block []string
	anchor := 0 // insert new keys after the target line, or after the header
	for i := start + 1; i < end; i++ {
		l := lines[i]
		if m := reKey.FindStringSubmatch(l); m != nil {
			if v, ok := set[m[1]]; ok {
				done[m[1]] = true
				if v == "" {
					continue
				}
				if cur, ok := lineValue(l, m[1]); !ok || cur != v {
					l = m[1] + " = " + tomlQuote(v) + trailingComment(l) + "\n"
				}
			}
			if m[1] == "target" {
				anchor = len(block) + 1
			}
		}
		block = append(block, l)
	}
	var add []string
	for _, k := range []string{"source", "when", "enclave"} {
		if v, ok := set[k]; ok && v != "" && !done[k] {
			add = append(add, k+" = "+tomlQuote(v)+"\n")
		}
	}
	if anchor > 0 && !strings.HasSuffix(block[anchor-1], "\n") {
		block[anchor-1] += "\n"
	}
	block = append(block[:anchor], append(add, block[anchor:]...)...)
	out := strings.Join(lines[:start+1], "") + strings.Join(block, "") + strings.Join(lines[end:], "")
	return []byte(out), nil
}

// lineValue parses one `key = "value"` line and returns its string value.
func lineValue(line, key string) (string, bool) {
	var m map[string]any
	if err := toml.Unmarshal([]byte(line), &m); err != nil {
		return "", false
	}
	s, ok := m[key].(string)
	return s, ok
}

// trailingComment returns the inline comment of a one-line `key = value`
// line, with the blanks before it, or "" when it has none.
func trailingComment(line string) string {
	line = strings.TrimRight(line, "\r\n")
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '"' && c == '\\':
			i++
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '"' || c == '\''):
			quote = c
		case quote == 0 && c == '#':
			j := i
			for j > 0 && (line[j-1] == ' ' || line[j-1] == '\t') {
				j--
			}
			return line[j:]
		}
	}
	return ""
}

// tomlQuote writes a TOML basic string.
func tomlQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}
