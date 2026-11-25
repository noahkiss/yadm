package apply

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// reVariant is a safe variant name: one path segment, no leading dot or
// dash, so it never names a directory, a hidden file or a flag.
var reVariant = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

// variantSource is the source of variant name of target t: the name goes
// before the base name's extension (`dir/route.toml` becomes
// `dir/route.<name>.toml`), or after a base name without one (`.profile`
// becomes `.profile.<name>`), under files/ or sealed/<enclave>/.
func variantSource(t model.Target, name string, enc model.EnclaveName) model.SourcePath {
	dir, base := path.Split(string(t))
	stem, ext := base, ""
	if i := strings.LastIndex(base, "."); i > 0 {
		stem, ext = base[:i], base[i:]
	}
	return defaultSource(model.Target(dir+stem+"."+name+ext), enc)
}

// scopeRest is a source path without its files/ or sealed/<enclave>/ prefix.
func scopeRest(src model.SourcePath) string {
	s := string(src)
	if r, ok := strings.CutPrefix(s, "files/"); ok {
		return r
	}
	if r, ok := strings.CutPrefix(s, "sealed/"); ok {
		if _, rest, ok := strings.Cut(r, "/"); ok {
			return rest
		}
	}
	return s
}

// trackVariant adds a variant of a target that literal entries already
// name: a new [[file]] entry for t with source variantSource(t, name, enc),
// opts.When and the enclave, and this machine's live bytes as its source,
// sealed for an enclave, in one change. The new entry must apply on this
// machine (it captures the live file here), and no other entry for t may
// apply on any fleet machine it applies to. It refuses (ErrBadRequest) an
// unsafe name, an empty when, a target no literal entry names, a when that
// does not apply here, and a variant name or source that already exists; a
// non-member of the enclave fails with crypt.ErrNotMember, and a variant
// outside the enclave of an enclave root that covers t with ErrRootRefused.
func (e *Engine) trackVariant(ctx context.Context, head model.CommitID, snap *Snapshot, t model.Target, opts TrackOptions) (Capture, error) {
	name, when, enc := opts.Variant, opts.When, opts.Enclave
	fail := func(format string, a ...any) (Capture, error) {
		return Capture{}, fmt.Errorf("track %s --variant %s: %w: %s", t, name, ErrBadRequest, fmt.Sprintf(format, a...))
	}
	if !reVariant.MatchString(name) {
		return fail("a variant name is one path segment of letters, digits, '.', '_' and '-', not starting with '.' or '-'")
	}
	if when == "" {
		return fail("a variant needs --when: without it, it applies everywhere the existing entries do")
	}
	var existing []manifest.Entry
	for _, en := range snap.Manifest.Entries {
		if en.Target == t && !manifest.IsGlob(string(en.Target)) {
			existing = append(existing, en)
		}
	}
	if len(existing) == 0 {
		return fail("no manifest entry names it; track the first copy with yadm track %s --when <condition>", model.ShellQuote(string(t)))
	}
	if snap.Manifest.Generated(t) {
		return fail("a task generates it (outputs); it is never tracked")
	}
	if enc != "" && snap.Fleet != nil {
		if d, ok := snap.Fleet.Types[model.TypeName(enc)]; !ok || !d.Enclave {
			return Capture{}, fmt.Errorf("track %s: %q is not an enclave type", t, enc)
		}
	}
	if r, ok := e.enclaveRoot(snap, t); ok && r.Enclave != enc {
		return Capture{}, fmt.Errorf("track %s --variant %s: %w: enclave root %s (enclave %s) covers it, so its plaintext stays in that enclave; pass --enclave %s", t, name, ErrRootRefused, r.Path, r.Enclave, r.Enclave)
	}
	if enc != "" && !snap.canOpen(enc) {
		return Capture{}, fmt.Errorf("track %s: %w", t, snap.notOpen(enc))
	}
	src := variantSource(t, name, enc)
	for _, en := range existing {
		if s := effectiveSource(en); scopeRest(s) == scopeRest(src) {
			return fail("variant %q already exists: an entry for it reads %s", name, s)
		}
	}
	if err := destinationFree(snap, src); err != nil {
		return fail("%v", err)
	}

	abs, err := e.abs(t)
	if err != nil {
		return Capture{}, err
	}
	lv, err := e.readTarget(ctx, abs)
	if err != nil {
		return Capture{}, err
	}
	if !lv.exists || !lv.info.Mode().IsRegular() {
		return Capture{}, fmt.Errorf("track %s: %w: a variant captures this machine's file, and it is not a regular file in $HOME", t, ErrNotFile)
	}

	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return Capture{}, err
	}
	var add strings.Builder
	if len(mb) > 0 && mb[len(mb)-1] != '\n' {
		add.WriteString("\n")
	}
	fmt.Fprintf(&add, "\n[[file]]\ntarget = %s\nsource = %s\nwhen = %s\n", tomlString(string(t)), tomlString(string(src)), tomlString(when))
	if enc != "" {
		fmt.Fprintf(&add, "enclave = %s\n", tomlString(string(enc)))
	}
	nm := append(append([]byte{}, mb...), add.String()...)
	check, err := manifest.Parse(nm)
	if err != nil {
		return Capture{}, fmt.Errorf("track %s: edited manifest does not parse: %w", t, err)
	}
	last := check.Entries[len(check.Entries)-1]
	if last.Target != t || last.Source != src || last.When != when || last.Enclave != enc {
		return Capture{}, fmt.Errorf("track %s: edited manifest does not say what was asked", t)
	}
	if err := check.LoadIncludes(func(p model.SourcePath) ([]byte, error) { return e.Store.ReadPath(ctx, head, p) }); err != nil {
		return Capture{}, fmt.Errorf("track %s: %w", t, err)
	}
	var fv cond.Vocabulary
	if snap.Fleet != nil {
		fv = snap.Fleet.Vocabulary()
		if err := check.Validate(fv); err != nil {
			return Capture{}, fmt.Errorf("track %s: %w", t, err)
		}
	}
	vocab, err := check.Vocabulary(fv)
	if err != nil {
		return Capture{}, fmt.Errorf("track %s: %w", t, err)
	}
	tree := append(slices.Collect(maps.Keys(snap.Tree)), src)
	sort.Slice(tree, func(i, j int) bool { return tree[i] < tree[j] })
	plan, err := check.Resolve(snap.Context, tree, vocab)
	var col *manifest.CollisionError
	switch {
	case errors.As(err, &col):
		return Capture{}, fmt.Errorf("track %s: this machine would get it from more than one entry; make the variants' conditions exclusive", t)
	case err != nil:
		return Capture{}, fmt.Errorf("track %s: %w", t, err)
	}
	r, ok := plan.Targets[t]
	if !ok || r.Source != src {
		return fail("when %q does not apply on this machine; a variant captures this machine's live file, so add it on a machine the condition selects", when)
	}
	// The live file may be a copy this machine received with stronger
	// protection (a sealed entry that no longer applies here): a weaker
	// variant would commit that plaintext.
	st, err := e.loadState()
	if err != nil {
		return Capture{}, err
	}
	ts, have := st.Targets[t]
	if _, weak := e.weakened(st, ts, have, r); weak {
		hint, why, enc := "", e.floorWeak(st, r), ts.Enclave
		if len(why) > 0 {
			enc = st.Floors[t].Protection.Enclave
		} else {
			why = weakerBy(ts.prot(), protOf(r.Entry))
		}
		if enc != "" {
			hint = fmt.Sprintf("; seal the variant with --enclave %s", enc)
		}
		return fail("this machine last received it with stronger protection than the variant has (%s)%s", strings.Join(why, "; "), hint)
	}
	// Every fleet machine resolves the new entry: a variant that overlaps
	// another entry for t on any of them fails here, before a commit.
	if err := e.checkEdited(ctx, head, snap, nm, t, src); err != nil {
		return Capture{}, fmt.Errorf("track %s: %w", t, err)
	}

	blob := lv.bytes
	if enc != "" {
		if blob, err = snap.cr().SealFile(enc, src, lv.bytes); err != nil {
			return Capture{}, fmt.Errorf("track %s: seal: %w", t, err)
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
