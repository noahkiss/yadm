package apply

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
)

// ErrRefused reports a source move or an untrack the manifest does not
// allow as asked: the caller must change the request, not retry.
var ErrRefused = errors.New("refused")

// SourceMove is the source change that renames a source within its scope.
type SourceMove struct {
	From, To model.SourcePath
	Targets  []model.Target // the targets of the entries that read From
	Scope    model.Scope
	// Changes are the manifest edit, the deletion of From and the new
	// blob at To. None is a target change: the content each target gets
	// stays the same, so they commit as source changes.
	Changes []store.Change
}

// MoveSource renames the source from to to at the source head, within one
// scope: files/ to files/, or sealed/<e>/ to sealed/<e>/. Every literal
// entry that reads from gets its `source` line pointed at to, or loses it
// when to is the entry's default source; no other manifest line changes.
// A sealed blob is opened under from and sealed under to with the
// enclave's current epoch, and sealed values and regions are rebound the
// same way (both bind the source path), all in memory. Only a member of
// every enclave involved can move it (crypt.ErrNotMember).
//
// It refuses (ErrRefused) a change of scope, which is retag's job, a from
// that no literal entry reads, a from a glob entry reads, and a to that
// exists or that another entry or glob would read.
func (e *Engine) MoveSource(ctx context.Context, from, to model.SourcePath) (SourceMove, error) {
	fail := func(format string, a ...any) (SourceMove, error) {
		return SourceMove{}, fmt.Errorf("source mv %s %s: %w: %s", from, to, ErrRefused, fmt.Sprintf(format, a...))
	}
	for _, p := range []model.SourcePath{from, to} {
		if s := string(p); s == "" || path.IsAbs(s) || path.Clean(s) != s || strings.HasPrefix(s, "../") || s == ".." {
			return fail("%q is not a clean path relative to the source root", p)
		}
	}
	if from == to {
		return fail("the paths are the same")
	}
	fromEnc, ok := sourceScope(from)
	if !ok {
		return fail("%s is not under files/ or sealed/<enclave>/", from)
	}
	toEnc, ok := sourceScope(to)
	if !ok {
		return fail("%s is not under files/ or sealed/<enclave>/", to)
	}
	if fromEnc != toEnc {
		return fail("moving between files/ and sealed/<enclave>/ changes who can read it; use yadm retag")
	}
	head, err := e.Store.Head(ctx)
	if err != nil {
		return SourceMove{}, err
	}
	snap, err := e.snapshot(ctx, head)
	if err != nil {
		return SourceMove{}, err
	}
	if snap.Manifest == nil {
		return SourceMove{}, errors.New("source mv: snapshot has no manifest")
	}
	if _, ok := snap.Tree[from]; !ok {
		return fail("%s is not in the source tree", from)
	}
	if fromEnc != "" && !snap.canOpen(fromEnc) {
		return SourceMove{}, fmt.Errorf("source mv %s: %w: %s", from, crypt.ErrNotMember, fromEnc)
	}
	idxs, err := readers(snap, from)
	if err != nil {
		return fail("%v", err)
	}
	if len(idxs) == 0 {
		return fail("no manifest entry names %s as its source; an owned root's file moves with its target", from)
	}
	entry := snap.Manifest.Entries[idxs[0]]
	if len(idxs) > 1 {
		for _, i := range idxs {
			if sp := rules.SpecOf(snap.Manifest.Entries[i]); len(sp.Seal) > 0 || sp.Regions {
				return fail("%d entries read it and one has sealed values or regions; edit the manifest by hand", len(idxs))
			}
		}
	}
	if err := destinationFree(snap, to, idxs...); err != nil {
		return fail("%v", err)
	}
	raw, err := e.Store.ReadPath(ctx, head, from)
	if err != nil {
		return SourceMove{}, err
	}
	blob, err := e.rebind(snap, entry, raw, from, to, fromEnc, toEnc)
	if err != nil {
		return SourceMove{}, fmt.Errorf("source mv %s: %w", from, err)
	}

	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return SourceMove{}, err
	}
	nm := mb
	var targets []model.Target
	for _, i := range idxs {
		en := snap.Manifest.Entries[i]
		line := string(to)
		if to == defaultSource(en.Target, en.Enclave) {
			line = "" // the default needs no source line
		}
		if nm, err = editEntry(nm, i, map[string]string{"source": line}); err != nil {
			return fail("%v; edit the manifest by hand", err)
		}
		targets = append(targets, en.Target)
	}
	check, err := manifest.Parse(nm)
	if err != nil {
		return fail("edited manifest does not parse: %v", err)
	}
	if len(check.Entries) != len(snap.Manifest.Entries) {
		return fail("edited manifest does not say what was asked")
	}
	for i, a := range snap.Manifest.Entries {
		b := check.Entries[i]
		want := a.Source
		if slices.Contains(idxs, i) {
			if effectiveSource(b) != to {
				return fail("edited manifest does not say what was asked")
			}
			want = b.Source
		}
		if a.Target != b.Target || a.When != b.When || a.Enclave != b.Enclave || b.Source != want {
			return fail("edited manifest does not say what was asked")
		}
	}
	if err := e.checkEdited(ctx, head, snap, nm, "", ""); err != nil {
		return SourceMove{}, fmt.Errorf("source mv %s: %w", from, err)
	}
	scope := model.ScopeShared
	if toEnc != "" {
		scope = model.Scope(toEnc)
	}
	return SourceMove{
		From: from, To: to, Targets: targets, Scope: scope,
		Changes: []store.Change{
			{Path: manifest.FileName, Blob: nm, Mode: gitModeFile},
			{Path: from, Delete: true},
			{Path: to, Blob: blob, Mode: sourceMode(snap, from)},
		},
	}, nil
}

// sourceScope returns the enclave a source path is sealed for ("" under
// files/), and false for a path outside files/ and sealed/<enclave>/.
func sourceScope(p model.SourcePath) (model.EnclaveName, bool) {
	s := string(p)
	if rest, ok := strings.CutPrefix(s, "files/"); ok && rest != "" {
		return "", true
	}
	if rest, ok := strings.CutPrefix(s, "sealed/"); ok {
		enc, name, ok := strings.Cut(rest, "/")
		if ok && enc != "" && name != "" {
			return model.EnclaveName(enc), true
		}
	}
	return "", false
}

// readers returns the positions of the literal entries whose source is
// src. A glob entry that reads src fails: its source is a directory the
// manifest names, not this file.
func readers(snap *Snapshot, src model.SourcePath) ([]int, error) {
	tree := slices.Collect(maps.Keys(snap.Tree))
	sort.Slice(tree, func(i, j int) bool { return tree[i] < tree[j] })
	var out []int
	for i, en := range snap.Manifest.Entries {
		if manifest.IsGlob(string(en.Target)) {
			for _, r := range manifest.Expand(en, tree) {
				if r.Source == src {
					return nil, fmt.Errorf("glob entry %q reads %s; rename its target instead", en.Target, src)
				}
			}
			continue
		}
		if effectiveSource(en) == src {
			out = append(out, i)
		}
	}
	return out, nil
}
