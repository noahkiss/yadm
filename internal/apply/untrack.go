package apply

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
)

// UntrackOptions picks the entry Untrack removes.
type UntrackOptions struct {
	// Source picks one of several entries for the target by its source.
	// With an empty target it alone names the entry.
	Source model.SourcePath
}

// Untracked is the source change that stops managing one entry.
type Untracked struct {
	Target     model.Target
	Source     model.SourcePath
	Scope      model.Scope
	SourceKept bool // another entry still reads the source, so it stays
	// Here reports that the entry applies on this machine: the commit
	// must forget the target here (Forget), or its own apply would delete
	// the file as one that left the plan.
	Here bool
	// Changes are the manifest edit and the source's deletion. Neither is
	// a target change: they commit as source changes, and no plaintext is
	// read or written.
	Changes []store.Change
}

// Untrack removes one literal [[file]] entry, with its [file.*] sub-tables
// and the comment lines directly above it, and deletes its source unless
// another entry (on any machine) still reads it, in one change at the
// source head. The target file stays where it is. A target with several
// entries needs opts.Source (ErrVariants). Only a member of every enclave
// the entry seals for may remove it (crypt.ErrNotMember). It refuses
// (ErrBadRequest) a path no literal entry names, such as one a glob entry or
// an owned root covers.
func (e *Engine) Untrack(ctx context.Context, t model.Target, opts UntrackOptions) (Untracked, error) {
	name := string(t)
	if name == "" {
		name = string(opts.Source)
	}
	fail := func(format string, a ...any) (Untracked, error) {
		return Untracked{}, fmt.Errorf("untrack %s: %w: %s", name, ErrBadRequest, fmt.Sprintf(format, a...))
	}
	head, err := e.Store.Head(ctx)
	if err != nil {
		return Untracked{}, err
	}
	snap, err := e.snapshot(ctx, head)
	if err != nil {
		return Untracked{}, err
	}
	if snap.Manifest == nil {
		return Untracked{}, errors.New("untrack: snapshot has no manifest")
	}
	idx := -1
	if t == "" {
		idxs, err := readers(snap, opts.Source)
		if err != nil {
			return fail("%v", err)
		}
		switch len(idxs) {
		case 0:
			return fail("no manifest entry reads %s", opts.Source)
		case 1:
			idx = idxs[0]
		default:
			return fail("%d entries read %s; name the target too", len(idxs), opts.Source)
		}
	} else {
		if idx, err = selectEntry(snap.Manifest, t, opts.Source); err != nil {
			if errors.Is(err, ErrVariants) {
				return Untracked{}, fmt.Errorf("untrack %s: %w", t, err)
			}
			return fail("%v", err)
		}
		if idx < 0 {
			if snap.Plan != nil {
				if r, ok := snap.Plan.Targets[t]; ok && manifest.IsGlob(string(r.Entry.Target)) {
					return fail("glob entry %q covers it; delete the file and commit the deletion with yadm commit %s", r.Entry.Target, model.ShellQuote(string(t)))
				}
				if root := snap.Plan.Root(t); root != nil {
					return fail("owned root %q covers it; delete the file and commit the deletion, or leave it untracked here with yadm hold ignore", root.Path)
				}
			}
			return fail("no manifest entry names it")
		}
	}
	entry := snap.Manifest.Entries[idx]
	t = entry.Target
	src := effectiveSource(entry)
	need := []model.EnclaveName{}
	if entry.Enclave != "" {
		need = append(need, entry.Enclave)
	}
	spec := rules.SpecOf(entry)
	need = append(need, slices.Collect(maps.Values(spec.Seal))...)
	if _, ok := snap.Tree[src]; ok && spec.Regions {
		raw, err := e.Store.ReadPath(ctx, head, src)
		if err != nil {
			return Untracked{}, err
		}
		encs, err := rules.RegionEnclaves(raw)
		if err != nil {
			return fail("%v", err)
		}
		need = append(need, encs...)
	}
	for _, enc := range need {
		if !snap.canOpen(enc) {
			return Untracked{}, fmt.Errorf("untrack %s: %w", t, snap.notOpen(enc))
		}
	}

	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return Untracked{}, err
	}
	nm, err := removeEntries(mb, []int{idx})
	if err != nil {
		return fail("%v; edit the manifest by hand", err)
	}
	check, err := manifest.Parse(nm)
	if err != nil {
		return fail("edited manifest does not parse: %v", err)
	}
	want := slices.Delete(slices.Clone(snap.Manifest.Entries), idx, idx+1)
	if len(check.Entries) != len(want) {
		return fail("edited manifest does not say what was asked")
	}
	for i := range want {
		a, b := want[i], check.Entries[i]
		if a.Target != b.Target || a.Source != b.Source || a.When != b.When || a.Enclave != b.Enclave {
			return fail("edited manifest does not say what was asked")
		}
	}
	if err := e.checkEdited(ctx, head, snap, nm, "", ""); err != nil {
		return Untracked{}, fmt.Errorf("untrack %s: %w", t, err)
	}
	kept := false
	tree := slices.Collect(maps.Keys(snap.Tree))
	sort.Slice(tree, func(i, j int) bool { return tree[i] < tree[j] })
	for _, en := range check.Entries {
		for _, r := range manifest.Expand(en, tree) {
			kept = kept || r.Source == src
		}
	}
	changes := []store.Change{{Path: manifest.FileName, Blob: nm, Mode: gitModeFile}}
	if _, ok := snap.Tree[src]; ok && !kept {
		changes = append(changes, store.Change{Path: src, Delete: true})
	}
	here := false
	if snap.Plan != nil {
		r, ok := snap.Plan.Targets[t]
		here = ok && r.Index == idx
	}
	return Untracked{Target: t, Source: src, Scope: entry.Scope(), SourceKept: kept, Here: here, Changes: changes}, nil
}

// Forget stops managing t on this machine and leaves the file as it is:
// its state record and every hold on it go. A file that is on disk
// (onDisk) inside an owned root accepted here is recorded as ignored, so
// the root never reports it as new. The caller saves the state.
func Forget(st *State, t model.Target, now time.Time, onDisk bool) {
	delete(st.Targets, t)
	delete(st.Seen, t)
	delete(st.Baseline, t)
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target != t {
			out = append(out, h)
		}
	}
	st.Holds = out
	if _, ok := rootOf(&manifest.Plan{Roots: st.Roots}, t); ok && onDisk {
		if st.Ignored == nil {
			st.Ignored = map[model.Target]time.Time{}
		}
		st.Ignored[t] = now
	}
}
