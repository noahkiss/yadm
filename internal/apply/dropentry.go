package apply

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// DropEntries returns the manifest edit that a committed deletion of
// targets needs at rev: each target whose applying entry on this machine
// names it literally loses that [[file]] entry, so the manifest never names
// a source the same commit deletes. A target of a glob entry or an owned
// root needs no edit; DropEntries returns nil when no target needs one.
//
// The edit fails closed: it refuses when the source would stay in use by
// another entry, when the edited manifest does not parse to the old entries
// minus exactly the dropped ones, or when it no longer validates against
// the fleet. The edit holds paths and conditions only, never file content.
func (e *Engine) DropEntries(ctx context.Context, rev model.CommitID, targets []model.Target) (*store.Change, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	snap, err := e.snapshot(ctx, rev)
	if err != nil {
		return nil, err
	}
	if snap.Manifest == nil || snap.Plan == nil {
		return nil, nil
	}
	drop := map[int]model.Target{}
	for _, t := range targets {
		r, ok := snap.Plan.Targets[t]
		if !ok || r.Index < 0 || r.Entry.Target != t || manifest.IsGlob(string(r.Entry.Target)) {
			continue // a glob or owned-root file: deleting its source is enough
		}
		drop[r.Index] = t
	}
	if len(drop) == 0 {
		return nil, nil
	}
	idxs := slices.Sorted(maps.Keys(drop))
	mb, err := e.Store.ReadPath(ctx, rev, manifest.FileName)
	if err != nil {
		return nil, err
	}
	nm, err := removeEntries(mb, idxs)
	if err != nil {
		return nil, fmt.Errorf("remove the manifest entry of %s: %w; edit the manifest by hand", joinT(drop), err)
	}
	check, err := manifest.Parse(nm)
	if err != nil {
		return nil, fmt.Errorf("remove the manifest entry of %s: edited manifest does not parse: %w", joinT(drop), err)
	}
	var want []manifest.Entry
	for i, en := range snap.Manifest.Entries {
		if _, ok := drop[i]; !ok {
			want = append(want, en)
		}
	}
	if len(check.Entries) != len(want) {
		return nil, fmt.Errorf("remove the manifest entry of %s: edited manifest does not say what was asked", joinT(drop))
	}
	for i := range want {
		a, b := want[i], check.Entries[i]
		if a.Target != b.Target || a.Source != b.Source || a.When != b.When || a.Enclave != b.Enclave {
			return nil, fmt.Errorf("remove the manifest entry of %s: edited manifest does not say what was asked", joinT(drop))
		}
	}
	// The deleted sources must not stay in use: another entry (on any
	// machine) reading one would lose its source with this commit.
	tree := slices.Collect(maps.Keys(snap.Tree))
	sort.Slice(tree, func(i, j int) bool { return tree[i] < tree[j] })
	for _, i := range idxs {
		src := snap.Plan.Targets[drop[i]].Source
		for _, en := range check.Entries {
			for _, r := range manifest.Expand(en, tree) {
				if r.Source == src {
					return nil, fmt.Errorf("remove %s: entry %q also reads its source %s; edit the manifest by hand", drop[i], en.Target, src)
				}
			}
		}
	}
	if snap.Fleet != nil {
		if err := check.LoadIncludes(func(p model.SourcePath) ([]byte, error) { return e.Store.ReadPath(ctx, rev, p) }); err != nil {
			return nil, fmt.Errorf("remove the manifest entry of %s: %w", joinT(drop), err)
		}
		if err := check.Validate(snap.Fleet.Vocabulary()); err != nil {
			return nil, fmt.Errorf("remove the manifest entry of %s: %w", joinT(drop), err)
		}
	}
	return &store.Change{Path: manifest.FileName, Blob: nm, Mode: gitModeFile}, nil
}

func joinT(m map[int]model.Target) string {
	s := make([]string, 0, len(m))
	for _, t := range m {
		s = append(s, string(t))
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

var (
	reFileSub  = regexp.MustCompile(`^\s*\[\s*file\s*\.`)
	reBlankCom = regexp.MustCompile(`^\s*(#.*)?\r?\n?$`)
	reComment  = regexp.MustCompile(`^\s*#`)
)

// removeEntries deletes the [[file]] tables at the given positions (in
// Manifest.Entries order) from a manifest, with their [file.*] sub-tables
// and the comment lines directly above each header. The comment and blank
// lines that precede the next table stay with it. No other line changes.
func removeEntries(src []byte, idxs []int) ([]byte, error) {
	lines := strings.SplitAfter(string(src), "\n")
	var heads []int
	for i, l := range lines {
		if reFile.MatchString(l) {
			heads = append(heads, i)
		}
	}
	cut := make([]bool, len(lines))
	for _, idx := range idxs {
		if idx < 0 || idx >= len(heads) {
			return nil, fmt.Errorf("manifest has no [[file]] table %d", idx)
		}
		start := heads[idx]
		end := len(lines)
		for i := start + 1; i < len(lines); i++ {
			if reTable.MatchString(lines[i]) && !reFileSub.MatchString(lines[i]) {
				end = i
				break
			}
		}
		// Leave the comments and blank lines that lead into the next table.
		for end > start+1 && reBlankCom.MatchString(lines[end-1]) {
			end--
		}
		// Take the comment lines directly above the header.
		for start > 0 && reComment.MatchString(lines[start-1]) {
			start--
		}
		for i := start; i < end; i++ {
			cut[i] = true
		}
		// One blank line separated this table from the one before: drop it.
		if start > 0 && end < len(lines) && strings.TrimSpace(lines[start-1]) == "" && strings.TrimSpace(lines[end]) == "" {
			cut[start-1] = true
		}
	}
	var b strings.Builder
	for i, l := range lines {
		if !cut[i] {
			b.WriteString(l)
		}
	}
	return []byte(b.String()), nil
}
