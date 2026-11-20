package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
)

// sealedEnclave returns the enclave of a whole-file sealed source path.
func sealedEnclave(p model.SourcePath) (model.EnclaveName, string, bool) {
	s := string(p)
	if !strings.HasPrefix(s, "sealed/") {
		return "", "", false
	}
	rest := strings.TrimPrefix(s, "sealed/")
	i := strings.IndexByte(rest, '/')
	if i <= 0 || i == len(rest)-1 {
		return "", "", false
	}
	return model.EnclaveName(rest[:i]), rest[i+1:], true
}

// MergeSealed resolves a replay conflict on a sealed file this machine can
// open: it opens the three stages, merges the plaintext with textmerge.Merge3
// in memory and reseals. A remaining conflict comes back as a Hold with the
// stage blob ids; no plaintext or marker text is returned in the Change.
func (e *Engine) MergeSealed(ctx context.Context, snap *Snapshot, c store.Conflict) (*store.Change, *model.Hold, error) {
	enc, rest, ok := sealedEnclave(c.Path)
	if !ok {
		return nil, nil, fmt.Errorf("merge %s: not a sealed file", c.Path)
	}
	if snap == nil || !snap.canOpen(enc) {
		return nil, nil, fmt.Errorf("merge %s: %w", c.Path, crypt.ErrNotMember)
	}
	target := model.Target(rest)
	if snap.Plan != nil {
		for t, r := range snap.Plan.Targets {
			if r.Source == c.Path {
				target = t
				break
			}
		}
	}
	conflict := func(detail string) (*store.Change, *model.Hold, error) {
		var prev []model.Hold
		if st, err := e.loadState(); err == nil {
			prev = st.Holds
		}
		h := model.KeepSince(prev, model.Hold{Target: target, Scope: model.Scope(enc), Reason: model.HoldConflict,
			Detail: detail, Base: c.Base, Ours: c.Ours, Theirs: c.Theirs}, e.Now())
		h.Next = []string{"yadm hold show " + h.ID}
		return nil, &h, nil
	}
	if c.Ours == "" || c.Theirs == "" {
		return conflict("one side deleted the file and the other changed it")
	}
	// The base is history and is never delivered. Both sides open only
	// under the current epoch: the merge reseals its result under the
	// current epoch, so a removed member's old-epoch forgery on either side
	// (a replay may name the fetched side ours or theirs) would come out
	// freshly sealed. A side that does not open is a conflict hold.
	open := func(s *Snapshot, id string) ([]byte, error) {
		if id == "" {
			return nil, nil
		}
		b, err := e.Store.ReadBlob(ctx, id)
		if err != nil {
			return nil, err
		}
		return s.cr().OpenFile(enc, c.Path, b)
	}
	base, err := open(snap.history(), c.Base)
	if err != nil {
		return nil, nil, fmt.Errorf("merge %s: base: %w", c.Path, err)
	}
	ours, err := open(snap.strict(), c.Ours)
	if detail, ok := sealedOpenFailure(err); ok {
		return conflict("our side: " + detail)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("merge %s: ours: %w", c.Path, err)
	}
	theirs, err := open(snap.strict(), c.Theirs)
	if detail, ok := sealedOpenFailure(err); ok {
		return conflict("their side: " + detail)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("merge %s: theirs: %w", c.Path, err)
	}
	merged, regions, err := e.Text.Merge3(base, ours, theirs)
	if err != nil {
		return nil, nil, fmt.Errorf("merge %s: %w", c.Path, err)
	}
	if len(regions) > 0 {
		return conflict(fmt.Sprintf("%d conflicting region(s) after an in-memory merge", len(regions)))
	}
	sealed, err := snap.cr().SealFile(enc, c.Path, merged)
	if err != nil {
		return nil, nil, fmt.Errorf("merge %s: seal: %w", c.Path, err)
	}
	return &store.Change{Path: c.Path, Blob: sealed, Mode: sourceMode(snap, c.Path)}, nil, nil
}

// Reseal reseals every file, value and region of an enclave under its
// current epoch, after a remove or rotate. The result is one protected commit.
// It covers every sealed/<enclave>/ file in the tree and every file of every
// manifest entry (templates and globs included) whose seal rules or regions
// may hold the enclave's tokens, whether or not the entry applies to this
// machine. A template whose source the rules cannot parse comes back as an
// uncapturable hold, to reseal by hand. Content under an epoch below the
// signed min_epoch does not open and fails the reseal.
func (e *Engine) Reseal(ctx context.Context, snap *Snapshot, enclave model.EnclaveName) (Capture, error) {
	out := Capture{Scopes: map[model.Target]model.Scope{}}
	if snap == nil {
		return out, errors.New("reseal: no snapshot")
	}
	if !snap.canOpen(enclave) {
		return out, fmt.Errorf("reseal %s: %w", enclave, crypt.ErrNotMember)
	}
	scope := model.Scope(enclave)
	targetOf := map[model.SourcePath]model.Target{}
	if snap.Plan != nil {
		for t, r := range snap.Plan.Targets {
			targetOf[r.Source] = t
		}
	}
	var paths []model.SourcePath
	for p := range snap.Tree {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	add := func(p model.SourcePath, t model.Target, b []byte) {
		out.Changes = append(out.Changes, store.Change{Path: p, Blob: b, Mode: sourceMode(snap, p)})
		out.Paths = append(out.Paths, t)
		out.Scopes[t] = scope
	}

	for _, p := range paths {
		enc, rest, ok := sealedEnclave(p)
		if !ok || enc != enclave {
			continue
		}
		raw, err := e.Store.ReadBlob(ctx, snap.Tree[p].Blob)
		if err != nil {
			return out, err
		}
		plain, err := snap.cr().OpenFile(enclave, p, raw)
		if err != nil {
			return out, fmt.Errorf("reseal %s: %w", p, err)
		}
		fresh, err := snap.cr().SealFile(enclave, p, plain)
		if err != nil {
			return out, fmt.Errorf("reseal %s: %w", p, err)
		}
		if !bytes.Equal(fresh, raw) {
			t, ok := targetOf[p]
			if !ok {
				t = model.Target(rest)
			}
			add(p, t, fresh)
		}
	}

	if snap.Manifest == nil {
		return out, nil
	}
	sealer := snap.sealer()
	done := map[model.SourcePath]bool{}
	for _, en := range snap.Manifest.Entries {
		if en.Enclave != "" {
			continue // whole files: the sealed/ loop above
		}
		touches := en.Regions
		for _, v := range en.Seal {
			if v == enclave {
				touches = true
			}
		}
		if !touches {
			continue
		}
		for _, r := range manifest.Expand(en, paths) {
			te, ok := snap.Tree[r.Source]
			if !ok || done[r.Source] {
				continue
			}
			done[r.Source] = true
			raw, err := e.Store.ReadBlob(ctx, te.Blob)
			if err != nil {
				return out, err
			}
			fresh, err := e.Rules.Reseal(raw, rules.SpecFor(r), enclave, sealer)
			if err != nil {
				if en.Template {
					h := model.KeepSince(nil, model.Hold{Target: r.Target, Scope: scope, Reason: model.HoldUncapturable,
						Detail: "reseal: the template source does not parse as " + string(en.Format) + "; reseal its tokens by hand: " + err.Error()}, e.Now())
					out.Holds = append(out.Holds, h)
					continue
				}
				return out, fmt.Errorf("reseal %s: %w", r.Source, err)
			}
			if !bytes.Equal(fresh, raw) {
				add(r.Source, r.Target, fresh)
			}
		}
	}
	return out, nil
}
