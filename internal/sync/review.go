package sync

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// ReviewItem is one unreviewed commit with its plaintext diff (members only
// see plaintext for enclave scopes).
type ReviewItem struct {
	Commit store.Commit `json:"commit"`
	Scope  model.Scope  `json:"scope"`
	Diff   string       `json:"diff"`
	// Note is the commit's review note, when one exists (RefReviewNotes).
	// The CLI fills it.
	Note *Note `json:"note,omitempty"`
}

// inScope reports whether a source path belongs to scope: an enclave owns
// sealed/<enclave>/ and keys/<enclave>/; shared owns everything else.
func inScope(p model.SourcePath, scope model.Scope) bool {
	s := string(p)
	if scope == model.ScopeShared {
		return !strings.HasPrefix(s, "sealed/") && !strings.HasPrefix(s, "keys/")
	}
	return strings.HasPrefix(s, "sealed/"+string(scope)+"/") || strings.HasPrefix(s, "keys/"+string(scope)+"/")
}

// reviewedBase returns the further of the local and fetched reviewed refs.
func reviewedBase(ctx context.Context, st store.Store, scope model.Scope) (model.CommitID, error) {
	local, err := st.ResolveRef(ctx, store.RefReviewed(scope))
	if err != nil {
		return "", err
	}
	remote, err := st.ResolveRef(ctx, remoteReviewed(scope))
	if err != nil {
		return "", err
	}
	if local == "" || local == remote {
		return remote, nil
	}
	if remote == "" {
		return local, nil
	}
	if ok, err := st.IsAncestor(ctx, local, remote); err != nil {
		return "", err
	} else if ok {
		return remote, nil
	}
	return local, nil
}

// Unreviewed lists commits in RefReviewed(scope)..main that touch scope,
// oldest first, each with a diff of the scope's paths. Sealed files show
// plaintext only when keys open the enclave; otherwise the diff names the
// path and says it is sealed.
func Unreviewed(ctx context.Context, st store.Store, keys *crypt.Set, scope model.Scope) ([]ReviewItem, error) {
	if st == nil {
		return nil, errors.New("review: no store")
	}
	if scope == "" {
		return nil, errors.New("review: empty scope")
	}
	main, err := st.ResolveRef(ctx, store.RefMain)
	if err != nil || main == "" {
		return nil, err
	}
	base, err := reviewedBase(ctx, st, scope)
	if err != nil {
		return nil, err
	}
	rng := string(main)
	if base != "" {
		rng = string(base) + ".." + string(main)
	}
	commits, err := st.Log(ctx, rng, nil)
	if err != nil {
		return nil, err
	}
	// Review reads old commits: open every epoch, as log and diff do.
	if keys != nil {
		keys = keys.History()
	}
	cr := apply.SetCrypto(keys)
	var out []ReviewItem
	for i := len(commits) - 1; i >= 0; i-- {
		c := commits[i]
		var parts []string
		for _, p := range c.Paths {
			if !inScope(p, scope) {
				continue
			}
			d, err := pathDiff(ctx, st, cr, keys, c, p)
			if err != nil {
				return nil, err
			}
			parts = append(parts, d)
		}
		if len(parts) == 0 {
			continue
		}
		out = append(out, ReviewItem{Commit: c, Scope: scope, Diff: strings.Join(parts, "")})
	}
	return out, nil
}

// pathDiff renders one path's change in c against its first parent.
func pathDiff(ctx context.Context, st store.Store, cr apply.Crypto, keys *crypt.Set, c store.Commit, p model.SourcePath) (string, error) {
	read := func(rev model.CommitID) ([]byte, error) {
		if rev == "" {
			return nil, nil
		}
		b, err := st.ReadPath(ctx, rev, p)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return b, err
	}
	var parent model.CommitID
	if len(c.Parents) > 0 {
		parent = c.Parents[0]
	}
	before, err := read(parent)
	if err != nil {
		return "", err
	}
	after, err := read(c.ID)
	if err != nil {
		return "", err
	}
	if enc, ok := sealedEnclave(p); ok {
		if !keys.CanOpen(enc) {
			return fmt.Sprintf("sealed %s changed (not a member of %s)\n", p, enc), nil
		}
		if before != nil {
			if before, err = cr.OpenFile(enc, p, before); err != nil {
				return "", fmt.Errorf("review %s: %w", p, err)
			}
		}
		if after != nil {
			if after, err = cr.OpenFile(enc, p, after); err != nil {
				return "", fmt.Errorf("review %s: %w", p, err)
			}
		}
	}
	if textmerge.IsBinary(before) || textmerge.IsBinary(after) {
		return fmt.Sprintf("binary %s differs\n", p), nil
	}
	return textmerge.Diff("a/"+string(p), "b/"+string(p), before, after)
}

// Ack fast-forwards the reviewed ref for scope to upTo. It refuses a commit
// that is not on main or not a descendant of the current reviewed ref.
func Ack(ctx context.Context, st store.Store, scope model.Scope, upTo model.CommitID) error {
	if st == nil {
		return errors.New("review: no store")
	}
	if scope == "" || strings.ContainsAny(string(scope), "/ ") {
		return fmt.Errorf("review: invalid scope %q", scope)
	}
	id, err := st.ResolveRef(ctx, string(upTo))
	if err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("review: unknown commit %q", upTo)
	}
	main, err := st.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return err
	}
	if ok, err := st.IsAncestor(ctx, id, main); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("review: %s is not on main", id)
	}
	ref := store.RefReviewed(scope)
	cur, err := st.ResolveRef(ctx, ref)
	if err != nil {
		return err
	}
	base, err := reviewedBase(ctx, st, scope)
	if err != nil {
		return err
	}
	if base != "" {
		if ok, err := st.IsAncestor(ctx, base, id); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("review: %s does not descend from the reviewed ref %s; refusing to move it back", id, base)
		}
	}
	return st.UpdateRef(ctx, ref, id, cur)
}
