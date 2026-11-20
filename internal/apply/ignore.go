package apply

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// ErrManaged is returned by Ignore for a target the state or the plan manages.
var ErrManaged = errors.New("managed files cannot be ignored; remove the manifest entry instead")

// ErrNotIgnorable is returned by Ignore for a path that is not an unmanaged
// regular file inside an accepted owned root.
var ErrNotIgnorable = errors.New("only an unmanaged regular file inside an accepted owned root can be ignored")

// Ignore records that an unmanaged file in an owned root is left untracked
// on purpose: scan stops reporting it and its holds go. It is local to
// this machine. Committing the file by name tracks it again. Shared
// patterns belong in the root's `ignore` globs. snap is the source this
// machine runs; a target its plan produces is refused, written yet or not.
func (e *Engine) Ignore(ctx context.Context, snap *Snapshot, t model.Target) error {
	abs, err := e.abs(t)
	if err != nil {
		return err
	}
	st, err := e.loadState()
	if err != nil {
		return err
	}
	if _, ok := st.Targets[t]; ok {
		return fmt.Errorf("ignore %s: %w", t, ErrManaged)
	}
	if snap != nil && snap.Plan != nil {
		if _, ok := snap.Plan.Targets[t]; ok {
			return fmt.Errorf("ignore %s: %w", t, ErrManaged)
		}
	}
	if _, ok := rootOf(&manifest.Plan{Roots: st.Roots}, t); !ok {
		return fmt.Errorf("ignore %s: %w", t, ErrNotIgnorable)
	}
	lv, err := e.readTarget(ctx, abs)
	if err != nil {
		return err
	}
	if !lv.exists || !lv.info.Mode().IsRegular() {
		return fmt.Errorf("ignore %s: %w", t, ErrNotIgnorable)
	}
	if st.Ignored == nil {
		st.Ignored = map[model.Target]time.Time{}
	}
	st.Ignored[t] = e.Now()
	delete(st.Seen, t)
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target != t {
			out = append(out, h)
		}
	}
	st.Holds = out
	return e.State.Save(st)
}

// Ignored reports whether t is left untracked on purpose on this machine:
// `hold ignore` recorded it, or the accepted owned root holding it has an
// ignore glob that matches it. Unattended commits (agent hooks) skip it; a
// commit that names it tracks it.
func (e *Engine) Ignored(t model.Target) bool {
	st, err := e.loadState()
	if err != nil {
		return false
	}
	return ignoredIn(st, t)
}

func ignoredIn(st *State, t model.Target) bool {
	if _, ok := st.Targets[t]; ok {
		return false
	}
	if _, ok := st.Ignored[t]; ok {
		return true
	}
	root, ok := rootOf(&manifest.Plan{Roots: st.Roots}, t)
	return ok && root.Ignored(t)
}
