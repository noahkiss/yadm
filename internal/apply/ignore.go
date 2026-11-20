package apply

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// ErrManaged is returned by Ignore for a target the state manages.
var ErrManaged = errors.New("managed files cannot be ignored; remove the manifest entry instead")

// Ignore records that an unmanaged file in an owned root is left untracked
// on purpose: scan stops reporting it and its holds go. It is local to
// this machine, like the baseline. Committing the file by name tracks it
// again. Shared patterns belong in the root's `ignore` globs.
func (e *Engine) Ignore(_ context.Context, t model.Target) error {
	if _, err := e.abs(t); err != nil {
		return err
	}
	st, err := e.loadState()
	if err != nil {
		return err
	}
	if _, ok := st.Targets[t]; ok {
		return fmt.Errorf("ignore %s: %w", t, ErrManaged)
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
