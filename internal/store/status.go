package store

import (
	"context"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

// StatusRefs returns the fleet.StatusRefs backed by this store. Each status
// ref is a fast-forward chain of commits whose tree holds one `status.json`.
// Publish writes the local ref only; the sync loop pushes it with main.
func StatusRefs(s Store, self model.MachineID) fleet.StatusRefs {
	return statusRefs{s: s, self: self}
}

type statusRefs struct {
	s    Store
	self model.MachineID
}

func (statusRefs) ReadAll(context.Context) (map[model.MachineID]model.Status, error) {
	return nil, model.ErrNotImplemented
}

func (statusRefs) Publish(context.Context, model.Status) error { return model.ErrNotImplemented }
