package fleet

import (
	"context"
	"fmt"
	"sync"

	"github.com/noahkiss/yadm/internal/model"
)

// MemoryStatusRefs is an in-memory StatusRefs for tests and dry runs. It
// enforces the status-ref rules: a machine publishes only its own record,
// and a record never moves its last sync backwards.
type MemoryStatusRefs struct {
	Self model.MachineID

	mu sync.Mutex
	m  map[model.MachineID]model.Status
}

// NewMemoryStatusRefs returns an empty store for machine self, seeded with
// other machines' records.
func NewMemoryStatusRefs(self model.MachineID, seed map[model.MachineID]model.Status) *MemoryStatusRefs {
	m := map[model.MachineID]model.Status{}
	for k, v := range seed {
		m[k] = v
	}
	return &MemoryStatusRefs{Self: self, m: m}
}

// ReadAll returns a copy of every record.
func (r *MemoryStatusRefs) ReadAll(context.Context) (map[model.MachineID]model.Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[model.MachineID]model.Status, len(r.m))
	for k, v := range r.m {
		out[k] = v
	}
	return out, nil
}

// Publish stores this machine's record.
func (r *MemoryStatusRefs) Publish(_ context.Context, s model.Status) error {
	if s.Machine != r.Self {
		return fmt.Errorf("status for %s: this machine publishes only %s", s.Machine, r.Self)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if prev, ok := r.m[s.Machine]; ok && s.LastSync.Before(prev.LastSync) {
		return fmt.Errorf("status for %s: not a fast-forward", s.Machine)
	}
	r.m[s.Machine] = s
	return nil
}
