package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

// StatusFile is the one file in a status ref's tree.
const StatusFile = "status.json"

const (
	statusLocalPrefix  = "refs/yadm/status/"
	statusRemotePrefix = "refs/remotes/origin/yadm/status/"
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

// ListRefs implements Store.
func (r *Repo) ListRefs(ctx context.Context, prefix string) (map[string]model.CommitID, error) {
	out, err := r.git(ctx, "for-each-ref", "--format=%(objectname) %(refname)", prefix)
	if err != nil {
		return nil, err
	}
	refs := map[string]model.CommitID{}
	for _, l := range strings.Split(string(out), "\n") {
		id, name, ok := strings.Cut(strings.TrimSpace(l), " ")
		if ok {
			refs[name] = model.CommitID(id)
		}
	}
	return refs, nil
}

// ReadAll reads every machine's status record: the local ref for this
// machine, the fetched copy for every other machine. When both exist, the
// newer one in the fast-forward chain wins.
func (sr statusRefs) ReadAll(ctx context.Context) (map[model.MachineID]model.Status, error) {
	heads := map[model.MachineID]model.CommitID{}
	for _, prefix := range []string{statusRemotePrefix, statusLocalPrefix} {
		refs, err := sr.s.ListRefs(ctx, prefix)
		if err != nil {
			return nil, err
		}
		for name, id := range refs {
			m := model.MachineID(strings.TrimPrefix(name, prefix))
			prev, seen := heads[m]
			if seen && prev != id {
				// Keep the descendant; on divergence prefer the local ref.
				if newer, err := sr.s.IsAncestor(ctx, id, prev); err != nil {
					return nil, err
				} else if newer {
					continue
				}
			}
			heads[m] = id
		}
	}
	out := make(map[model.MachineID]model.Status, len(heads))
	for m, id := range heads {
		b, err := sr.s.ReadPath(ctx, id, StatusFile)
		if err != nil {
			return nil, fmt.Errorf("status of %s: %w", m, err)
		}
		var st model.Status
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("status of %s: %w", m, err)
		}
		out[m] = st
	}
	return out, nil
}

// Publish appends st to this machine's local status ref with a
// compare-and-swap. It refuses a record for another machine.
func (sr statusRefs) Publish(ctx context.Context, st model.Status) error {
	if st.Machine == "" {
		st.Machine = sr.self
	}
	if st.Machine != sr.self {
		return fmt.Errorf("status: machine %s may not publish for %s", sr.self, st.Machine)
	}
	if st.Schema == 0 {
		st.Schema = model.StatusSchema
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	ref := fleet.StatusRef(sr.self)
	local, err := sr.s.ResolveRef(ctx, ref)
	if err != nil {
		return err
	}
	parent := local
	if parent == "" {
		// Continue the chain from the fetched copy so the push fast-forwards.
		if parent, err = sr.s.ResolveRef(ctx, statusRemotePrefix+string(sr.self)); err != nil {
			return err
		}
	}
	tree, err := sr.s.WriteTree(ctx, "", []Change{{Path: StatusFile, Blob: b, Mode: 0o100644}})
	if err != nil {
		return err
	}
	var parents []model.CommitID
	if parent != "" {
		parents = []model.CommitID{parent}
	}
	msg := Message{
		Subject:  "status(" + string(sr.self) + ")",
		Trailers: []Trailer{{Key: TrailerMachine, Value: string(sr.self)}, {Key: TrailerAuto, Value: "1"}},
	}
	id, err := sr.s.CommitTree(ctx, tree, parents, msg)
	if err != nil {
		return err
	}
	return sr.s.UpdateRef(ctx, ref, id, local)
}
