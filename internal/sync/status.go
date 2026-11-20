package sync

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// collectWith adapts fleet.CollectWith to an allow check over any definition.
func collectWith(ctx context.Context, f *fleet.File, mctx model.Context, r extexec.Runner, allowed func(string, any) bool, base extexec.Request) (map[string]model.ObservedFact, []string, error) {
	return fleet.CollectWith(ctx, f, mctx, r, func(name string, def fleet.CollectorDef) bool {
		return allowed(name, def)
	}, base)
}

// publish writes this machine's status record to its status ref when one is
// due: after a sync that changed something, and at least hourly.
func (s *Syncer) publish(ctx context.Context, tip model.CommitID, changed bool, pendingCount int) error {
	if s.Status == nil {
		return nil
	}
	now := s.now()
	var last *model.Status
	if all, err := s.Status.ReadAll(ctx); err == nil {
		if x, ok := all[s.self()]; ok {
			last = &x
		}
	}
	if !fleet.PublishDue(last, changed, now) {
		return nil
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	rec := model.Status{
		Schema:   model.StatusSchema,
		Machine:  s.self(),
		Version:  s.Version,
		Applied:  st.Applied,
		LastSync: now.UTC(),
		Pending:  pendingCount,
	}
	for _, h := range st.Holds {
		rec.Held++
		if h.Reason == model.HoldConflict {
			rec.Conflicts++
		}
		if !h.Since.IsZero() && (rec.OldestHeld == nil || h.Since.Before(*rec.OldestHeld)) {
			t := h.Since.UTC()
			rec.OldestHeld = &t
		}
	}
	if tip != "" {
		if snap, err := s.Apply.Load(ctx, tip); err == nil {
			if snap.Keys != nil {
				for e, r := range snap.Keys.Rings {
					if r == nil {
						continue
					}
					if rec.Epochs == nil {
						rec.Epochs = map[model.EnclaveName]model.Epoch{}
					}
					rec.Epochs[e] = r.Current
				}
			}
			if snap.Fleet != nil && len(st.Observed) > 0 {
				// Only plain and sealed collectors leave the machine; sealing
				// happens here, before the record is written.
				plain, sealed, _ := fleet.Published(snap.Fleet, st.Observed, snap.Keys)
				if len(plain) > 0 {
					rec.Observed = plain
				}
				if len(sealed) > 0 {
					rec.Sealed = sealed
				}
			}
		}
	}
	names := make([]string, 0, len(st.Tasks))
	for n := range st.Tasks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		rec.Tasks = append(rec.Tasks, st.Tasks[n])
	}
	rec.Alerts = s.loadAlerts()
	return s.Status.Publish(ctx, rec)
}

func (s *Syncer) alertsPath() string { return filepath.Join(s.Apply.StateDir, AlertsFile) }

func (s *Syncer) loadAlerts() []model.Alert {
	if s.Apply.StateDir == "" {
		return nil
	}
	b, err := os.ReadFile(s.alertsPath())
	if err != nil {
		return nil
	}
	var out []model.Alert
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// recordAlerts appends alerts to the state directory, keeping the newest.
// The status record carries them to the rest of the fleet.
func (s *Syncer) recordAlerts(alerts []model.Alert) error {
	if len(alerts) == 0 || s.Apply.StateDir == "" {
		return nil
	}
	all := append(s.loadAlerts(), alerts...)
	if len(all) > maxAlerts {
		all = all[len(all)-maxAlerts:]
	}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	p := s.alertsPath()
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// reviewScopes lists shared and every enclave of the fleet file at main.
func reviewScopes(ctx context.Context, st store.Store) ([]model.Scope, error) {
	scopes := []model.Scope{model.ScopeShared}
	main, err := st.ResolveRef(ctx, store.RefMain)
	if err != nil || main == "" {
		return scopes, err
	}
	b, err := st.ReadPath(ctx, main, fleet.FileName)
	if errors.Is(err, fs.ErrNotExist) {
		return scopes, nil
	}
	if err != nil {
		return nil, err
	}
	f, err := fleet.Parse(b)
	if err != nil {
		return scopes, nil
	}
	for _, e := range f.Enclaves() {
		scopes = append(scopes, model.Scope(e))
	}
	return scopes, nil
}

const remoteYadmPrefix = "refs/remotes/origin/yadm/"

// remoteReviewed is the fetched copy of a reviewed ref.
func remoteReviewed(s model.Scope) string { return remoteYadmPrefix + "reviewed/" + string(s) }

// reviewedSpecs fast-forwards local reviewed refs the remote advanced, and
// returns refspecs for the ones this machine advanced. Diverged refs are
// left for the next ack.
func (s *Syncer) reviewedSpecs(ctx context.Context) ([]string, error) {
	scopes, err := reviewScopes(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	var specs []string
	for _, sc := range scopes {
		ref := store.RefReviewed(sc)
		local, err := s.Store.ResolveRef(ctx, ref)
		if err != nil {
			return nil, err
		}
		remote, err := s.Store.ResolveRef(ctx, remoteReviewed(sc))
		if err != nil {
			return nil, err
		}
		switch {
		case local == remote:
			continue
		case local == "":
			if err := s.Store.UpdateRef(ctx, ref, remote, ""); err != nil {
				return nil, err
			}
			continue
		case remote == "":
			specs = append(specs, ref+":"+ref)
			continue
		}
		if ok, err := s.Store.IsAncestor(ctx, local, remote); err != nil {
			return nil, err
		} else if ok {
			if err := s.Store.UpdateRef(ctx, ref, remote, local); err != nil {
				return nil, err
			}
			continue
		}
		if ok, err := s.Store.IsAncestor(ctx, remote, local); err != nil {
			return nil, err
		} else if ok {
			specs = append(specs, ref+":"+ref)
		}
	}
	return specs, nil
}
