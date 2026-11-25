package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

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
	onDemand := slices.Sorted(slices.Values(s.Apply.OnDemand))
	if last != nil && !slices.Equal(last.OnDemand, onDemand) {
		changed = true // peers' check reads it; do not wait for the hourly record
	}
	pausedUntil, pauseID, pauseVerified, pauseIgnored := s.pauseFields()
	if !samePause(last, pausedUntil, pauseID, pauseVerified, pauseIgnored) {
		changed = true // the confirmation the initiator waits for
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	rr := ReadRerootStatus(s.Apply.StateDir, st.Holds)
	var rerootID, rerootHeld string
	if rr.Last != nil {
		rerootID = rr.Last.ID
	}
	if rr.Held != nil {
		rerootHeld = rr.Held.Task
	}
	if last != nil && (last.Reroot != rerootID || last.RerootHeld != rerootHeld) {
		changed = true // the confirmation `yadm reroot` waits for
	}
	if last != nil && (last.Home != s.Apply.Home || last.User != s.Apply.User) {
		changed = true // show --as on peers renders with them
	}
	held, conflicts, oldest, kinds := holdCounts(st.Holds)
	if last != nil && (last.Held != held || last.Conflicts != conflicts || !sameTime(last.OldestHeld, oldest) || !maps.Equal(last.HoldKinds, kinds)) {
		changed = true // fleet alerts read the holds; do not wait for the hourly record
	}
	if !fleet.PublishDue(last, changed, now) {
		return nil
	}
	rec := model.Status{
		Schema:   model.StatusSchema,
		Machine:  s.self(),
		Version:  s.Version,
		Applied:  st.Applied,
		LastSync: now.UTC(),
		Pending:  pendingCount,

		Reroot:     rerootID,
		RerootHeld: rerootHeld,

		Home: s.Apply.Home,
		User: s.Apply.User,
	}
	rec.Held, rec.Conflicts, rec.OldestHeld, rec.HoldKinds = held, conflicts, oldest, kinds
	if tip != "" {
		if snap, err := s.load(ctx, tip); err == nil {
			if keys := snap.Readable(); keys != nil {
				for e, r := range keys.Rings {
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
	if s.Apply.Pins != nil {
		for _, e := range s.enclavesAt(ctx, tip) {
			p, err := s.Apply.Pins.Get(e)
			if err != nil || p == nil {
				continue
			}
			if rec.KeyHeads == nil {
				rec.KeyHeads = map[model.EnclaveName]model.KeyHead{}
			}
			rec.KeyHeads[e] = model.KeyHead{Seq: p.Seq, Hash: p.Hash}
		}
	}
	if len(onDemand) > 0 {
		rec.OnDemand = onDemand
	}
	rec.PausedUntil, rec.PauseID, rec.PauseIgnored = pausedUntil, pauseID, pauseIgnored
	rec.PauseVerified = pauseVerified
	return s.Status.Publish(ctx, rec)
}

// holdCounts is what a status record says about holds: how many, how many
// conflicts, the oldest, and the count per kind (model.HoldKind).
func holdCounts(holds []model.Hold) (held, conflicts int, oldest *time.Time, kinds map[string]int) {
	for _, h := range holds {
		held++
		if h.Reason == model.HoldConflict {
			conflicts++
		}
		if !h.Since.IsZero() && (oldest == nil || h.Since.Before(*oldest)) {
			t := h.Since.UTC()
			oldest = &t
		}
		if kinds == nil {
			kinds = map[string]int{}
		}
		kinds[model.HoldKind(h)]++
	}
	return held, conflicts, oldest, kinds
}

func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
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

// reviewedSpecs returns refspecs for the reviewed refs this machine
// advanced. A remote advance moves the local ref only when it skips no
// commit of the scope: another machine's ack never hides a commit from this
// machine's review queue. A remote advance that skips commits is refused
// and alerted once; with no local ref, every commit of the scope counts.
// Diverged refs are left for the next ack.
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
			n, err := skippedInScope(ctx, s.Store, sc, "", remote)
			if err != nil {
				return nil, err
			}
			if n > 0 {
				if err := s.alertReviewedSkip(ctx, sc, remote, n); err != nil {
					return nil, err
				}
				continue
			}
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
			n, err := skippedInScope(ctx, s.Store, sc, local, remote)
			if err != nil {
				return nil, err
			}
			if n > 0 {
				if err := s.alertReviewedSkip(ctx, sc, remote, n); err != nil {
					return nil, err
				}
				continue
			}
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

// AlertReviewedSkip is the alert kind for a fetched reviewed ref that would
// skip unreviewed commits of a scope here.
const AlertReviewedSkip = "reviewed_ref_refused"

// alertReviewedSkip records and sends, once per scope and remote commit,
// that a fetched reviewed ref was not taken.
func (s *Syncer) alertReviewedSkip(ctx context.Context, sc model.Scope, remote model.CommitID, n int) error {
	detail := fmt.Sprintf("the fetched reviewed ref of %s skips %d commit(s) of the scope that this machine has not reviewed; it was not taken (yadm review list %s)", sc, n, model.ShellQuote(string(sc)))
	for _, a := range s.loadAlerts() {
		if a.Kind == AlertReviewedSkip && a.Commit == remote && a.Detail == detail {
			return nil
		}
	}
	a := model.Alert{Kind: AlertReviewedSkip, Commit: remote, Detail: detail, At: s.now()}
	s.notify(ctx, a)
	return s.recordAlerts([]model.Alert{a})
}

// enclavesAt lists the enclaves of the fleet file at rev.
func (s *Syncer) enclavesAt(ctx context.Context, rev model.CommitID) []model.EnclaveName {
	if rev == "" {
		return nil
	}
	snap, err := s.load(ctx, rev)
	if err != nil || snap.Fleet == nil {
		return nil
	}
	return snap.Fleet.Enclaves()
}
