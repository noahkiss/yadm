package sync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// Quick-check tuning. A quick sync (Options.Quick) runs a full sync only when
// it is due: the remote main or a reviewed ref moved, a target drifted, the last full sync is older
// than FullEvery, or the last check is older than WakeGap (the machine slept
// or the timer stopped).
const (
	FullEvery = 15 * time.Minute
	WakeGap   = 3 * time.Minute
	QuickFile = "quick.json"
)

// RemoteHeads is the cheap remote check. *store.Repo implements it with
// `git ls-remote`. A Store without it always runs the full sync.
type RemoteHeads interface {
	RemoteHeads(ctx context.Context) (map[string]model.CommitID, error)
}

// quickState is what the quick check remembers between runs.
type quickState struct {
	LastFull  time.Time                 `json:"last_full"`
	LastCheck time.Time                 `json:"last_check"`
	Heads     map[string]model.CommitID `json:"heads"` // remote main and refs/yadm/* after the last full sync
	Drift     map[model.Target]string   `json:"drift"` // drift the last full sync left (held, pending), by hash
	// Network backoff: consecutive failed remote checks, and the time before
	// which the quick check does not reach the remote again.
	NetFailures int       `json:"net_failures,omitempty"`
	NetRetryAt  time.Time `json:"net_retry_at,omitempty"`
}

// NetBackoffMax caps the wait between remote checks after repeated failures.
const NetBackoffMax = 15 * time.Minute

// netBackoff is the wait after n consecutive failed remote checks: 1 min,
// doubling, at most NetBackoffMax.
func netBackoff(n int) time.Duration {
	d := time.Minute
	for i := 1; i < n && d < NetBackoffMax; i++ {
		d *= 2
	}
	if d > NetBackoffMax {
		d = NetBackoffMax
	}
	return d
}

// NetBackingOff reports whether the remote failed recently and the quick
// check is still waiting before it reaches it again (`yadm status` and
// tests read it).
func NetBackingOff(stateDir string, now time.Time) bool {
	_, ok := NetBackoff(stateDir, now)
	return ok
}

// NetBackoff returns when the quick check reaches the remote again, and
// whether that is still ahead of now.
func NetBackoff(stateDir string, now time.Time) (time.Time, bool) {
	var q quickState
	if b, err := os.ReadFile(filepath.Join(stateDir, QuickFile)); err == nil {
		_ = json.Unmarshal(b, &q)
	}
	return q.NetRetryAt, now.Before(q.NetRetryAt)
}

func (s *Syncer) quickPath() string { return filepath.Join(s.Apply.StateDir, QuickFile) }

func (s *Syncer) loadQuick() quickState {
	var q quickState
	if b, err := os.ReadFile(s.quickPath()); err == nil {
		_ = json.Unmarshal(b, &q)
	}
	return q
}

// quickDue decides whether a quick sync must run in full, and says why. ""
// means nothing changed: the run stops after the check.
//
// The scan runs under the sync lock; `git ls-remote` runs under the network
// lock without it. When another process holds the network lock, the check
// stops there and notes it in rep: that process is syncing already.
func (s *Syncer) quickDue(ctx context.Context, rep *Report) (string, error) {
	now := s.now()
	q := s.loadQuick()
	defer func() {
		// Keep what a full sync recorded meanwhile; this check owns only
		// the check time and the backoff.
		cur := s.loadQuick()
		cur.LastCheck, cur.NetFailures, cur.NetRetryAt = now, q.NetFailures, q.NetRetryAt
		_ = writeJSON(s.quickPath(), cur)
	}()
	switch {
	case q.LastFull.IsZero():
		return "first run", nil
	case now.Sub(q.LastCheck) > WakeGap:
		return "wake", nil
	case now.Sub(q.LastFull) >= FullEvery:
		return "periodic", nil
	}
	release, err := s.Lock.Acquire(ctx)
	if err != nil {
		return "", err
	}
	drift, err := s.Apply.Scan(ctx, apply.ScanOptions{})
	release()
	if err != nil {
		return "", err
	}
	if !sameDrift(driftSig(drift), q.Drift) {
		return "local drift", nil
	}
	rh, ok := s.Store.(RemoteHeads)
	if !ok {
		return "no remote check", nil
	}
	if now.Before(q.NetRetryAt) {
		return "", nil // backing off: the remote refused recently
	}
	// A hook commits without pushing; the timer pushes it on its next tick.
	if local, err := s.Store.ResolveRef(ctx, store.RefMain); err == nil && local != "" {
		if remote, err := s.Store.ResolveRef(ctx, store.RemoteMain); err == nil && remote != local {
			return "unpushed commits", nil
		}
	}
	netRelease, err := s.netLock().TryAcquire()
	if err != nil {
		if errors.Is(err, ErrNetBusy) {
			rep.note("check skipped: " + err.Error())
			return "", nil
		}
		return "", err
	}
	heads, err := rh.RemoteHeads(ctx)
	netRelease()
	if err != nil {
		// Back off instead of a full sync that would reach the same remote
		// again. The wake and periodic paths above still run the full sync,
		// which reports the network error.
		q.NetFailures++
		q.NetRetryAt = now.Add(netBackoff(q.NetFailures))
		return "", nil
	}
	q.NetFailures, q.NetRetryAt = 0, time.Time{}
	if !sameHeads(heads, q.Heads, s.self()) {
		return "remote moved", nil
	}
	return "", nil
}

// sameHeads compares two ls-remote views on the refs that change what a
// machine applies or reviews: main and the reviewed refs. Status refs move
// on every peer's sync; the periodic full sync fetches them.
func sameHeads(a, b map[string]model.CommitID, _ model.MachineID) bool {
	pick := func(m map[string]model.CommitID) map[string]model.CommitID {
		out := map[string]model.CommitID{}
		for k, v := range m {
			if k == store.RefMain || strings.HasPrefix(k, "refs/yadm/reviewed/") {
				out[k] = v
			}
		}
		return out
	}
	x, y := pick(a), pick(b)
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}

// driftSig is the drift a quick check compares: each target with its kind
// and hash. Files that predate their owned root never count; they stay
// until committed by name.
func driftSig(drift []apply.Drift) map[model.Target]string {
	out := map[model.Target]string{}
	for _, d := range drift {
		if d.Baseline {
			continue
		}
		out[d.Target] = string(d.Kind) + ":" + d.Hash
	}
	return out
}

func sameDrift(a, b map[model.Target]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// leftDrift scans what a full sync leaves behind (held or pending targets)
// for recordFull. The caller holds the sync lock. nil means the scan failed.
func (s *Syncer) leftDrift(ctx context.Context) map[model.Target]string {
	drift, err := s.Apply.Scan(ctx, apply.ScanOptions{})
	if err != nil {
		return nil
	}
	return driftSig(drift)
}

// recordFull remembers a finished full sync, the remote heads it left (read
// from the remote-tracking refs it fetched and pushed) and the drift it
// left behind, so an unchanged leftover does not count as new drift. Only
// a push that went out (or had nothing to send) records one: a skipped or
// rejected push leaves local main ahead, and the next quick check runs in
// full.
func (s *Syncer) recordFull(ctx context.Context, left map[model.Target]string) {
	q := s.loadQuick()
	if left != nil {
		q.Drift = left
	}
	q.LastFull, q.LastCheck = s.now(), s.now()
	q.NetFailures, q.NetRetryAt = 0, time.Time{} // the remote answered
	q.Heads = map[string]model.CommitID{}
	if id, err := s.Store.ResolveRef(ctx, store.RemoteMain); err == nil && id != "" {
		q.Heads[store.RefMain] = id
	}
	if refs, err := s.Store.ListRefs(ctx, remoteYadmPrefix); err == nil {
		for name, id := range refs {
			q.Heads["refs/yadm/"+strings.TrimPrefix(name, remoteYadmPrefix)] = id
		}
	}
	_ = writeJSON(s.quickPath(), q)
}

// writeJSON writes v to p atomically, mode 0600. The temp file has its own
// name, so writers outside the sync lock never interleave in it.
func writeJSON(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, p)
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}
