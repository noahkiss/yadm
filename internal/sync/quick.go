package sync

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// Quick-check tuning. A quick sync (Options.Quick) runs a full sync only when
// it is due: the remote moved, a target drifted, the last full sync is older
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
func (s *Syncer) quickDue(ctx context.Context) (string, error) {
	now := s.now()
	q := s.loadQuick()
	defer func() {
		q.LastCheck = now
		_ = writeJSON(s.quickPath(), q)
	}()
	switch {
	case q.LastFull.IsZero():
		return "first run", nil
	case now.Sub(q.LastCheck) > WakeGap:
		return "wake", nil
	case now.Sub(q.LastFull) >= FullEvery:
		return "periodic", nil
	}
	drift, err := s.Apply.Scan(ctx, apply.ScanOptions{})
	if err != nil {
		return "", err
	}
	if len(drift) > 0 {
		return "local drift", nil
	}
	rh, ok := s.Store.(RemoteHeads)
	if !ok {
		return "no remote check", nil
	}
	heads, err := rh.RemoteHeads(ctx)
	if err != nil {
		return "remote check failed", nil // the full sync reports the network
	}
	if !sameHeads(heads, q.Heads, s.self()) {
		return "remote moved", nil
	}
	return "", nil
}

// sameHeads compares two ls-remote views, ignoring this machine's own status
// ref (its own pushes must not wake it).
func sameHeads(a, b map[string]model.CommitID, self model.MachineID) bool {
	own := "refs/yadm/status/" + string(self)
	n := 0
	for k, v := range a {
		if k == own {
			continue
		}
		if b[k] != v {
			return false
		}
		n++
	}
	m := 0
	for k := range b {
		if k != own {
			m++
		}
	}
	return n == m
}

// recordFull remembers a finished full sync and the remote heads it left,
// read from the remote-tracking refs it fetched and pushed.
func (s *Syncer) recordFull(ctx context.Context) {
	q := s.loadQuick()
	q.LastFull, q.LastCheck = s.now(), s.now()
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
