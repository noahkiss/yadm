package sync

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/pause"
	"github.com/noahkiss/yadm/internal/store"
)

// PauseNetWait bounds how long PublishPause waits for the network lock.
const PauseNetWait = 15 * time.Second

// Signers returns the signers this machine trusts for pause records: the
// members of the key logs it has pinned, at rev. A source that does not
// load gives none.
func (s *Syncer) Signers(ctx context.Context, rev model.CommitID) pause.Signers {
	if rev == "" || s.Apply == nil {
		return pause.Signers{}
	}
	snap, err := s.load(ctx, rev)
	if err != nil {
		return pause.Signers{}
	}
	return pause.TrustedSigners(snap.Enclaves, s.Apply.Pins)
}

// evalPause evaluates the pause ref against the key logs at rev and keeps
// the view for publish. With save it records what it accepted; the caller
// then holds the sync lock.
func (s *Syncer) evalPause(ctx context.Context, rev model.CommitID, save bool) (pause.View, error) {
	v, err := pause.Evaluate(ctx, s.Store, s.Apply.StateDir, s.self(), s.Signers(ctx, rev), s.now(), save)
	if err != nil {
		return v, fmt.Errorf("pause: %w", err)
	}
	s.pauseView = &v
	return v, nil
}

// heldError is the refusal of a write while another machine's pause holds
// this one, or nil.
func (s *Syncer) heldError(v pause.View) error {
	if h := v.Holding(s.self()); h != nil {
		e := &pause.HeldError{Active: *h, Self: s.self()}
		if s.Fleet != nil {
			e.Name = s.Fleet.Machines[h.Initiator].Name
		}
		return e
	}
	return nil
}

// pauseFields are the status-record fields of the run's pause view.
func (s *Syncer) pauseFields() (until *time.Time, id string, ignored []model.PauseIgnored) {
	v := s.pauseView
	if v == nil {
		return nil, "", nil
	}
	a := v.Holding(s.self())
	if a == nil && len(v.Active) > 0 {
		a = &v.Active[0]
	}
	if a != nil {
		t := a.Until.UTC()
		until, id = &t, a.ID
	}
	for _, x := range v.Ignored {
		ignored = append(ignored, model.PauseIgnored{ID: x.ID, Why: x.Why})
	}
	return until, id, ignored
}

// samePause reports whether a status record already carries these fields.
func samePause(last *model.Status, until *time.Time, id string, ignored []model.PauseIgnored) bool {
	if last == nil {
		return until == nil && id == "" && len(ignored) == 0
	}
	if last.PauseID != id || (last.PausedUntil == nil) != (until == nil) {
		return false
	}
	if until != nil && !last.PausedUntil.Equal(*until) {
		return false
	}
	return slices.Equal(last.PauseIgnored, ignored)
}

// pausedRun is a sync on a machine another machine's pause holds. It has
// fetched (so it sees a resume or an extension); it captures, commits,
// replays and applies nothing, publishes its status record, which confirms
// the pause, and pushes only that ref. The caller holds the sync lock in lk.
func (s *Syncer) pausedRun(ctx context.Context, rep Report, lk *lockHold, f fetched, head model.CommitID, opts Options) (Report, error) {
	rep.Paused = true
	if rep.Captured == nil {
		rep.Captured = []model.Target{}
	}
	if rep.Committed == nil {
		rep.Committed = []model.CommitID{}
	}
	if opts.DryRun {
		return s.finish(ctx, rep, nil, nil)
	}
	if err := s.publish(ctx, head, false, 0); err != nil {
		return rep, fmt.Errorf("status: %w", err)
	}
	if f.err != nil {
		return s.finishErr(rep, nil, nil, f.err)
	}
	if !opts.Push {
		return s.finish(ctx, rep, nil, nil)
	}
	spec, err := s.statusSpec(ctx)
	if err != nil {
		return rep, err
	}
	lk.unlock()
	var specs []string
	if spec != "" {
		specs = []string{spec}
	}
	err = s.push(ctx, specs)
	switch {
	case err == nil:
		rep.Pushed = len(specs) > 0
		if !f.skipped {
			s.recordFull(ctx, nil)
		}
	case errors.Is(err, ErrNetBusy):
		rep.note("push skipped: " + err.Error())
		rep.deferred = true
	case errors.Is(err, store.ErrRejected):
		rep.note("push rejected: the next sync publishes the status record")
		rep.deferred = true
	default:
		return s.finishErr(rep, nil, nil, err)
	}
	return s.finish(ctx, rep, nil, nil)
}

// PublishPause writes recs to the pause ref and pushes it: fetch, write
// under the sync lock, push, never forced. A push the remote rejects is
// redone on the new remote head, up to 3 times. It waits up to PauseNetWait
// for the network lock; when it stays busy, the error matches ErrNetBusy,
// the record stands on the local ref and the next sync pushes it. The
// caller holds neither lock.
func (s *Syncer) PublishPause(ctx context.Context, recs []pause.Record) (pushed bool, err error) {
	onNet := func(fn func() error) error {
		deadline := s.now().Add(PauseNetWait)
		for {
			release, err := s.netLock().TryAcquire()
			if err == nil {
				defer release()
				return fn()
			}
			if !errors.Is(err, ErrNetBusy) || !s.now().Before(deadline) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	write := func() error {
		release, err := s.Lock.Acquire(ctx)
		if err != nil {
			return err
		}
		defer release()
		_, err = pause.Write(ctx, s.Store, recs, s.now())
		return err
	}
	fetchErr := onNet(func() error { return s.Store.Fetch(ctx) })
	if fetchErr != nil && !errors.Is(fetchErr, ErrNetBusy) {
		// Offline: the record still lands on the local ref; the next sync
		// pushes it.
		if err := write(); err != nil {
			return false, err
		}
		return false, fetchErr
	}
	for attempt := 0; ; attempt++ {
		if err := write(); err != nil {
			return false, err
		}
		if fetchErr != nil {
			return false, fetchErr
		}
		spec, err := pause.Spec(ctx, s.Store)
		if err != nil || spec == "" {
			return false, err
		}
		err = onNet(func() error { return s.Store.Push(ctx, []string{spec}) })
		if err == nil {
			s.trackPushedPause(ctx)
			return true, nil
		}
		if !errors.Is(err, store.ErrRejected) || attempt >= 3 {
			return false, err
		}
		if fetchErr = onNet(func() error { return s.Store.Fetch(ctx) }); fetchErr != nil {
			return false, fetchErr
		}
	}
}

// trackPushedPause moves the fetched copy of the pause ref to the local
// one after a push, in case git did not.
func (s *Syncer) trackPushedPause(ctx context.Context) {
	local, err := s.Store.ResolveRef(ctx, pause.Ref)
	if err != nil || local == "" {
		return
	}
	remote, err := s.Store.ResolveRef(ctx, pause.RemoteRef)
	if err != nil || remote == local {
		return
	}
	_ = s.Store.UpdateRef(ctx, pause.RemoteRef, local, remote)
}

// FetchRefs fetches main and refs/yadm/* under the network lock, without
// the sync lock. When another process holds the network lock, it returns
// an error that matches ErrNetBusy.
func (s *Syncer) FetchRefs(ctx context.Context) error {
	release, err := s.netLock().TryAcquire()
	if err != nil {
		return err
	}
	defer release()
	return s.Store.Fetch(ctx)
}

// EvalPause evaluates the pause ref at local main under the sync lock and
// records what it accepted. Commands that write a pause or a resume use it
// before and after the write.
func (s *Syncer) EvalPause(ctx context.Context) (pause.View, pause.Signers, error) {
	if err := s.check(); err != nil {
		return pause.View{}, nil, err
	}
	defer s.begin()()
	release, err := s.Lock.Acquire(ctx)
	if err != nil {
		return pause.View{}, nil, err
	}
	defer release()
	head, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return pause.View{}, nil, err
	}
	signers := s.Signers(ctx, head)
	v, err := pause.Evaluate(ctx, s.Store, s.Apply.StateDir, s.self(), signers, s.now(), true)
	return v, signers, err
}

// NudgePeers runs the nudge after a pause record went out, so peers sync
// now instead of on their next timer tick.
func (s *Syncer) NudgePeers(ctx context.Context) {
	head, _ := s.Store.ResolveRef(ctx, pause.Ref)
	s.nudge(ctx, head)
}
