package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
)

// Defaults.
const (
	DefaultQuiet      = 2 * time.Minute
	DefaultMaxRetries = 5
	DefaultMassChange = 50 // more changed files than this in one scope are held
	LockFile          = "lock"
	LeaseDir          = "leases"
	AlertsFile        = "alerts.json"
	maxAlerts         = 20
)

// ErrLocked means another sync holds the lock.
var ErrLocked = errors.New("another yadm process holds the lock")

// Options tunes one sync.
type Options struct {
	Auto       bool // timer run: auto-commit by policy; otherwise commit nothing
	Push       bool
	DryRun     bool // scan, capture and plan; commit, fetch, apply and push nothing
	MaxRetries int  // push retries; 0 means DefaultMaxRetries
	// Quick first runs the cheap check (scan, `git ls-remote`) and stops
	// there when nothing moved and no full sync is due (FullEvery, WakeGap).
	Quick bool
}

// Report is the outcome of one sync.
type Report struct {
	Captured    []model.Target     `json:"captured"`
	Pending     []model.Target     `json:"pending,omitempty"` // captured, not committed yet (quiet period, lease, busy)
	Committed   []model.CommitID   `json:"committed"`
	Fetched     model.CommitID     `json:"fetched"`
	Replayed    int                `json:"replayed"`
	Applied     model.CommitID     `json:"applied"`
	Pushed      bool               `json:"pushed"`
	Retries     int                `json:"retries"`
	Holds       []model.Hold       `json:"holds"`
	Alerts      []Alert            `json:"alerts,omitempty"`
	Tasks       []model.TaskResult `json:"tasks,omitempty"`
	Resolutions []Resolution       `json:"resolutions,omitempty"`
	Skipped     bool               `json:"skipped,omitempty"` // a quick sync found nothing to do
	Reason      string             `json:"reason,omitempty"`  // why a quick sync ran in full
}

// Alert is an event sent through the notify hook and kept in the status record.
type Alert = model.Alert

// Lock is the exclusive sync lock.
type Lock interface {
	Acquire(ctx context.Context) (release func(), err error)
}

// Lease marks paths an agent session is editing; auto-commit skips them.
type Lease struct {
	Holder  string    `json:"holder"`
	Paths   []string  `json:"paths"` // globs relative to $HOME
	Expires time.Time `json:"expires"`
}

// Leases stores leases in the state directory.
type Leases interface {
	List() ([]Lease, error)
	Take(Lease) error
	Release(holder string) error
}

// Policy is the auto-commit policy. Run fills the hooks from the manifest
// when they are nil.
type Policy struct {
	Quiet      time.Duration
	MassChange int
	Protected  []string // extra never-auto-commit globs; manifest.BuiltinProtected always applies

	Host        string                                   // display name in commit subjects; default the machine id
	QuietFor    func(model.Target) (time.Duration, bool) // per-entry quiet period
	Protect     func(model.Target) bool                  // manifest `protected` globs and `review = true`
	LastChange  func(model.Target) time.Time             // the target's last change (its mtime)
	MergeFor    func(model.Target) MergePolicy           // per-file merge policy; "" means MergeText
	VolatileFor func(model.Target) []string              // key paths resolved locally, never merged from the remote
}

// PlannedCommit is one auto-commit to make. Targets[i] is the target of Changes[i].
type PlannedCommit struct {
	Scope   model.Scope
	Changes []store.Change
	Targets []model.Target
	Message store.Message
	Info    MessageInfo // rebuilds Message when only some targets land

	direct []bool // direct[i]: Changes[i] is not a target (a key-log entry)
}

// Deps are the collaborators a Syncer needs.
type Deps struct {
	Store    store.Store
	Apply    *apply.Engine
	Fleet    *fleet.File // fallback when the source has no fleet file
	Status   fleet.StatusRefs
	Keys     *crypt.Set
	Exec     extexec.Runner
	Identity fleet.Identity
	Gate     tasks.Gate // nil: built per sync from the plan's checks and the allow list
	Lock     Lock
	Leases   Leases
	Policy   Policy
	Version  string
	Now      func() time.Time

	Structural Structural    // key-level merge for json, jsonc and toml; nil decides nothing
	Guard      RemoteGuard   // refuses a fetched source this machine has not allowed; nil allows all
	Backoff    time.Duration // first push-retry delay; doubles per retry; default 200ms

	// Nudge is an optional extexec argv run after a push that moved main,
	// so peers sync now instead of on their next timer tick (they run
	// `yadm sync --quick`). Its failure never fails the sync.
	Nudge []string
}

// Syncer runs the sync loop.
type Syncer struct {
	Deps
	snaps map[model.CommitID]*apply.Snapshot // per-run cache of loaded snapshots
}

// load returns the snapshot of a commit id, loading each commit once per run.
func (s *Syncer) load(ctx context.Context, rev model.CommitID) (*apply.Snapshot, error) {
	if snap, ok := s.snaps[rev]; ok {
		return snap, nil
	}
	snap, err := s.Apply.Load(ctx, rev)
	if err != nil {
		return nil, err
	}
	if s.snaps == nil {
		s.snaps = map[model.CommitID]*apply.Snapshot{}
	}
	s.snaps[rev] = snap
	return snap, nil
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) self() model.MachineID { return s.Identity.Machine }

// check refuses a Syncer that is not wired.
func (s *Syncer) check() error {
	switch {
	case s.Store == nil:
		return errors.New("sync: no store")
	case s.Apply == nil || s.Apply.State == nil:
		return errors.New("sync: no apply engine")
	case s.self() == "":
		return errors.New("sync: no machine identity")
	case s.Apply.Self != "" && s.Apply.Self != s.self():
		return fmt.Errorf("sync: identity %s and apply engine %s disagree", s.self(), s.Apply.Self)
	case s.Lock == nil:
		return errors.New("sync: no lock")
	}
	return nil
}

// CommitOptions tunes a manual commit.
type CommitOptions struct {
	Message string         // subject; empty builds `<verb> <path>` from the paths
	Paths   []model.Target // empty means every captured, unheld, unprotected path
	DryRun  bool
	// Capture, when set, commits these changes as they are (for example a
	// retag) instead of scanning. They still pass the gate.
	Capture *apply.Capture
	// Changes are source changes that are not targets, such as key-log
	// entries and a retag's manifest edit. They commit in ChangesScope
	// (default shared) against the current source. The gate does not see
	// them: its paths name targets, and these hold no plaintext.
	Changes      []store.Change
	ChangesScope model.Scope

	Trigger string // Yadm-Auto trailer: TriggerManual (default), TriggerHook or TriggerStop
	Session string // Yadm-Session trailer, the harness session id
	Tool    string // Yadm-Tool trailer, the tool that made the edit

	// Unattended commits for an agent hook: naming a path does not lift its
	// protection, and a new file in an owned root is held for a decision.
	Unattended bool
	// Resolve settles the conflict holds of the named paths: they commit over
	// the current source blob and the hold is dropped.
	Resolve bool
	// Push fetches, replays, applies, publishes and pushes after the commit,
	// under the same lock.
	Push       bool
	MaxRetries int
}

// LockTimeout bounds how long any command waits for the lock before failing
// with ErrLocked. Commands never wait without a bound.
const LockTimeout = 30 * time.Second

// Run performs one sync (design §10).
func (s *Syncer) Run(ctx context.Context, opts Options) (Report, error) {
	var rep Report
	if err := s.check(); err != nil {
		return rep, err
	}
	release, err := s.Lock.Acquire(ctx)
	if err != nil {
		return rep, err
	}
	defer release()
	s.snaps = nil
	defer func() { s.snaps = nil }()

	if opts.Quick && !opts.DryRun {
		why, err := s.quickDue(ctx)
		if err != nil {
			return rep, err
		}
		if why == "" {
			rep.Skipped = true
			rep.Captured, rep.Committed = []model.Target{}, []model.CommitID{}
			return s.finish(ctx, rep, nil, nil)
		}
		rep.Reason = why
	}

	start, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return rep, err
	}

	// 1. Scan and capture.
	drift, err := s.Apply.Scan(ctx, apply.ScanOptions{})
	if err != nil {
		return rep, fmt.Errorf("scan: %w", err)
	}
	cp, err := s.Apply.Capture(ctx, drift)
	if err != nil {
		return rep, fmt.Errorf("capture: %w", err)
	}
	rep.Captured = cp.Paths
	if !opts.DryRun {
		if err := s.holdBaseline(drift, cp); err != nil {
			return rep, err
		}
		// A hold whose target is back at its source settles by itself.
		if _, err := s.Apply.SettleHolds(ctx, drift); err != nil {
			return rep, err
		}
	}

	// 2. Auto-commit by policy.
	committed := map[model.Target]bool{}
	if opts.Auto && len(cp.Paths) > 0 {
		st, err := s.Apply.State.Load()
		if err != nil {
			return rep, err
		}
		snap, err := s.snapshotAt(ctx, st.Applied, start)
		if err != nil {
			return rep, err
		}
		pol := s.policyFor(snap)
		leases, err := s.leases(ctx, snap, start)
		if err != nil {
			return rep, err
		}
		planned, holds, err := PlanCommits(cp, st, pol, leases, s.self(), s.now())
		if err != nil {
			return rep, err
		}
		evaluated := map[model.Target]bool{}
		for _, t := range cp.Paths {
			evaluated[t] = true
		}
		dropSyncHolds(st, func(t model.Target) bool { return evaluated[t] })
		for _, h := range holds {
			putHold(st, h)
		}
		if opts.DryRun {
			for _, pc := range planned {
				for _, t := range pc.Targets {
					committed[t] = true
				}
			}
			rep.Pending = pending(cp.Paths, committed, st)
			rep.Holds = reportHolds(st, rep.Pending)
			return rep, nil
		}
		if err := s.Apply.State.Save(st); err != nil {
			return rep, err
		}
		out, err := s.commit(ctx, &rep, snap, planned, drift, nil)
		if err != nil {
			return rep, err
		}
		rep.Committed = out.ids
		rep.Resolutions = append(rep.Resolutions, out.resolutions...)
		for t := range out.committed {
			committed[t] = true
		}
		if out.dirty {
			return s.finish(ctx, rep, cp.Paths, committed)
		}
	} else if opts.DryRun {
		st, err := s.Apply.State.Load()
		if err != nil {
			return rep, err
		}
		rep.Pending = pending(cp.Paths, committed, st)
		rep.Holds = reportHolds(st, rep.Pending)
		return rep, nil
	}

	return s.exchange(ctx, rep, start, cp.Paths, committed, opts)
}

// exchange runs steps 3 to 9 under the lock the caller holds: collectors,
// fetch, replay, apply, publish and push, retrying a lost push race. Run and
// Commit (with CommitOptions.Push) both end here, so a commit reaches the
// remote in the same call.
func (s *Syncer) exchange(ctx context.Context, rep Report, start model.CommitID, captured []model.Target, committed map[model.Target]bool, opts Options) (Report, error) {
	// 3. Collectors.
	head, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return rep, err
	}
	if err := s.collect(ctx, head); err != nil {
		return rep, err
	}

	// 4-9. Fetch, replay, apply, publish, push; retry on a lost push race.
	maxRetries := opts.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	seen := map[model.CommitID]bool{}
	var publishedTip model.CommitID
	published := false
	for attempt := 0; ; attempt++ {
		base := s.accepted()
		if base == "" {
			// First sync: the clone's own fetch is the trusted start.
			if base, err = s.Store.ResolveRef(ctx, store.RemoteMain); err != nil {
				return rep, err
			}
		}
		if err := s.Store.Fetch(ctx); err != nil {
			// A network that returns late: the next run catches up once.
			rep.Holds = s.currentHolds(captured, committed)
			return rep, err
		}
		local, err := s.Store.ResolveRef(ctx, store.RefMain)
		if err != nil {
			return rep, err
		}
		remote, err := s.Store.ResolveRef(ctx, store.RemoteMain)
		if err != nil {
			return rep, err
		}
		rep.Fetched = remote
		res, err := s.integrateAndApply(ctx, &rep, base, local, remote, seen)
		if err != nil {
			return rep, err
		}
		tip := res.tip
		rep.Alerts = append(rep.Alerts, res.alerts...)
		if res.dirty {
			return s.finish(ctx, rep, captured, committed)
		}

		// 8. Status record.
		changed := tip != start || len(rep.Committed) > 0 || len(rep.Alerts) > 0
		if !published || tip != publishedTip {
			if err := s.publish(ctx, tip, changed || published, len(pending(captured, committed, nil))); err != nil {
				return rep, fmt.Errorf("status: %w", err)
			}
			published, publishedTip = true, tip
		}
		rep.Applied = tip

		// 9. Push main, the status ref and the reviewed refs atomically.
		if !opts.Push {
			break
		}
		pushTip := tip
		if res.refused {
			pushTip = "" // never push over a refused remote; status still goes out
		}
		specs, err := s.pushSpecs(ctx, pushTip, remote)
		if err != nil {
			return rep, err
		}
		err = s.Store.Push(ctx, specs)
		if err == nil {
			rep.Pushed = len(specs) > 0
			if pushTip != "" && pushTip != remote {
				s.nudge(ctx, pushTip)
			}
			break
		}
		if !errors.Is(err, store.ErrRejected) || attempt >= maxRetries {
			return s.finishErr(rep, captured, committed, err)
		}
		rep.Retries++
		if err := s.backoff(ctx, attempt); err != nil {
			return rep, err
		}
	}
	if opts.Push {
		s.recordFull(ctx)
	}
	return s.finish(ctx, rep, captured, committed)
}

// stepResult is the outcome of steps 5 to 7.
type stepResult struct {
	tip     model.CommitID
	alerts  []model.Alert
	dirty   bool // stopped with a source_dirty hold
	refused bool // the fetched source was refused; local main was kept
}

// integrateAndApply runs steps 5 to 7: check the fetched source, replay,
// compare-and-swap main, move the worktree, then apply. base is the remote
// main before this fetch.
func (s *Syncer) integrateAndApply(ctx context.Context, rep *Report, base, local, remote model.CommitID, seen map[model.CommitID]bool) (stepResult, error) {
	var out stepResult
	st, err := s.Apply.State.Load()
	if err != nil {
		return out, err
	}
	// The key-log rule runs even when the fetched source does not load: a
	// key-log entry anyone pushed in a form that does not parse must refuse
	// that source with a hold and an alert, not stop every machine's sync.
	var snap *apply.Snapshot
	var loadErr error
	if remote != "" {
		snap, loadErr = s.load(ctx, remote)
	}
	ref, err := s.checkRemote(ctx, base, local, remote, snap)
	if err != nil {
		return out, err
	}
	if ref == nil && loadErr != nil {
		return out, fmt.Errorf("load %s: %w", remote, loadErr)
	}
	fresh, err := s.setRefusal(ref)
	if err != nil {
		return out, err
	}
	if ref != nil {
		out.refused = true
		if fresh {
			a := model.Alert{Kind: ref.kind, Commit: remote, Detail: ref.detail, At: s.now()}
			s.notify(ctx, a)
			if err := s.recordAlerts([]model.Alert{a}); err != nil {
				return out, err
			}
			out.alerts = append(out.alerts, a)
		}
		out.tip = local
		if local != "" && local != st.Applied {
			out.dirty, err = s.moveAndApply(ctx, rep, local)
		}
		return out, err
	}
	if err := s.setAccepted(remote); err != nil {
		return out, err
	}
	alerts, err := s.nonMemberAlerts(ctx, snap, local, remote, seen)
	if err != nil {
		return out, err
	}
	for _, a := range alerts {
		s.notify(ctx, a)
	}
	if err := s.recordAlerts(alerts); err != nil {
		return out, err
	}
	out.alerts = alerts
	r := &resolver{s: s, snap: snap, st: st}
	in, err := s.integrate(ctx, r, local, remote)
	if err != nil {
		return out, err
	}
	rep.Replayed += in.replayed
	rep.Resolutions = append(rep.Resolutions, in.resolutions...)
	if len(in.holds) > 0 {
		// Reload: integrate may not touch state, but stay on the latest copy.
		if st, err = s.Apply.State.Load(); err != nil {
			return out, err
		}
		for _, h := range in.holds {
			putHold(st, h)
			// Apply must not overwrite this machine's side of a conflict.
			if ts, ok := st.Targets[h.Target]; ok {
				ts.Written = ""
				st.Targets[h.Target] = ts
			}
		}
		if err := s.Apply.State.Save(st); err != nil {
			return out, err
		}
		for _, h := range in.holds {
			s.notify(ctx, model.Alert{Kind: "held", Detail: "conflict on " + string(h.Target) + " (" + string(h.Scope) + ")", At: s.now()})
		}
	}
	if in.tip == "" {
		return out, nil
	}
	if in.tip != local {
		if err := s.setMain(ctx, in.tip, local); err != nil {
			return out, err
		}
	}
	out.tip = in.tip
	out.dirty, err = s.moveAndApply(ctx, rep, in.tip)
	return out, err
}

// setMain compare-and-swaps main from old to tip. When main is unborn (a
// clone of a remote that was empty), the worktree moves to tip first: the
// store measures local edits against HEAD, and once main exists HEAD names
// it, so an empty index would read as every file staged for deletion. A
// worktree that does not move here is left to moveAndApply, which holds it.
func (s *Syncer) setMain(ctx context.Context, tip, old model.CommitID) error {
	if old == "" {
		if err := s.Store.SyncWorktree(ctx, tip); err != nil && !errors.Is(err, store.ErrDirty) {
			return err
		}
	}
	return s.Store.UpdateRef(ctx, store.RefMain, tip, old)
}

// moveAndApply moves the source worktree to tip and applies it. A worktree
// with local edits stops the sync with a source_dirty hold; nothing is stashed.
func (s *Syncer) moveAndApply(ctx context.Context, rep *Report, tip model.CommitID) (bool, error) {
	if err := s.Store.SyncWorktree(ctx, tip); err != nil {
		if !errors.Is(err, store.ErrDirty) {
			return false, err
		}
		st, lerr := s.Apply.State.Load()
		if lerr != nil {
			return false, lerr
		}
		h := model.KeepSince(st.Holds, model.Hold{Scope: model.ScopeShared, Reason: model.HoldSourceDirty,
			Detail: "the source clone has local edits: " + err.Error()}, s.now())
		h.Next = []string{"yadm git status", "yadm git restore ."}
		putHold(st, h)
		return true, s.Apply.State.Save(st)
	}
	if err := s.clearSourceDirty(); err != nil {
		return false, err
	}
	if err := s.guardConflicts(); err != nil {
		return false, err
	}
	res, err := s.Apply.Apply(ctx, tip, apply.ApplyOptions{})
	if err != nil {
		return false, fmt.Errorf("apply: %w", err)
	}
	rep.Applied = tip
	rep.Tasks = append(rep.Tasks, res.Tasks...)
	for _, t := range res.Tasks {
		if t.ExitCode != 0 || t.Error != "" {
			s.notify(ctx, model.Alert{Kind: "task_failed", Commit: tip, Detail: "task " + t.Task + " failed", At: s.now()})
		}
	}
	return false, nil
}

// guardConflicts clears the last-written hash of every target with an open
// conflict hold, so apply holds this machine's side instead of overwriting
// it. Capture may have refreshed the hash since the hold was raised.
func (s *Syncer) guardConflicts() error {
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	changed := false
	for _, h := range st.Holds {
		if h.Reason != model.HoldConflict || h.Target == "" {
			continue
		}
		if ts, ok := st.Targets[h.Target]; ok && ts.Written != "" {
			ts.Written = ""
			st.Targets[h.Target] = ts
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.Apply.State.Save(st)
}

func (s *Syncer) clearSourceDirty() error {
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	n := len(st.Holds)
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Reason != model.HoldSourceDirty {
			out = append(out, h)
		}
	}
	st.Holds = out
	if len(out) == n {
		return nil
	}
	return s.Apply.State.Save(st)
}

func (s *Syncer) backoff(ctx context.Context, attempt int) error {
	d := s.Backoff
	if d <= 0 {
		d = 200 * time.Millisecond
	}
	for i := 0; i < attempt && d < 5*time.Second; i++ {
		d *= 2
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// pushSpecs lists what to push: main when it moved past the remote, this
// machine's status ref, reviewed refs this machine advanced, and the review
// notes ref when it holds notes the remote lacks. A reviewed
// ref the remote advanced further is fast-forwarded locally instead.
func (s *Syncer) pushSpecs(ctx context.Context, tip, remote model.CommitID) ([]string, error) {
	var specs []string
	if tip != "" && tip != remote {
		specs = append(specs, store.RefMain+":"+store.RefMain)
	}
	sref := fleet.StatusRef(s.self())
	local, err := s.Store.ResolveRef(ctx, sref)
	if err != nil {
		return nil, err
	}
	pushed, err := s.Store.ResolveRef(ctx, "refs/remotes/origin/yadm/status/"+string(s.self()))
	if err != nil {
		return nil, err
	}
	if local != "" && local != pushed {
		specs = append(specs, sref+":"+sref)
	}
	more, err := s.reviewedSpecs(ctx)
	if err != nil {
		return nil, err
	}
	if ns, err := notesSpec(ctx, s.Store); err != nil {
		return nil, err
	} else if ns != "" {
		more = append(more, ns)
	}
	return append(specs, more...), nil
}

// finish fills the holds of a report.
func (s *Syncer) finish(_ context.Context, rep Report, captured []model.Target, committed map[model.Target]bool) (Report, error) {
	rep.Holds = s.currentHolds(captured, committed)
	rep.Pending = pending(captured, committed, nil)
	return rep, nil
}

func (s *Syncer) finishErr(rep Report, captured []model.Target, committed map[model.Target]bool, err error) (Report, error) {
	rep.Holds = s.currentHolds(captured, committed)
	return rep, err
}

func (s *Syncer) currentHolds(captured []model.Target, committed map[model.Target]bool) []model.Hold {
	st, err := s.Apply.State.Load()
	if err != nil {
		return nil
	}
	return reportHolds(st, pending(captured, committed, st))
}

// pending lists captured targets that were not committed and carry no hold.
func pending(captured []model.Target, committed map[model.Target]bool, st *apply.State) []model.Target {
	var out []model.Target
	for _, t := range captured {
		if committed[t] {
			continue
		}
		if st != nil && hasHold(st, t, model.HoldProtected, model.HoldCheckFailed, model.HoldTaskUntrusted, model.HoldConflict) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// reportHolds returns the state's holds without the drifted holds apply puts
// on pending targets: a pending edit is not a problem, only not yet committed.
func reportHolds(st *apply.State, pend []model.Target) []model.Hold {
	skip := map[model.Target]bool{}
	for _, t := range pend {
		skip[t] = true
	}
	for _, h := range st.Holds {
		if h.Reason == model.HoldConflict && h.Target != "" {
			skip[h.Target] = true // the conflict hold says it all
		}
	}
	out := []model.Hold{}
	for _, h := range st.Holds {
		if h.Reason == model.HoldDrifted && skip[h.Target] {
			continue
		}
		out = append(out, h)
	}
	return out
}

// snapshotAt loads the snapshot capture used: the applied commit, else rev.
func (s *Syncer) snapshotAt(ctx context.Context, applied, rev model.CommitID) (*apply.Snapshot, error) {
	if applied == "" {
		applied = rev
	}
	if applied == "" {
		return nil, nil
	}
	return s.load(ctx, applied)
}

// policyFor fills the policy hooks from the manifest of snap.
func (s *Syncer) policyFor(snap *apply.Snapshot) Policy {
	p := s.Policy
	if p.Quiet <= 0 {
		p.Quiet = DefaultQuiet
	}
	if snap == nil {
		return p
	}
	if p.Host == "" {
		p.Host = snap.Context.Machine.Name
	}
	if p.QuietFor == nil && snap.Manifest != nil && snap.Plan != nil {
		p.QuietFor = func(t model.Target) (time.Duration, bool) {
			r, ok := snap.Plan.Targets[t]
			if !ok {
				return 0, false
			}
			return snap.Manifest.Quiet(r.Entry).D(), true
		}
	}
	if p.Protect == nil && snap.Plan != nil {
		p.Protect = snap.Plan.Protected
	}
	if p.LastChange == nil && s.Apply.Home != "" {
		home := s.Apply.Home
		p.LastChange = func(t model.Target) time.Time {
			info, err := os.Lstat(filepath.Join(home, filepath.FromSlash(string(t))))
			if err != nil {
				return time.Time{}
			}
			return info.ModTime()
		}
	}
	return p
}

// leases returns the stored leases plus the busy probe's answer as one lease.
func (s *Syncer) leases(ctx context.Context, snap *apply.Snapshot, head model.CommitID) ([]Lease, error) {
	var out []Lease
	if s.Leases != nil {
		ls, err := s.Leases.List()
		if err != nil {
			return nil, err
		}
		out = ls
	}
	if len(s.Identity.Busy) > 0 && s.Exec != nil {
		req := s.request(snap, head)
		req.Kind = extexec.KindBusy
		req.Name = "busy"
		res, err := s.Exec.Run(ctx, extexec.Spec{Argv: s.Identity.Busy, Timeout: 10 * time.Second}, req)
		if err == nil && len(res.Items) > 0 {
			out = append(out, Lease{Holder: "busy-probe", Paths: res.Items, Expires: s.now().Add(time.Minute)})
		}
	}
	return out, nil
}

func (s *Syncer) request(snap *apply.Snapshot, commit model.CommitID) extexec.Request {
	req := extexec.Request{Schema: extexec.Schema, Source: s.Store.Dir(), Commit: commit, Home: s.Apply.Home}
	if snap != nil {
		req.Machine = snap.Context.Machine
	}
	return req
}

// notify sends an alert through the notify hook. A failing hook never fails
// the sync.
func (s *Syncer) notify(ctx context.Context, a model.Alert) {
	if len(s.Identity.Notify) == 0 || s.Exec == nil {
		return
	}
	req := extexec.Request{Schema: extexec.Schema, Kind: extexec.KindNotify, Name: a.Kind, Home: s.Apply.Home, Source: s.Store.Dir(),
		Commit: a.Commit, Event: map[string]any{"kind": a.Kind, "commit": string(a.Commit), "machine": string(a.Machine), "detail": a.Detail}}
	_, _ = s.Exec.Run(ctx, extexec.Spec{Argv: s.Identity.Notify, Timeout: 10 * time.Second}, req)
}

// nudge runs the Nudge argv after a push that moved main. A failing nudge
// never fails the sync.
func (s *Syncer) nudge(ctx context.Context, tip model.CommitID) {
	if len(s.Nudge) == 0 || s.Exec == nil {
		return
	}
	req := extexec.Request{Schema: extexec.Schema, Kind: extexec.KindNudge, Name: "pushed", Home: s.Apply.Home, Source: s.Store.Dir(),
		Commit: tip, Event: map[string]any{"kind": "pushed", "commit": string(tip), "machine": string(s.self())}}
	_, _ = s.Exec.Run(ctx, extexec.Spec{Argv: s.Nudge, Timeout: 10 * time.Second}, req)
}

// sortedEnclaves returns the keys of m in order.
func sortedEnclaves(m map[model.EnclaveName]bool) []model.EnclaveName {
	out := make([]model.EnclaveName, 0, len(m))
	for e := range m {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
