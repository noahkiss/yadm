// Package sync runs the sync loop, mechanical auto-commit, agent leases and
// the review queue.
//
// Two locks in the state directory serialize one machine's processes. The
// sync lock (LockFile; Acquire waits at most its bound, then ErrLocked)
// covers local writes. A holder named by extexec.EnvParentPID is the yadm
// process that runs this one as a task or check: Acquire fails at once with
// ErrSelfLocked instead of waiting on it. The network lock (NetLockFile) covers fetch, push
// and ls-remote; it is only ever tried (TryAcquire), and a caller that
// finds it held skips its network step (ErrNetBusy) and says so in
// Report.Network. No process holds the sync lock while it waits on the
// network. Each lock file holds its holder's record (pid, command, start);
// a LockedError names it, and HeldLocks reads both without locking.
//
// One sync runs in three phases: step 4 under the network lock; steps 1 to
// 3 and 5 to 7 under the sync lock; step 8 under the network lock after the
// sync lock is released.
//
//  1. Scan and capture drift (package apply). Unreadable drift never commits.
//     A target with a deferred decision (Deps.Deferred) and an open hold is
//     not captured; only an attended Commit that names it captures it.
//  2. With Options.Auto, auto-commit captured paths whose quiet period has
//     passed, that no lease or busy probe names, that hold no open conflict
//     and that are not protected (built-in and manifest globs, review
//     entries, deletions, new files that predate their owned root, and every
//     path of a scope over the mass-change limit). Generated files never
//     auto-commit. The commit gate (tasks.Gate) holds failures; other files
//     still commit. One commit per scope through store.CommitPaths, a fresh
//     private index each. Each commit carries `Machine:`, `Yadm-Auto: 1` and
//     `Yadm-Scope:`. A change captured against a source blob main has since
//     moved past is merged first, so a commit never reverts what it did not
//     see. Main moves by compare-and-swap and apply records the targets.
//     A deletion commits only when named (Commit); its commit also drops
//     the target's own [[file]] entry (apply.Engine.DropEntries).
//     CommitOptions.Forget makes this machine stop managing the named
//     targets (apply.Forget) once the commit lands, so its apply keeps them.
//  3. Run allowed collectors (fleet.CollectWith, with source and commit).
//  4. Fetch origin main and refs/yadm/* (first, before step 1). The guard's
//     base is the accepted remote main recorded in AcceptedFile; only an
//     accepted source moves it. With no record, the fetch first records the
//     origin main its clone holds (SeedAccepted; init records it at clone).
//     A failed fetch still lets steps 1 to 3 run; the sync then ends with
//     the fetch error. A fetched source that rewrites or
//     deletes a key-log entry, or that the RemoteGuard refuses, is not taken:
//     a hold and one alert, local main stays, main is not pushed. It stays
//     refused on every later sync until the remote drops it or an allow
//     names it. A PathGuard (apply.Guard) names each weakening instead:
//     when all are targets, the source is taken, and each weakened target
//     is a held path. Its floor is recorded (apply.Engine.HoldBack) before
//     the accepted remote moves, one AlertPathHeld names it, and apply keeps
//     the target as it is until allowed or restored. A weakened owned root
//     still refuses the whole source.
//  5. If local main is not an ancestor of origin main, replay each local
//     commit onto origin main with `git merge-tree`, in memory. Conflicted
//     paths go up the resolution ladder: a key-level merge for json, jsonc
//     and toml (Structural), then the file's merge policy (text, union,
//     add-only, ours, theirs, generated), then a conflict hold with all three
//     stage blobs and the commit kept on the local-only held ref. Sealed files
//     are opened, merged and resealed in memory. Clean paths still land,
//     except in a commit that changes manifest.toml: it lands whole or not. Each
//     resolution is recorded in a `Yadm-Resolved:` trailer. History stays
//     linear. There is no autostash and no merge commit.
//  6. Compare-and-swap local main, move the source worktree (a dirty worktree
//     stops with a source_dirty hold), apply. Main moves only after
//     store.CheckWorktree passes, so the clone's index never falls behind
//     HEAD; a commit over a dirty clone makes nothing.
//  7. Publish the status record to this machine's status ref: holds (count,
//     conflicts, oldest, count per model.HoldKind), tasks, published facts,
//     alerts, the pinned key-log head of each enclave, and this machine's
//     home and user (read only by show --as). A change to the holds the
//     record shows publishes at once, not only hourly.
//  8. Release the sync lock; push main, the status ref and advanced
//     reviewed refs atomically under the network lock. A rejection is not
//     an error: go back to 4 (fetch, then 5 to 7 under the sync lock again),
//     up to MaxRetries rounds with backoff (negative: none), then leave it to
//     the next sync. Only a run that fetched and whose push went out records
//     a full sync for the quick check, so unpushed commits trigger the next
//     one. Never force (the one forced push is Reroot's, below).
//     A fetched reviewed ref moves the local one only when it skips no
//     commit of its scope; otherwise it is refused with an alert
//     (AlertReviewedSkip). SeedReviewed seeds empty local refs at init.
//
// A quick sync (Options.Quick) first stats the targets and lists the remote
// heads with `git ls-remote`; it stops there unless the remote moved, a
// target drifted, FullEvery passed since the last full sync, or WakeGap
// passed since the last check; the scan runs under the sync lock and
// ls-remote under the network lock. Commit with Push runs the same phases
// around its commit: fetch, then the commit and steps 3 and 5 to 7 under the
// sync lock, then the push; a push left to the next sync is an ExchangeError
// wrapping ErrPushDeferred. After a push that moved main,
// Deps.Nudge runs so peers can sync now.
//
// A fleet pause (package pause) another machine started holds this one:
// after the fetch, Run evaluates the pause ref against the fleet.toml
// machines and the pinned key logs at local main, and, when held, only
// publishes the status record (which carries paused_until) and pushes that
// ref. Commit refuses with a *pause.HeldError, except a dry run. The quick check also runs in full
// when the pause ref moved or a pause that held this machine passed its
// deadline. pushSpecs pushes a pause or resume written here that has not
// gone out.
//
// A re-root (design §10.2, package reroot) replaces the remote's history.
// When the fetched main does not descend from the accepted one, the run
// looks for a re-root record that leads there, verified by a pinned
// key-log member's signature and newer than this machine's floor (its
// join time and the newest re-root it runs). Without one it refuses the fetch with a
// HoldTaskRewrite hold. With one it holds (HoldTaskReroot) while this
// machine has commits the old history lacks (unless Options.Carry replays
// them), or the rewrite changes a key-log file or fails the RemoteGuard;
// otherwise it backs up the old history when fleet.toml asks (Deps.Backups,
// reroot_keep), moves main to the new head, moves reviewed refs that point
// into the old history, records the new head as accepted last, and goes on
// with the normal checks on new..remote. A machine held by a pause switches
// only for the pause's initiator, during the pause. Reroot is the
// initiator side: checks, its own backup, a signed record and one
// atomic, leased push.
//
// Fetched commits that touch an enclave and whose Machine trailer names no
// member of its key log are applied, alerted through the notify hook and
// kept in the status record.
//
// Exported API:
//
//	type Options struct{ Auto, Push, DryRun bool; MaxRetries int; Quick, Carry bool }
//	type CommitOptions struct{ Message; Paths; DryRun; Capture; Changes; ChangesScope; Build; Atomic; Forget; Trigger; Session; Tool; Unattended; Resolve; Push; MaxRetries } // Forget: targets an untrack stops managing here once its commit lands, before the apply
//	(Build computes Capture and Changes under the commit's hold of the sync lock, on the main it lands on)
//	type MessageInfo struct{ Trigger, Subject, Session, Tool string }; Trigger* and Trailer* constants
//	type RemoteHeads interface{ RemoteHeads(ctx) (map[string]model.CommitID, error) } // the quick check; *store.Repo
//	const FullEvery, WakeGap
//	type Report struct{ ... }; type DryCommit struct{ Scope; Subject; Paths } // Report.Planned: what a dry-run Commit would commit
//	type Syncer struct{ Deps }
//	func (s *Syncer) Run(ctx, opts Options) (Report, error)
//	func (s *Syncer) Commit(ctx, opts CommitOptions) (Report, error)
//	type Lock interface{ Acquire(ctx context.Context) (release func(), err error) }
//	func FileLock(stateDir string) Lock; func FileLockTimeout(stateDir string, d time.Duration) Lock
//	func FileLockWait(stateDir string, d time.Duration, onWait func(*Holder, time.Duration)) Lock // onWait once, before the first wait
//	type NetLock interface{ TryAcquire() (release func(), err error) }; func FileNetLock(stateDir string) NetLock
//	const LockFile, NetLockFile, LockSync, LockNetwork; var ErrLocked, ErrSelfLocked, ErrNetBusy, ErrPushDeferred
//	type Holder struct{ PID int; Command string; Since time.Time }; type LockedError struct{ Lock; Holder; Cause }
//	type HeldLock struct{ Lock; Holder; Age }; func HeldLocks(stateDir string) []HeldLock
//	func NetBackingOff(stateDir, now) bool; func NetBackoff(stateDir, now) (time.Time, bool)
//	type Policy struct{ Quiet; MassChange; Protected; Host; QuietFor; Protect; LastChange; MergeFor; VolatileFor }
//	func PlanCommits(c apply.Capture, st *apply.State, p Policy, leases []Lease, self model.MachineID, now time.Time) ([]PlannedCommit, []model.Hold, error)
//	type MergePolicy string; type Structural interface{ Merge3(format, volatile, base, ours, theirs) }
//	type RemoteGuard interface{ Allow(ctx, from, to *apply.Snapshot) (bool, string, error) }
//	type PathGuard interface{ RemoteGuard; Weakenings(from, to *apply.Snapshot) []apply.Weakening } // holds weakened targets alone
//	const HoldTaskKeyLog, HoldTaskGuard (= apply.GuardTask); const AlertNonMember, AlertKeyLogRewrite, AlertGuardRefused, AlertPathHeld
//	type Lease struct{ Holder string; Paths []string; Expires time.Time }
//	func LeaseOn(leases []Lease, t model.Target, now time.Time) (Lease, bool) // the live lease naming t
//	(an Unattended Commit skips every path a live stored lease names)
//	type Leases interface{ List() ([]Lease, error); Take(Lease) error; Release(holder string, paths ...string) error } // Take adds to a live lease of the same holder and refreshes its expiry
//	func FileLeases(stateDir string) Leases
//	const LockTimeout, CommandLockTimeout // the timer's wait; an interactive command's default wait
//	type ReviewItem struct{ Commit store.Commit; Scope model.Scope; Diff string }
//	func Unreviewed(ctx, st store.Store, keys *crypt.Set, scope model.Scope) ([]ReviewItem, error)
//	func Ack(ctx, st store.Store, scope model.Scope, upTo model.CommitID) error
//	func SeedReviewed(ctx, st store.Store) error; const AlertReviewedSkip
//	const AcceptedFile = "remote-accepted"; func ReadAccepted(stateDir string) (model.CommitID, bool)
//	func SeedAccepted(stateDir string, start model.CommitID) error // never replaces a record
//	func SeedStart(ctx, st store.Store, stateDir string, holds []model.Hold, preFetch model.CommitID) (model.CommitID, error)
//	const RefReviewNotes = "refs/yadm/notes/review"; const NoteSchema = 1; var ErrNoteNeedsSeal
//	type NoteOptions struct{ Commit; Why; PathsOnly; Seal; Machine; Now }
//	type Note struct{ Commit; Machine; Time; Why; PathsOnly; Sealed; Enclave; Opened }; func (Note) Text() string
//	func WriteNote(ctx, st store.Store, snap *apply.Snapshot, opts NoteOptions) (Note, error) // seals before writing
//	func ReadNotes(ctx, st store.Store, keys *crypt.Set) (map[model.CommitID]Note, error)
//	func PushNotes(ctx, st store.Store, lock Lock, net NetLock) (bool, error)
//	(ReviewItem gains Note *Note; pushSpecs also pushes the notes ref, merging a diverged one)
//	Report.Paused, Report.Pause *pause.View
//	func (s *Syncer) Trust(ctx, rev) pause.Trust; func FleetIDs(*fleet.File) []model.MachineID
//	func (s *Syncer) EvalPause(ctx) (pause.View, pause.Trust, error)
//	func (s *Syncer) PublishPause(ctx, recs []pause.Record) (pushed bool, err error) // waits PauseNetWait for the network lock
//	func (s *Syncer) FetchRefs(ctx) error; func (s *Syncer) NudgePeers(ctx)
//	Deps.Backups string // re-root backup directory
//	const HoldTaskRewrite, HoldTaskReroot; const AlertHistoryRewrite, AlertRerootAccepted, AlertRerootHeld
//	var ErrRerootRefused, ErrRerootState; func RefCarry(id string) string
//	type RerootRequest struct{ NewHead, Reason, PauseID string; Signer *crypt.Identity; FoldUnreviewed bool }
//	type RerootResult struct{ Record reroot.Record; Pushed bool; Unreviewed map[model.Scope]int; Sync *Report }
//	func (s *Syncer) RerootCheck(ctx, req) (RerootResult, error) // checks only
//	func (s *Syncer) Reroot(ctx, req) (RerootResult, error)
//	type RerootStatus struct{ Last *reroot.Accepted; Held *model.Hold }; func ReadRerootStatus(stateDir string, holds []model.Hold) RerootStatus
package sync
