// Package sync runs the sync loop, mechanical auto-commit, agent leases and
// the review queue.
//
// Two locks in the state directory serialize one machine's processes. The
// sync lock (LockFile; Acquire waits at most LockTimeout, then ErrLocked)
// covers local writes. The network lock (NetLockFile) covers fetch, push
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
//  3. Run allowed collectors (fleet.CollectWith, with source and commit).
//  4. Fetch origin main and refs/yadm/* (first, before step 1). On a first
//     sync the guard's base is origin main as it was before this fetch.
//     A failed fetch still lets steps 1 to 3 run; the sync then ends with
//     the fetch error. A fetched source that rewrites or
//     deletes a key-log entry, or that the RemoteGuard refuses, is not taken:
//     a hold and one alert, local main stays, main is not pushed.
//  5. If local main is not an ancestor of origin main, replay each local
//     commit onto origin main with `git merge-tree`, in memory. Conflicted
//     paths go up the resolution ladder: a key-level merge for json, jsonc
//     and toml (Structural), then the file's merge policy (text, union,
//     add-only, ours, theirs, generated), then a conflict hold with all three
//     stage blobs and the commit kept on the local-only held ref. Sealed files
//     are opened, merged and resealed in memory. Clean paths still land. Each
//     resolution is recorded in a `Yadm-Resolved:` trailer. History stays
//     linear. There is no autostash and no merge commit.
//  6. Compare-and-swap local main, move the source worktree (a dirty worktree
//     stops with a source_dirty hold), apply. Main moves only after
//     store.CheckWorktree passes, so the clone's index never falls behind
//     HEAD; a commit over a dirty clone makes nothing.
//  7. Publish the status record to this machine's status ref: holds, tasks,
//     published facts, alerts and the pinned key-log head of each enclave.
//  8. Release the sync lock; push main, the status ref and advanced
//     reviewed refs atomically under the network lock. A rejection is not
//     an error: go back to 4 (fetch, then 5 to 7 under the sync lock again),
//     up to MaxRetries rounds with backoff (negative: none), then leave it to
//     the next sync. Only a run that fetched and whose push went out records
//     a full sync for the quick check, so unpushed commits trigger the next
//     one. Never force.
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
// Fetched commits that touch an enclave and whose Machine trailer names no
// member of its key log are applied, alerted through the notify hook and
// kept in the status record.
//
// Exported API:
//
//	type Options struct{ Auto, Push, DryRun bool; MaxRetries int; Quick bool }
//	type CommitOptions struct{ Message; Paths; DryRun; Capture; Changes; ChangesScope; Atomic; Trigger; Session; Tool; Unattended; Resolve; Push; MaxRetries }
//	type MessageInfo struct{ Trigger, Subject, Session, Tool string }; Trigger* and Trailer* constants
//	type RemoteHeads interface{ RemoteHeads(ctx) (map[string]model.CommitID, error) } // the quick check; *store.Repo
//	const FullEvery, WakeGap
//	type Report struct{ ... }
//	type Syncer struct{ Deps }
//	func (s *Syncer) Run(ctx, opts Options) (Report, error)
//	func (s *Syncer) Commit(ctx, opts CommitOptions) (Report, error)
//	type Lock interface{ Acquire(ctx context.Context) (release func(), err error) }
//	func FileLock(stateDir string) Lock; func FileLockTimeout(stateDir string, d time.Duration) Lock
//	type NetLock interface{ TryAcquire() (release func(), err error) }; func FileNetLock(stateDir string) NetLock
//	const LockFile, NetLockFile, LockSync, LockNetwork; var ErrLocked, ErrNetBusy, ErrPushDeferred
//	type Holder struct{ PID int; Command string; Since time.Time }; type LockedError struct{ Lock; Holder; Cause }
//	type HeldLock struct{ Lock; Holder; Age }; func HeldLocks(stateDir string) []HeldLock
//	func NetBackingOff(stateDir, now) bool; func NetBackoff(stateDir, now) (time.Time, bool)
//	type Policy struct{ Quiet; MassChange; Protected; Host; QuietFor; Protect; LastChange; MergeFor; VolatileFor }
//	func PlanCommits(c apply.Capture, st *apply.State, p Policy, leases []Lease, self model.MachineID, now time.Time) ([]PlannedCommit, []model.Hold, error)
//	type MergePolicy string; type Structural interface{ Merge3(format, volatile, base, ours, theirs) }
//	type RemoteGuard interface{ Allow(ctx, from, to *apply.Snapshot) (bool, string, error) }
//	type Lease struct{ Holder string; Paths []string; Expires time.Time }
//	type Leases interface{ List() ([]Lease, error); Take(Lease) error; Release(holder string) error }
//	func FileLeases(stateDir string) Leases
//	const LockTimeout
//	type ReviewItem struct{ Commit store.Commit; Scope model.Scope; Diff string }
//	func Unreviewed(ctx, st store.Store, keys *crypt.Set, scope model.Scope) ([]ReviewItem, error)
//	func Ack(ctx, st store.Store, scope model.Scope, upTo model.CommitID) error
//	func SeedReviewed(ctx, st store.Store) error; const AlertReviewedSkip
//	const RefReviewNotes = "refs/yadm/notes/review"; const NoteSchema = 1; var ErrNoteNeedsSeal
//	type NoteOptions struct{ Commit; Why; PathsOnly; Seal; Machine; Now }
//	type Note struct{ Commit; Machine; Time; Why; PathsOnly; Sealed; Enclave; Opened }; func (Note) Text() string
//	func WriteNote(ctx, st store.Store, snap *apply.Snapshot, opts NoteOptions) (Note, error) // seals before writing
//	func ReadNotes(ctx, st store.Store, keys *crypt.Set) (map[model.CommitID]Note, error)
//	func PushNotes(ctx, st store.Store, lock Lock, net NetLock) (bool, error)
//	(ReviewItem gains Note *Note; pushSpecs also pushes the notes ref, merging a diverged one)
package sync
