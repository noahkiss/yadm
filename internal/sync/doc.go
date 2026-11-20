// Package sync runs the sync loop, mechanical auto-commit, agent leases and
// the review queue.
//
// One sync, under an exclusive lock in the state directory (bounded wait,
// LockTimeout):
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
//  4. Fetch origin main and refs/yadm/*. A fetched source that rewrites or
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
//     stops with a source_dirty hold), apply.
//  7. Publish the status record to this machine's status ref: holds, tasks,
//     published facts, alerts and the pinned key-log head of each enclave.
//  8. Push main, the status ref and advanced reviewed refs atomically. On
//     rejection go back to 4, up to MaxRetries with backoff. Never force.
//     A fetched reviewed ref moves the local one only when it skips no
//     commit of its scope; otherwise it is refused with an alert
//     (AlertReviewedSkip). SeedReviewed seeds empty local refs at init.
//
// A quick sync (Options.Quick) first stats the targets and lists the remote
// heads with `git ls-remote`; it stops there unless the remote moved, a
// target drifted, FullEvery passed since the last full sync, or WakeGap
// passed since the last check. Commit with Push runs steps 3 to 8 right
// after its commit, under the same lock. After a push that moved main,
// Deps.Nudge runs so peers can sync now.
//
// Fetched commits that touch an enclave and whose Machine trailer names no
// member of its key log are applied, alerted through the notify hook and
// kept in the status record.
//
// Exported API:
//
//	type Options struct{ Auto, Push, DryRun bool; MaxRetries int; Quick bool }
//	type CommitOptions struct{ Message; Paths; DryRun; Capture; Changes; ChangesScope; Trigger; Session; Tool; Unattended; Resolve; Push; MaxRetries }
//	type MessageInfo struct{ Trigger, Subject, Session, Tool string }; Trigger* and Trailer* constants
//	type RemoteHeads interface{ RemoteHeads(ctx) (map[string]model.CommitID, error) } // the quick check; *store.Repo
//	const FullEvery, WakeGap
//	type Report struct{ ... }
//	type Syncer struct{ Deps }
//	func (s *Syncer) Run(ctx, opts Options) (Report, error)
//	func (s *Syncer) Commit(ctx, opts CommitOptions) (Report, error)
//	type Lock interface{ Acquire(ctx context.Context) (release func(), err error) }
//	func FileLock(stateDir string) Lock; func FileLockTimeout(stateDir string, d time.Duration) Lock
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
//	func PushNotes(ctx, st store.Store) (bool, error)
//	(ReviewItem gains Note *Note; pushSpecs also pushes the notes ref, merging a diverged one)
package sync
