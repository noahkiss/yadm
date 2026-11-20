// Package sync runs the sync loop, mechanical auto-commit, agent leases and
// the review queue.
//
// One sync, under an exclusive lock in the state directory:
//
//  1. Scan and capture drift (package apply).
//  2. Auto-commit captured paths whose quiet period has passed, that no lease
//     holds, and that are not protected. The commit gate (tasks.Gate) checks
//     them first and holds failures. One commit per scope, each built in a
//     fresh private index that holds only its own paths, so concurrent agents
//     never sweep each other's changes. Each commit carries `Machine:`, `Yadm-Auto: 1` and
//     `Yadm-Scope:` trailers.
//  3. Run allowed collectors.
//  4. Fetch origin main and refs/yadm/*.
//  5. If local main is not an ancestor of origin main, replay each local
//     commit onto origin main with `git merge-tree` (in memory; sealed
//     conflicts are opened, merged and resealed by apply). A commit whose
//     paths still conflict is split: clean paths land, conflicted paths move
//     to the local held ref and become model.HoldConflict. History stays
//     linear. There is no autostash and no merge commit.
//  6. Compare-and-swap local main, move the source worktree, apply.
//  7. Publish the status record to this machine's status ref.
//  8. Push main and the status ref atomically. On rejection go back to 4, up
//     to MaxRetries with backoff. Never force.
//
// Commits from another machine that touch an enclave whose key log does not
// list that machine are applied and reported through the notify hook.
//
// A timer runs `yadm sync --auto` every few minutes and once at wake. A
// missed run is never queued twice: the next run catches up once.
//
// Exported API:
//
//	type Options struct{ Auto, Push, DryRun bool; MaxRetries int }
//	type Report struct{ ... }
//	type Syncer struct{ Deps }
//	func (s *Syncer) Run(ctx, opts Options) (Report, error)
//	func (s *Syncer) Commit(ctx, opts CommitOptions) (Report, error)
//	type Lock interface{ Acquire(ctx context.Context) (release func(), err error) }
//	func FileLock(stateDir string) Lock
//	type Policy struct{ Quiet time.Duration; MassChange int; Protected []string }
//	func PlanCommits(c apply.Capture, st *apply.State, p Policy, leases []Lease, self model.MachineID, now time.Time) ([]PlannedCommit, []model.Hold, error)
//	type Lease struct{ Holder string; Paths []string; Expires time.Time }
//	type Leases interface{ List() ([]Lease, error); Take(Lease) error; Release(holder string) error }
//	func FileLeases(stateDir string) Leases
//	const LockTimeout
//	type ReviewItem struct{ Commit store.Commit; Scope model.Scope; Diff string }
//	func Unreviewed(ctx, st store.Store, keys *crypt.Set, scope model.Scope) ([]ReviewItem, error)
//	func Ack(ctx, st store.Store, scope model.Scope, upTo model.CommitID) error
package sync
