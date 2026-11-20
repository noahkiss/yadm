// Package apply moves bytes between the source and $HOME: apply (source to
// targets), scan (find drift), capture (targets to source changes) and adopt
// (take over a machine whose files already exist). It also owns the local
// state database that makes all four safe.
//
// Invariants:
//
//   - Apply writes a target atomically (temp file plus rename) and only when its
//     bytes change. It never overwrites a target whose current hash differs from
//     the hash it last wrote: that target is drifted, and apply captures it
//     first or holds it (model.HoldDrifted). Bytes it does replace go to a
//     backup directory in the state directory for 30 days.
//   - Capture is accepted only if rendering the new source for this machine
//     reproduces the target byte for byte (the round-trip check). Otherwise the
//     file is held as uncapturable. Templates capture by patching the template
//     with the target's diff against the last render, then re-checking.
//   - A non-member never writes plaintext of an enclave it cannot open: sealed
//     files are skipped, sealed values and regions are left out of targets and
//     restored from the source on capture (package rules).
//   - A hand edit to a rendered target is drift like any other. Capture patches
//     the template; when that fails the target is held (model.HoldRenderedEdit)
//     and status reports it. Apply never re-renders over it.
//   - Every command starts with Scan; scanning is a stat pass that hashes only
//     on a stat mismatch, plus a full hash pass at most once a day.
//
// Exported API:
//
//	type State struct{ Schema int; Machine model.MachineID; Applied model.CommitID; FirstApplyDone bool; Targets map[model.Target]TargetState; Holds []model.Hold; Observed map[string]model.ObservedFact }
//	type TargetState struct{ Source; SourceBlob; Scope; Written; Size; ModTime; SealSet; LastRender }
//	type StateDB interface{ Load() (*State, error); Save(*State) error }
//	func FileStateDB(stateDir string) StateDB
//	type Deps struct{ Store; Manifest; Plan; Context; Keys; Render; State; Home; StateDir; Tasks }
//	type Engine struct{ Deps }
//	func (e *Engine) Scan(ctx, opts ScanOptions) ([]Drift, error)
//	func (e *Engine) Plan(ctx, rev model.CommitID) ([]Action, error)
//	func (e *Engine) Apply(ctx, rev model.CommitID, opts ApplyOptions) (Result, error)
//	func (e *Engine) Capture(ctx, drift []Drift) (Capture, error)
//	func (e *Engine) Adopt(ctx, rev model.CommitID, opts AdoptOptions) (Result, error)
//	func (e *Engine) Retag(ctx, t model.Target, opts RetagOptions) (Capture, error)
package apply
