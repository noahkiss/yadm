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
//     file is held as uncapturable. Templates capture with
//     textmerge.PatchTemplate: the last render is recomputed from the source
//     blob and the stored render Context (never stored as bytes), its diff to
//     the target is applied to the template, and the round trip is re-checked.
//   - A non-member never writes plaintext of an enclave it cannot open: sealed
//     files are skipped, sealed values and regions are left out of targets and
//     restored from the source on capture (package rules).
//   - A hand edit to a rendered target is drift like any other. Capture patches
//     the template; when that fails the target is held (model.HoldRenderedEdit)
//     and status reports it. Apply never re-renders over it. The hold names
//     the template (Hold.Source) and carries a proposed unified diff
//     (Hold.Patch, Hold.PatchOf): a template patch that renders back to the
//     target here (the edited expressions become literal text), else the
//     edit against the last render. An agent reviews it and commits in one
//     step. An enclave template gets no patch: holds live in
//     the state file, which never holds plaintext.
//   - Every command starts with Scan; scanning is a stat pass that hashes only
//     on a stat mismatch, plus a full hash pass at most once a day.
//   - The manifest cannot weaken secrecy on its own (docs/design.md 7.4). The
//     state records each target's protection (enclave, sealed keys, regions);
//     a weaker manifest entry holds the target with model.HoldSealGuard in
//     apply and capture until AllowProtection. An owned root that is new or
//     changed its enclave takes effect only after AllowRoot
//     (model.HoldRootUntrusted until then); files already in it go into
//     State.Baseline and are never captured automatically.
//   - Sealed content new to this machine opens only under the enclave's
//     current epoch; content that does not open is held, never fatal. An
//     explicit mode wider than an enclave file's source mode is held.
//   - Backups of files with enclave plaintext go to
//     backup/enclave/<enclaves>/ and are deleted when a verified key log no
//     longer lists this machine.
//
// Exported API:
//
//	type State struct{ Schema; Machine; Applied; FirstApplyDone; LastFullHash; Targets; Holds; Observed; Tasks; RenderContext; Roots; Seen; Baseline }
//	type TargetState struct{ Source; SourceBlob; Scope; Written; Size; ModTime; Mode; SealSet; Enclave; Seal; Regions; RenderHash; ChangedAt }
//	type StateDB interface{ Load() (*State, error); Save(*State) error }
//	func FileStateDB(stateDir string) StateDB
//	type Deps struct{ Store; Self; Identity; Pins; State; Home; User; StateDir; Tasks; Now; Allow; LoadSnapshot; Rules; Text; StatTimeout; ScanBudget }
//	type Snapshot struct{ Commit; Fleet; Manifest; Plan; Context; Keys; Enclaves; Render; Crypto; Tree }
//	type Crypto interface{ rules.Sealer; SealFile(e, path, pt); OpenFile(e, path, ct) }; func SetCrypto(*crypt.Set) Crypto
//	const KindProtection, KindRoot extexec.Kind // allow-list kinds
//	func (e *Engine) AllowProtection(ctx, rev model.CommitID, t model.Target) error
//	func (e *Engine) AllowRoot(ctx, rev model.CommitID, path model.Target) error
//	type Rules interface{ ToTarget; ToSource; Reseal } // default: package rules
//	type Text interface{ Merge3; PatchTemplate }      // default: package textmerge
//	type Engine struct{ Deps }; func New(Deps) *Engine
//	func (e *Engine) Load(ctx, rev model.CommitID) (*Snapshot, error)
//	func (e *Engine) Render(ctx, snap *Snapshot, t model.Target, live []byte) ([]byte, error) // the one render pipeline; ErrNotPlanned, crypt.ErrNotMember
//	func (e *Engine) Ignore(ctx, snap *Snapshot, t model.Target) error; func (e *Engine) Ignored(t) bool // State.Ignored; ErrManaged, ErrNotIgnorable
//	func (e *Engine) SettleHolds(ctx, drift []Drift) (int, error) // drop holds whose target is back at its last write
//	func (s *Snapshot) CanOpen(e model.EnclaveName) bool
//	type Guard struct{ List tasks.AllowList } // sync.RemoteGuard: refuses a fetched manifest that weakens protection until allowed
//	func (e *Engine) Scan(ctx, opts ScanOptions) ([]Drift, error)
//	func (e *Engine) Plan(ctx, rev model.CommitID) ([]Action, error)
//	func (e *Engine) Apply(ctx, rev model.CommitID, opts ApplyOptions) (Result, error)
//	func (e *Engine) Capture(ctx, drift []Drift) (Capture, error)
//	func (e *Engine) Adopt(ctx, rev model.CommitID, opts AdoptOptions) (Result, error)
//	func (e *Engine) Retag(ctx, t model.Target, opts RetagOptions) (Capture, error)
//	func (e *Engine) MergeSealed(ctx, snap *Snapshot, c store.Conflict) (*store.Change, *model.Hold, error)
//	func (e *Engine) Reseal(ctx, snap *Snapshot, enclave model.EnclaveName) (Capture, error)
//	func (e *Engine) Holds(ctx) ([]model.Hold, error)
//	func (e *Engine) ResolveHold(ctx, id string, opts ResolveOptions) (Result, error) // Result.Capture carries a take-target capture
//	func HoldID(h model.Hold) string
//
// Every stat and read of a target has a timeout (Deps.StatTimeout) and a
// Scan has a budget (Deps.ScanBudget); a path that does not answer is
// reported as DriftUnreadable or held, never waited on.
package apply
