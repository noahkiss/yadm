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
//     first or holds it (model.HoldDrifted). The exception is a
//     `merge = "union"` target whose source changed too: apply writes the
//     line union (textmerge.Union, the source's lines first) and records the
//     source as written, so the next capture commits the union. Bytes it
//     does replace go to a backup directory in the state directory for 30
//     days.
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
//     state records each target's protection (enclave, sealed keys, regions,
//     and the machine-local keys of keep, drop and volatile) and the explicit
//     mode of a file with enclave plaintext; a weaker manifest entry or a
//     wider mode holds the target with model.HoldSealGuard in apply and
//     capture until AllowProtection. A new keep, drop or volatile entry over
//     a file yadm never wrote is held with model.HoldNeedsDecision, unless
//     the file, or the regular file inside $HOME a symlink there resolves
//     to, is byte-identical to the source's own (opened) bytes. ResolveHold
//     with take target is that decision: it records the target as managed
//     with the entry's protection, then captures it. An owned
//     root that is new or changed its enclave takes effect, for capture and
//     delivery, only after AllowRoot (model.HoldRootUntrusted until then);
//     files already in it, or copied in by adopt, go into State.Baseline and
//     are never captured automatically. Only the deepest accepted root
//     that contains a new file captures it, never a shallower one, and not
//     when its ignore globs match the file, a deeper enclave root of another
//     enclave (not accepted or not applying here) contains it, or a manifest
//     entry names it. Track and retag refuse to take a file under an
//     enclave root out of that enclave.
//   - A target whose parent directory resolves outside $HOME (InsideHome,
//     ErrOutsideHome), or whose name holds a control character, is held:
//     never read, written or captured.
//   - Sealed content new to this machine opens only under the enclave's
//     current epoch; content that does not open is held, never fatal. An
//     explicit mode wider than an enclave file's source mode is held.
//   - A committed deletion of a target its own literal [[file]] entry names
//     drops that entry too (DropEntries), so the manifest never names a
//     missing source; it refuses when another entry still reads the source.
//   - Retag, MoveSource and Untrack edit only the lines they change in
//     manifest.toml and verify the edit parses to what was asked. A sealed
//     blob, sealed value or region that moves is opened under the old path
//     and sealed under the new one in memory, under the current epoch only;
//     a part this machine cannot open fails with crypt.ErrNotMember.
//   - A full apply drops the holds nothing covers any more (no plan target,
//     state record, applying glob or owned root), except conflicts, gate holds,
//     weakened-protection holds and holds without a target.
//   - Backups of files with enclave plaintext go to
//     backup/enclave/<enclaves>/ and are deleted when a verified key log no
//     longer lists this machine.
//   - An enclave in Deps.OnDemand is read on demand only. Load verifies its
//     key log and advances its pin as for any enclave, then leaves its keys
//     out of Snapshot.Keys and Crypto, so apply, capture, track, retag,
//     merges and the gate treat it as a non-member does. A target of it that
//     an earlier apply delivered leaves $HOME as if it had left the plan.
//     Its plaintext is never backed up, and older backups of it are
//     deleted: a file its protection covers is replaced only when it holds
//     the bytes apply last wrote, else backup refuses. Snapshot.Readable
//     holds every key, for stdout and key-log writes only.
//
// Exported API:
//
//	type State struct{ Schema; Machine; Applied; FirstApplyDone; LastFullHash; Targets; Holds; Observed; Tasks; RenderContext; Roots; Seen; Baseline; Ignored; TaskInputs; Outputs }
//	func (e *Engine) Generated(ctx) ([]model.Target, error) // files on disk matching a task's outputs
//	type TargetState struct{ Source; SourceBlob; Scope; Written; Size; ModTime; Mode; Want; SealSet; Enclave; Seal; Regions; Keep; Drop; Volatile; ExplicitMode; RenderHash; ApplyKey; ChangedAt }
//	type StateDB interface{ Load() (*State, error); Save(*State) error }
//	func FileStateDB(stateDir string) StateDB
//	type Deps struct{ Store; Self; Identity; Pins; State; Home; User; StateDir; Tasks; Now; Allow; OnDemand; LoadSnapshot; Rules; Text; StatTimeout; ScanBudget }
//	type Snapshot struct{ Commit; Fleet; Manifest; Plan; Context; Keys; ReadKeys; OnDemand; Enclaves; Render; Crypto; Tree }
//	type Crypto interface{ rules.Sealer; SealFile(e, path, pt); OpenFile(e, path, ct) }; func SetCrypto(*crypt.Set) Crypto
//	const KindProtection, KindMode, KindRoot extexec.Kind // allow-list kinds
//	func ModeAccepted(t model.Target, live, want fs.FileMode) bool // a stricter live mode, or group write the owner and group may read and write, is not drift (never under .ssh or .gnupg), unless it drops the owner's execute bit
//	func InsideHome(home, p string) error; var ErrOutsideHome // p's real parent directory stays under $HOME
//	func (e *Engine) AllowProtection(ctx, rev model.CommitID, t model.Target) error
//	func (e *Engine) AllowRoot(ctx, rev model.CommitID, path model.Target) error
//	type Rules interface{ ToTarget; ToSource; Reseal } // default: package rules
//	type Text interface{ Merge3; PatchTemplate }      // default: package textmerge
//	type Engine struct{ Deps }; func New(Deps) *Engine
//	func (e *Engine) Load(ctx, rev model.CommitID) (*Snapshot, error)
//	func ExpandRoots(man, plan, tree, allowed); const RootIndex // owned roots share their entry-less source files; Load calls it with this machine's accepted or allowed roots
//	func (e *Engine) Render(ctx, snap *Snapshot, t model.Target, live []byte) ([]byte, error) // the one render pipeline; ErrNotPlanned, crypt.ErrNotMember
//	func (e *Engine) OpenSource(ctx, snap *Snapshot, t model.Target) ([]byte, error) // the source as stored, a whole sealed file opened in memory; refuses what Render refuses
//	func (e *Engine) Ignore(ctx, snap *Snapshot, t model.Target) error; func (e *Engine) Ignored(t) bool // State.Ignored; ErrManaged, ErrNotIgnorable
//	func (e *Engine) SettleHolds(ctx, drift []Drift) (int, error) // drop holds whose target is back at its last write, and an unmanaged file's protected or gate hold once the file is gone
//	func (s *Snapshot) CanOpen(e model.EnclaveName) bool // delivery: false for an on-demand enclave
//	func (s *Snapshot) CanRead(e) bool; func (s *Snapshot) Readable() *crypt.Set; func (s *Snapshot) IsOnDemand(e) bool // stdout and key-log writes only
//	type Guard struct{ List tasks.AllowList } // sync.RemoteGuard: refuses a fetched manifest that weakens protection until allowed
//	func (e *Engine) Scan(ctx, opts ScanOptions) ([]Drift, error) // a named path also reports a new file under an applying glob or in an accepted root that may capture it
//	func (e *Engine) CheckNew(ctx, t model.Target) error; var ErrRootRefused // why no owned root may capture a new file t here
//	func (e *Engine) Plan(ctx, rev model.CommitID) ([]Action, error)
//	func (e *Engine) Apply(ctx, rev model.CommitID, opts ApplyOptions) (Result, error)
//	func (e *Engine) Capture(ctx, drift []Drift) (Capture, error) // a new file an applying glob matches captures through that entry (rules, enclave, round trip)
//	func (e *Engine) Adopt(ctx, rev model.CommitID, opts AdoptOptions) (Result, error)
//	func (e *Engine) Retag(ctx, t model.Target, opts RetagOptions) (Retagged, error) // opts.Source picks a variant (ErrVariants); when keeps non-type terms (cond.Retype)
//	func (e *Engine) RetagAll(ctx, ts []model.Target, opts RetagOptions) (RetaggedAll, error) // several targets as one change, one manifest; any refusal fails all (ErrBadRequest for a repeat or a shared source)
//	func (e *Engine) Track(ctx, t model.Target, opts TrackOptions) (Capture, error) // ErrCovered, ErrNotFile, crypt.ErrNotMember
//	func (e *Engine) DropEntries(ctx, rev model.CommitID, targets []model.Target) (*store.Change, error) // manifest edit for committed deletions; nil when none needed
//	func (e *Engine) MoveSource(ctx, from, to model.SourcePath) (SourceMove, error) // rename within a scope, resealed in memory; ErrBadRequest, crypt.ErrNotMember
//	func (e *Engine) Untrack(ctx, t model.Target, opts UntrackOptions) (Untracked, error) // drop one entry and its source unless shared; ErrBadRequest, ErrVariants, crypt.ErrNotMember
//	func Forget(st *State, t model.Target, now time.Time, onDisk bool) // stop managing t here, file kept; ignored inside an accepted root
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
