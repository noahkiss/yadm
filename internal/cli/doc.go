// Package cli is the command tree, the JSON envelope, exit codes, the query
// commands (`machine`, `why`, `managed`, `where`, `explain`) and the
// dispatch to manifest plugins and external `yadm-<name>` subcommands. It
// wires every other package together and holds no domain logic of its own.
//
// `yadm <name>` resolves a built-in command first, then a manifest plugin
// whose `when` is true here, then `yadm-<name>` on PATH. A plugin runs only
// when allowed (KindPlugin in the allow list, tasks.PluginHash over its
// definition and executable bytes); otherwise it exits ExitRefused and never
// falls through to PATH. A plugin's stdio, terminal, arguments (--json
// included) and exit code pass through unchanged, with no envelope.
//
// Every command accepts --json. With --json, stdout carries exactly one
// Envelope and nothing else; human text goes nowhere. No command prompts
// unless it is given --interactive. A command that succeeds with holds exits
// ExitAttention with ok true and error code "attention". Key-log trust failures
// (crypt.ErrInvalidLog, ErrNotPinned, ErrBadSignature, ErrBrokenChain,
// ErrNotMember) and a refused re-root (sync.ErrRerootRefused) exit ExitRefused. A write while a fleet pause holds this
// machine (pause.ErrHeld) exits ExitLocked, like a held sync lock.
//
// A relative path argument is relative to $HOME; an absolute one must be
// under $HOME. Upstream yadm verbs (alt, bootstrap, encrypt, decrypt, enter,
// perms, introspect, gitconfig, upgrade) print their replacement and exit
// ExitUsage. `clone` is init; `holds` and `conflicts` are `hold list`;
// `fleet status` is `fleet list`.
//
// Which package function backs each command:
//
//	version, where                 cli (implemented)
//	machine, why, managed, list    apply.Engine.Load -> Snapshot (Fleet, Plan.Why); explain: cli over the same;
//	                               list --as resolves as manifest --as does
//	manifest [--as|--fleet]        manifest.Resolve per fleet machine over the loaded snapshot; reads no file content
//	eval <cond> [--as]             cond.Parse with the named conditions, cond.Expand; another machine's observed
//	                               facts from its status ref: plain, plus sealed ones a member opens (fleet.WithVisible)
//	init, clone                    store.Clone, crypt.GenerateIdentity + Save, schedule.ForOS().Install
//	status                         apply.Engine.Scan, apply.Engine.Holds, store.IsAncestor, sync.HeldLocks, sync.NetBackoff
//	apply                          apply.Engine.Load, Plan, Apply
//	capture                        apply.Engine.Scan, Capture
//	diff                           apply.Engine.Load, render + rules in memory, textmerge.Diff; an on-demand
//	                               enclave's target is skipped with a pointer to show
//	show <path> [--as] [--source]  apply.Engine.Render (OpenSource with --source) with the machine's plan and
//	                               context, its published home and user (else $HOME and $USER), and the keys of
//	                               the enclaves it is a member of that this machine holds (Snapshot.Readable);
//	                               stdout only
//	commit                         refuses named paths no entry, applying glob (manifest.Plan.GlobNew) or owned root covers, then sync.Syncer.Commit (tasks.Gate inside), then push in the same call;
//	                               --expect-enclave is sync.CommitOptions.ExpectEnclave (sync.ErrNotSealed exits ExitRefused)
//	                               (fetch and push under sync.FileNetLock, never under the sync lock)
//	sync                           sync.Syncer.Run (--auto implies the quick check and records the run);
//	                               without --auto, schedule.Status.Broken + Install, once an hour
//	review note                    sync.WriteNote under the sync lock, then sync.PushNotes
//	pause, resume                  pause.Sign with the machine's key, sync.Syncer.EvalPause + PublishPause;
//	                               pause waits for peers' status refs (store.StatusRefs.ReadAll), polling with hooks.sleep;
//	                               apply, capture, hold resolve and the allows refuse (pause.HeldError, ExitLocked)
//	                               while another machine's pause holds this one
//	reroot [carry], backups        sync.Syncer.RerootCheck, then a pause (as above) when none runs, then
//	                               sync.Syncer.Reroot; waits for peers' status refs like pause; carry is
//	                               sync.Syncer.Run with Options.Carry; backups: reroot.List / Prune
//	hook post-edit|stop|session-start  sync.Syncer.Commit/Run (unattended, bounded lock wait); own
//	                               exit codes 0/1/2 and a verdict instead of an envelope (docs/hooks.md);
//	                               session-start repairs a broken schedule as sync does, then adds plugin news
//	                               (extexec.Runner, KindNews, all plugins at once, NewsTimeout, NewsLines, NewsTotalLines)
//	defer                          deferred.json in the state directory; review list shows it
//	protection allow, root allow   apply.Engine.AllowProtection / AllowRoot, then Apply
//	log                            store.Log + crypt.Set + textmerge.Diff
//	retag                          apply.Engine.RetagAll (one or more paths), committed once through sync.Commit
//	                               (Capture + Changes; Changes alone when the picked entry does not apply here)
//	source mv                      apply.Engine.MoveSource, committed through sync.Commit (Changes, Atomic)
//	untrack                        apply.Engine.Untrack, committed through sync.Commit (Changes, Atomic, Forget)
//	track                          apply.Engine.Track, committed through sync.Commit (Capture + Changes); a new file under an applying glob (no --when, --enclave) commits as `commit <path>`; --variant adds an entry beside existing ones (ErrBadRequest exits 2)
//	                               retag, track, untrack, source mv and the enclave writes (writeEntry) check
//	                               their change, then compute it again in CommitOptions.Build, on the main the
//	                               commit lands on; writeEntry refuses a key-log seq the source holds
//	--lock-wait, $YADM_LOCK_WAIT   a command's wait for the sync lock (default sync.CommandLockTimeout; one stderr
//	                               line names the holder); sync --auto waits at most sync.LockTimeout
//	bisect                         store.Log + apply.Engine.Load + render into a sandbox
//	collect                        fleet.Collect with tasks.FileAllowList
//	check                          store.CheckSecrecyConfig, crypt.LoadSet, manifest.Resolve, schedule.Status
//	                               (Broken, last scheduled run), git config (merge.*.driver, filter.*);
//	                               membership roles per pinned key log, with peers' on_demand from their status refs
//	enclave on-demand [--off]      fleet.SaveIdentity: the on_demand list of machine.toml
//	fleet list|show|diff           store.StatusRefs.ReadAll, fleet.OpenAll (members only), fleet.WithVisible,
//	                               fleet.DiffObserved; a non-member's output holds no sealed facts
//	enclave create|add|remove|retire|set-recovery
//	                               crypt.Create/Add/Remove/Retire/SetRecovery, crypt.MarshalLogEntry, sync.Commit (Changes),
//	                               crypt.FilePins (pinned after the commit lands); remove also apply.Engine.Reseal,
//	                               committed with its entry atomically (sync.CommitOptions.Atomic), retired only once it landed;
//	                               add without keys: crypt.Vouched over pinned logs, signer this machine or a member
//	enclave new-recovery           crypt.GenerateIdentity + Save into a new directory; DefaultPaths only, no init
//	enclave recover --read-only    git reads of main in --repo (store.Output), crypt.VerifyLog (--expect as the pin),
//	                               crypt.LoadRecoveryKey or ParseRecoveryKey (stdin), crypt.OpenRecovery; opens every
//	                               selected whole sealed file before it writes any, into a new --out (os.Root); no init
//	review list|ok|revert          sync.Unreviewed (Snapshot.Readable), sync.Ack, store.CommitTree
//	hold list|show|resolve         apply.Engine.Holds, ResolveHold; conflicts through sync.Commit{Resolve}
//	lease take|release|list        sync.FileLeases
//	task list|allow|run            tasks.FileAllowList, tasks.DefinitionHash, tasks.Runner
//	schedule install|...           schedule.ForOS
//	import                         importer.Import; a cli sealer creates each enclave's key log
//	                               and commits it on top of the import commit
//	adopt                          apply.Engine.Adopt, schedule.ForOS().Install
//	git                            store.Passthrough: git in the source clone with the secrecy overrides
//	plugin list|allow              tasks.PluginHash, tasks.FileAllowList (KindPlugin); allow under the sync lock
//	<plugin>                       extexec.Passthrough of $HOME/<command[0]> in the caller's directory, with
//	                               extexec.PassEnv plus YADM_ENCLAVES, YADM_ON_DEMAND, YADM_PLUGIN_STATE
//	<other>                        extexec.FindSubcommand + extexec.Runner
//
// Exported API:
//
//	type Envelope struct{ Schema int; Command string; OK bool; Data any; Next []string; Error *ErrorBody }
//	type ErrorBody struct{ Code, Message string; Details any }
//	const ExitOK, ExitError, ExitUsage, ExitAttention, ExitLocked, ExitNotImplemented, ExitRefused
//	const ManifestQuerySchema, EvalQuerySchema // data schemas of the manifest and eval queries
//	type Paths struct{ Source, State, Config string }
//	func DefaultPaths() (Paths, error)
//	func NewRoot(version string) *cobra.Command
//	func Main(args []string, stdout, stderr io.Writer, version string) int
package cli
