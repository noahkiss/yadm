// Package cli is the command tree, the JSON envelope, exit codes, the query
// commands (`machine`, `why`, `managed`, `where`, `explain`) and the
// dispatch to external `yadm-<name>` subcommands. It wires every other
// package together and holds no domain logic of its own.
//
// Every command accepts --json. With --json, stdout carries exactly one
// Envelope and nothing else; human text goes nowhere. No command prompts
// unless it is given --interactive. A command that succeeds with holds exits
// ExitAttention with ok true and error code "attention". Key-log trust failures
// (crypt.ErrInvalidLog, ErrNotPinned, ErrBadSignature, ErrBrokenChain,
// ErrNotMember) exit ExitRefused.
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
//	machine, why, managed          apply.Engine.Load -> Snapshot (Fleet, Plan.Why); explain: cli over the same
//	init, clone                    store.Clone, crypt.GenerateIdentity + Save, schedule.ForOS().Install
//	status                         apply.Engine.Scan, apply.Engine.Holds, store.IsAncestor
//	apply                          apply.Engine.Load, Plan, Apply
//	capture                        apply.Engine.Scan, Capture
//	diff                           apply.Engine.Load, render + rules in memory, textmerge.Diff
//	commit                         sync.Syncer.Commit (tasks.Gate inside)
//	sync                           sync.Syncer.Run
//	log                            store.Log + crypt.Set + textmerge.Diff
//	retag                          apply.Engine.Retag, one protected commit on main
//	bisect                         store.Log + apply.Engine.Load + render into a sandbox
//	collect                        fleet.Collect with tasks.FileAllowList
//	check                          store.CheckSecrecyConfig, crypt.LoadSet, manifest.Resolve, schedule.Status,
//	                               git config (merge.*.driver, filter.*)
//	fleet list|show|diff           store.StatusRefs.ReadAll, fleet.DiffObserved
//	enclave create|add|remove|...  crypt.Create/Add/Remove/Rotate/Recover, crypt.MarshalLogEntry,
//	                               crypt.FilePins (pinned after the commit lands); remove also apply.Engine.Reseal
//	review list|ok|revert          sync.Unreviewed, sync.Ack, store.CommitTree
//	hold list|show|resolve         apply.Engine.Holds, ResolveHold
//	lease take|release|list        sync.FileLeases
//	task list|allow|run            tasks.FileAllowList, tasks.DefinitionHash, tasks.Runner
//	schedule install|...           schedule.ForOS
//	import                         importer.Import; a cli sealer creates each enclave's key log
//	                               and commits it on top of the import commit
//	adopt                          apply.Engine.Adopt, schedule.ForOS().Install
//	git                            git in the source clone with the secrecy overrides
//	<other>                        extexec.FindSubcommand + extexec.Runner
//
// Exported API:
//
//	type Envelope struct{ Schema int; Command string; OK bool; Data any; Next []string; Error *ErrorBody }
//	type ErrorBody struct{ Code, Message string; Details any }
//	const ExitOK, ExitError, ExitUsage, ExitAttention, ExitLocked, ExitNotImplemented, ExitRefused
//	type Paths struct{ Source, State, Config string }
//	func DefaultPaths() (Paths, error)
//	func NewRoot(version string) *cobra.Command
//	func Main(args []string, stdout, stderr io.Writer, version string) int
package cli
