// Package tasks runs the user-declared external programs around apply and
// commit: on-change tasks after an apply, and the commit gate's checks before
// every commit.
//
// A task is declared in the manifest: "when an apply writes (`on`) or removes
// (`on_remove`) a target matching these globs, or on this machine's first
// apply (`first_apply`), run this command", scoped by a `when` condition and
// bounded by a timeout. Results go into the machine's status record. A target
// that adopt or a first apply takes over with its bytes already in place
// counts as written for `on`: the apply engine adds it to Event.Changed.
//
// Two more triggers watch this machine's inputs instead of paths:
// `on_fact` (a collector's observed items, or "fact:KEY") and `on_render`
// (the render context: types, declared and observed facts, the fleet). The
// apply passes a fingerprint of each input (Event.Inputs) and what each task
// last ran against (Event.LastInputs, kept in state); a task with no record
// fires once. A held task records nothing, so the change still fires once it
// is allowed. Only a full apply checks inputs; adopt runs path tasks only.
//
// A task's `outputs` globs name files it generates. Apply records them, and
// scan, capture and retag never report, take or track such a file, so it is
// never committed or gated; status lists it as generated.
//
// A check is declared in the manifest too. The Gate runs matching checks on
// the staged targets before any commit, manual or automatic, and fails closed:
// a failing, timed-out or disallowed check holds its files; other files still
// commit.
//
// The core knows no package manager or provisioning tool. Bootstrap is a task
// with `first_apply = true`; package-manager integration ships, if ever, as a
// separate `yadm-<name>` executable that a task calls.
//
// Reloading service units is the one built-in task: apply reports changed
// unit targets and the built-in reloader runs `launchctl bootout/bootstrap`
// or `systemctl --user daemon-reload` plus restart, only for units whose bytes
// changed.
//
// Trust: task and collector definitions run commands, and any machine that can
// push can change them. A machine runs a definition only after it is allowed
// locally (`yadm task allow`, or `--allow-tasks` on init and adopt). The
// allow list stores a hash of each definition; a changed definition is held
// (model.HoldTaskUntrusted) and reported, never run. Definitions never
// auto-commit. A task hold sets Hold.Task and no Target; its id is
// model.HoldID, and the caller keeps the first sighting (model.KeepSince)
// so the id stays stable across runs.
//
// Unit reloads need no allow entry, by decision. The unit file is managed
// content like a shell profile: once apply writes it, launchd or systemd
// runs it at the next login whether or not yadm reloads it. Gating the
// reload would delay the effect, not prevent it. The allow list guards what
// the manifest itself asks this machine to run: tasks, checks and
// collectors.
//
// Exported API:
//
//	type Event struct{ Commit model.CommitID; Changed, Removed []model.Target; Units []manifest.Unit; FirstApply bool; Inputs map[string]string; LastInputs map[string]map[string]string }
//	const TriggerPaths, TriggerRemove, TriggerFirstApply, TriggerUnit, TriggerFact, TriggerRender; const RenderInput = "@render"
//	func InputKeys(def manifest.TaskDef) []string
//	func Select(defs map[string]manifest.TaskDef, ev Event) ([]Selected, error)
//	type Selected struct{ Name, Trigger string; Def manifest.TaskDef; Matched []model.Target; Inputs []string }
//	type AllowList interface{ Allowed(kind extexec.Kind, name, hash string) bool; Allow(kind extexec.Kind, name, hash string) error }
//	func DefinitionHash(def any) (string, error) // tasks, checks and collectors share the allow list
//	func FileAllowList(stateDir string) AllowList
//	type Runner struct{ Exec extexec.Runner; Allow AllowList; Units UnitReloader }
//	func (r *Runner) Run(ctx, ev Event, sel []Selected, req extexec.Request) ([]model.TaskResult, []model.Hold)
//	type Gate interface{ Check(ctx, staged []Staged, req extexec.Request) (pass []model.Target, holds []model.Hold, verdicts []Verdict) }
//	func NewGate(checks map[string]manifest.CheckDef, r extexec.Runner, allow AllowList) Gate
//	func NewGateIn(checks, r, allow, dir string) Gate // dir (the state dir) holds staged plaintext; "" fails closed
//	type UnitReloader interface{ Reload(ctx, u manifest.Unit, home string) error }
//	func SystemReloader(goos string) (UnitReloader, error)
//	func NewReloader(goos string, c Commander, uid int) (UnitReloader, error) // c runs launchctl/systemctl
//	type SkipError struct{ Reason string }; func IsSkip(err error) (string, bool) // a unit left alone on purpose: never, KeepAlive, self, unreadable plist
//	func MatchGlob(glob, target string) bool // "**" spans segments; "*" stays in one
package tasks
