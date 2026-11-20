package tasks

import (
	"context"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Triggers recorded in model.TaskResult.Trigger.
const (
	TriggerPaths      = "paths"
	TriggerRemove     = "remove"
	TriggerFirstApply = "first-apply"
	TriggerUnit       = "unit"
)

// Event is what one apply changed.
type Event struct {
	Commit     model.CommitID
	Changed    []model.Target
	Removed    []model.Target
	Units      []manifest.Unit // changed unit targets
	FirstApply bool
}

// Selected is one task to run for an event.
type Selected struct {
	Name    string
	Trigger string
	Def     manifest.TaskDef
	Matched []model.Target
}

// Select returns the tasks an event triggers, in name order. defs must
// already be filtered by `when` (manifest.Plan.Tasks).
func Select(defs map[string]manifest.TaskDef, ev Event) ([]Selected, error) {
	return nil, model.ErrNotImplemented
}

// AllowList is the local record of task and collector definitions this
// machine agreed to run.
// Collectors (fleet.CollectorDef) use the same list with extexec.KindCollector.
type AllowList interface {
	Allowed(kind extexec.Kind, name, hash string) bool
	Allow(kind extexec.Kind, name, hash string) error
}

// AllowFile is the allow list's file in the state directory.
const AllowFile = "allowed.json"

// DefinitionHash is the hex SHA-256 of a task or collector definition's
// canonical JSON.
func DefinitionHash(def any) (string, error) { return "", model.ErrNotImplemented }

// FileAllowList returns the AllowList stored in AllowFile in stateDir.
func FileAllowList(stateDir string) AllowList { return fileAllow{dir: stateDir} }

type fileAllow struct{ dir string }

// Allowed answers false until implemented: nothing runs.
func (fileAllow) Allowed(extexec.Kind, string, string) bool { return false }
func (fileAllow) Allow(extexec.Kind, string, string) error  { return model.ErrNotImplemented }

// UnitReloader reloads one service unit.
type UnitReloader interface {
	Reload(ctx context.Context, u manifest.Unit, home string) error
}

// SystemReloader returns the launchd/systemd reloader for this OS.
func SystemReloader(goos string) (UnitReloader, error) { return nil, model.ErrNotImplemented }

// Runner runs selected tasks and unit reloads.
type Runner struct {
	Exec  extexec.Runner
	Allow AllowList
	Units UnitReloader
}

// Run runs each selected task once, in order, through the extexec contract.
// A task that is not allowed is not run and comes back as a Hold. A failed
// task never stops the others or the sync.
func (r *Runner) Run(ctx context.Context, ev Event, sel []Selected, req extexec.Request) ([]model.TaskResult, []model.Hold) {
	return nil, []model.Hold{{Reason: model.HoldTaskUntrusted, Detail: model.ErrNotImplemented.Error()}}
}

// Staged is one file about to be committed, as a check sees it.
type Staged struct {
	Target    model.Target
	Scope     model.Scope
	Plaintext []byte // written to a 0600 temp file for the check, removed afterwards
}

// Verdict is the commit gate's answer for one target.
type Verdict struct {
	Target model.Target `json:"target"`
	Check  string       `json:"check"`
	Pass   bool         `json:"pass"`
	Detail string       `json:"detail,omitempty"`
}

// Gate is the fail-closed commit gate. Every commit, manual or automatic,
// passes through it. A target fails when any matching check exits non-zero,
// times out, returns ok=false, or is not allowed on this machine.
type Gate interface {
	Check(ctx context.Context, staged []Staged, req extexec.Request) (pass []model.Target, holds []model.Hold, verdicts []Verdict)
}

// NewGate returns the gate for the checks a plan selected.
func NewGate(checks map[string]manifest.CheckDef, r extexec.Runner, allow AllowList) Gate {
	return gate{}
}

type gate struct{}

// Check holds everything until implemented: the gate fails closed.
func (gate) Check(_ context.Context, staged []Staged, _ extexec.Request) ([]model.Target, []model.Hold, []Verdict) {
	holds := make([]model.Hold, 0, len(staged))
	for _, s := range staged {
		holds = append(holds, model.Hold{Target: s.Target, Scope: s.Scope, Reason: model.HoldCheckFailed, Detail: model.ErrNotImplemented.Error()})
	}
	return nil, holds, nil
}
