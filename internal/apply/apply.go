package apply

import (
	"context"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/render"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
)

// StateSchema is the version of the state file.
const StateSchema = 1

// BackupRetention is how long replaced target bytes are kept.
const BackupRetention = 30 * 24 * time.Hour

// TargetState is what the tool knows about one target it manages.
type TargetState struct {
	Source     model.SourcePath `json:"source"`
	SourceBlob string           `json:"source_blob"` // source blob id at last apply or capture
	Scope      model.Scope      `json:"scope"`
	Written    string           `json:"written"` // hex SHA-256 of the bytes last written or adopted
	Size       int64            `json:"size"`
	ModTime    time.Time        `json:"mtime"`
	Mode       uint32           `json:"mode"`
	SealSet    []string         `json:"seal_set,omitempty"`    // key paths and region labels sealed at last apply
	LastRender string           `json:"last_render,omitempty"` // blob id of the last rendered bytes (templates)
	ChangedAt  time.Time        `json:"changed_at"`            // first time the current drift was seen
}

// State is the local state database for one machine. It never leaves the machine.
type State struct {
	Schema         int                           `json:"schema"`
	Machine        model.MachineID               `json:"machine"`
	Applied        model.CommitID                `json:"applied"`
	FirstApplyDone bool                          `json:"first_apply_done"`
	LastFullHash   time.Time                     `json:"last_full_hash"`
	Targets        map[model.Target]TargetState  `json:"targets"`
	Holds          []model.Hold                  `json:"holds"`
	Observed       map[string]model.ObservedFact `json:"observed,omitempty"`
	Tasks          map[string]model.TaskResult   `json:"tasks,omitempty"`
}

// StateDB loads and saves State atomically.
type StateDB interface {
	Load() (*State, error)
	Save(*State) error
}

// StateFile is the state database file in the state directory.
const StateFile = "state.json"

// FileStateDB returns the JSON-file StateDB in stateDir.
func FileStateDB(stateDir string) StateDB { return fileDB{dir: stateDir} }

type fileDB struct{ dir string }

func (fileDB) Load() (*State, error) { return nil, model.ErrNotImplemented }
func (fileDB) Save(*State) error     { return model.ErrNotImplemented }

// DriftKind classifies a difference between a target and the state.
type DriftKind string

// Drift kinds.
const (
	DriftModified DriftKind = "modified"
	DriftDeleted  DriftKind = "deleted"
	DriftNew      DriftKind = "new" // unmanaged file inside an owned root
	DriftMode     DriftKind = "mode"
)

// Drift is one target that differs from what the tool last wrote.
type Drift struct {
	Target model.Target `json:"target"`
	Kind   DriftKind    `json:"kind"`
	Scope  model.Scope  `json:"scope"`
	Since  time.Time    `json:"since"`
	Hash   string       `json:"hash,omitempty"`
}

// ScanOptions tunes Scan.
type ScanOptions struct {
	FullHash bool // ignore the stat cache
	Paths    []model.Target
}

// ActionKind is what apply will do to a target.
type ActionKind string

// Action kinds.
const (
	ActWrite  ActionKind = "write"
	ActDelete ActionKind = "delete" // target left the plan and is unchanged since written
	ActSkip   ActionKind = "skip"   // bytes already equal
	ActHold   ActionKind = "hold"
	ActAdopt  ActionKind = "adopt"  // adopt: identical bytes recorded, not written
	ActSealed ActionKind = "sealed" // non-member: sealed file not delivered
)

// Action is one planned step.
type Action struct {
	Target model.Target     `json:"target"`
	Kind   ActionKind       `json:"kind"`
	Source model.SourcePath `json:"source,omitempty"`
	Scope  model.Scope      `json:"scope"`
	Reason string           `json:"reason,omitempty"`
	Unit   *manifest.Unit   `json:"unit,omitempty"`
}

// ApplyOptions tunes Apply.
type ApplyOptions struct {
	DryRun bool
	Paths  []model.Target
}

// Result is the outcome of Apply or Adopt.
type Result struct {
	Commit  model.CommitID     `json:"commit"`
	Actions []Action           `json:"actions"`
	Holds   []model.Hold       `json:"holds"`
	Tasks   []model.TaskResult `json:"tasks,omitempty"`
}

// Capture is the outcome of capturing drift: source changes ready for a
// commit, and holds for what could not be captured.
type Capture struct {
	Changes []store.Change               `json:"-"`
	Paths   []model.Target               `json:"paths"`
	Scopes  map[model.Target]model.Scope `json:"scopes"`
	Holds   []model.Hold                 `json:"holds"`
}

// AdoptOptions tunes Adopt.
type AdoptOptions struct {
	DryRun     bool
	AllowTasks bool // allow every current task and collector definition
}

// Deps are the collaborators an Engine needs. cli wires them.
type Deps struct {
	Store    store.Store
	Manifest *manifest.Manifest
	Plan     *manifest.Plan
	Context  model.Context
	Keys     *crypt.Set
	Render   render.Engine
	State    StateDB
	Home     string
	StateDir string
	Tasks    *tasks.Runner
	Now      func() time.Time
}

// Engine runs apply, scan, capture and adopt.
type Engine struct{ Deps }

// New returns an Engine.
func New(d Deps) *Engine { return &Engine{Deps: d} }

// Scan finds drift between targets and the state.
func (e *Engine) Scan(ctx context.Context, opts ScanOptions) ([]Drift, error) {
	return nil, model.ErrNotImplemented
}

// Plan computes the actions apply would take for rev.
func (e *Engine) Plan(ctx context.Context, rev model.CommitID) ([]Action, error) {
	return nil, model.ErrNotImplemented
}

// Apply renders rev for this machine and writes changed targets, then runs
// triggered tasks (including unit reloads and, once, first-apply tasks).
func (e *Engine) Apply(ctx context.Context, rev model.CommitID, opts ApplyOptions) (Result, error) {
	return Result{}, model.ErrNotImplemented
}

// Capture turns drift into source changes, applying the round-trip check and
// the seal guard.
func (e *Engine) Capture(ctx context.Context, drift []Drift) (Capture, error) {
	return Capture{}, model.ErrNotImplemented
}

// Adopt takes over an existing $HOME: identical targets are recorded without
// writing, missing ones are written, differing ones are held.
func (e *Engine) Adopt(ctx context.Context, rev model.CommitID, opts AdoptOptions) (Result, error) {
	return Result{}, model.ErrNotImplemented
}

// RetagOptions describes a change of which machines get a target.
type RetagOptions struct {
	Types   []model.TypeName  // the target goes to machines with any of these types
	Enclave model.EnclaveName // seal for this enclave; empty stores plaintext
	DryRun  bool
}

// Retag builds one atomic source change for a target: the manifest entry's
// `when` and `enclave`, the move between files/ and sealed/<enclave>/ with
// the content opened and resealed, and nothing else. Only a member of every
// enclave involved can retag. The change is protected: it never auto-commits,
// and machines that lose the target remove it on their next apply (if it is
// unchanged there; a drifted copy is held).
func (e *Engine) Retag(ctx context.Context, t model.Target, opts RetagOptions) (Capture, error) {
	return Capture{}, model.ErrNotImplemented
}
