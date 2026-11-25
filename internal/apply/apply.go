package apply

import (
	"context"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/render"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// StateSchema is the version of the state file.
const StateSchema = 1

// BackupRetention is how long replaced target bytes are kept.
const BackupRetention = 30 * 24 * time.Hour

// FullHashInterval is the longest time between two full hash passes of Scan.
const FullHashInterval = 24 * time.Hour

// Default bounds for filesystem access, so a slow or dead mount never hangs a command.
const (
	DefaultStatTimeout = 2 * time.Second  // one stat or one read of a target
	DefaultScanBudget  = 60 * time.Second // a whole Scan, owned roots included
)

// TargetState is what the tool knows about one target it manages.
type TargetState struct {
	Source     model.SourcePath `json:"source"`
	SourceBlob string           `json:"source_blob"` // source blob id at last apply or capture
	Scope      model.Scope      `json:"scope"`
	Written    string           `json:"written"` // hex SHA-256 of the bytes last written or adopted
	Size       int64            `json:"size"`
	ModTime    time.Time        `json:"mtime"`
	Mode       uint32           `json:"mode"` // live mode at last record (stat cache)
	// Want is the mode the entry asked for at last record. A live mode that
	// grants a subset of it, or adds only group write the group may read
	// (ModeAccepted), is not drift. Zero in an older state: Mode stands for it.
	Want    uint32   `json:"want,omitempty"`
	SealSet []string `json:"seal_set,omitempty"` // key paths and region labels sealed at last apply
	// The protection recorded at last apply: whole-file enclave, sealed keys
	// with their enclaves, regions. Apply and capture hold the target when
	// the manifest weakens it, until the change is allowed locally.
	Enclave model.EnclaveName            `json:"enclave,omitempty"`
	Seal    map[string]model.EnclaveName `json:"seal,omitempty"`
	Regions bool                         `json:"regions,omitempty"`
	// The machine-local key paths recorded at last apply: keep (the keys
	// the repo owns), drop and volatile. A manifest that removes or widens
	// them would make capture commit keys that stayed on this machine.
	Keep     []string `json:"keep,omitempty"`
	Drop     []string `json:"drop,omitempty"`
	Volatile []string `json:"volatile,omitempty"`
	// ExplicitMode is the entry's explicit `mode` at last apply, 0 when the
	// mode followed the source. A manifest may not widen it on a file with
	// enclave plaintext without a local allow.
	ExplicitMode uint32 `json:"explicit_mode,omitempty"`
	RenderHash   string `json:"render_hash,omitempty"` // templates: hex SHA-256 of the last rendered bytes; the bytes are recomputed, never stored
	// ApplyKey fingerprints what apply computed the target from, besides
	// the source blob: the resolved entry and, for a template, the render
	// inputs. Apply skips an unchanged target only while it matches.
	ApplyKey  string    `json:"apply_key,omitempty"`
	ChangedAt time.Time `json:"changed_at"` // first time the current drift was seen
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
	RenderContext  *model.Context                `json:"render_context,omitempty"` // the Context of the last apply, to recompute last renders
	Roots          []manifest.Root               `json:"roots,omitempty"`          // accepted owned roots; Scan and capture read only these
	Seen           map[model.Target]time.Time    `json:"seen,omitempty"`           // first sighting of each new file in an owned root
	// Baseline lists files that were in an owned root when it was accepted,
	// or stayed on disk when they left management. They are never reported
	// as new or captured automatically.
	Baseline map[model.Target]time.Time `json:"baseline,omitempty"`
	// Ignored lists unmanaged files the user left untracked on purpose
	// (`yadm hold ignore`). Scan never reports them; naming one in a
	// commit tracks it and drops it from this list.
	Ignored map[model.Target]time.Time `json:"ignored,omitempty"`
	// TaskInputs records, per task, the fingerprints (hashes, never
	// values) of the on_fact and on_render inputs it last ran against.
	TaskInputs map[string]map[string]string `json:"task_inputs,omitempty"`
	// Outputs holds the task `outputs` globs of the last applied
	// manifest. Scan never reports a file that matches one.
	Outputs []string `json:"outputs,omitempty"`
	// Floors holds, per target, the protection a fetched commit tried to
	// take from it (Floor). The target stays as it is here until allowed
	// or restored.
	Floors map[model.Target]Floor `json:"floors,omitempty"`
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

// DriftKind classifies a difference between a target and the state.
type DriftKind string

// Drift kinds.
const (
	DriftModified   DriftKind = "modified"
	DriftDeleted    DriftKind = "deleted"
	DriftNew        DriftKind = "new" // unmanaged file inside an owned root
	DriftMode       DriftKind = "mode"
	DriftUnreadable DriftKind = "unreadable" // stat or read failed or timed out; nothing is known
)

// Drift is one target that differs from what the tool last wrote.
type Drift struct {
	Target model.Target `json:"target"`
	Kind   DriftKind    `json:"kind"`
	Scope  model.Scope  `json:"scope"`
	Since  time.Time    `json:"since"`
	Hash   string       `json:"hash,omitempty"`
	Detail string       `json:"detail,omitempty"`
	// Baseline marks a new file that was in its owned root when the root
	// was accepted here. Capture skips it unless Named.
	Baseline bool `json:"baseline,omitempty"`
	// Named is set when ScanOptions.Paths named the file: the caller asked
	// for it by name, so capture takes a baseline file too.
	Named bool `json:"-"`
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

// Result is the outcome of Apply, Adopt or ResolveHold.
type Result struct {
	Commit  model.CommitID     `json:"commit"`
	Actions []Action           `json:"actions"`
	Holds   []model.Hold       `json:"holds"`
	Tasks   []model.TaskResult `json:"tasks,omitempty"`
	// Capture carries source changes when ResolveHold takes the target. The
	// caller commits them through the gate; apply never commits.
	Capture *Capture `json:"-"`
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

// Snapshot is everything resolved at one source commit for this machine.
// The fleet, manifest and key logs are read from that commit, so a sync that
// fetches a new manifest loads a new Snapshot.
type Snapshot struct {
	Commit   model.CommitID
	Fleet    *fleet.File
	Manifest *manifest.Manifest
	Plan     *manifest.Plan
	Context  model.Context
	// Keys are the keys delivery may use: every enclave this machine
	// opens, except the on-demand ones.
	Keys *crypt.Set
	// ReadKeys are all the keys this machine holds, on-demand enclaves
	// included. Only paths that print to stdout or write ciphertext
	// (review, hold show, show, notes, key-log writes) use them, through
	// Readable.
	ReadKeys *crypt.Set
	// OnDemand holds the enclaves this machine reads on demand only.
	OnDemand map[model.EnclaveName]bool
	Enclaves map[model.EnclaveName]crypt.EnclaveLoad
	Render   render.Engine
	// Crypto seals and opens for this machine. Load sets it from Keys; nil
	// means this machine opens no enclave.
	Crypto Crypto
	// Tree maps each source path at Commit to its blob id and git mode.
	Tree map[model.SourcePath]store.TreeEntry
}

// Crypto is what apply needs from the enclave keys: the rules.Sealer for
// values and regions, plus whole-file sealing. SetCrypto adapts a crypt.Set.
type Crypto interface {
	rules.Sealer
	SealFile(e model.EnclaveName, path model.SourcePath, plaintext []byte) ([]byte, error)
	OpenFile(e model.EnclaveName, path model.SourcePath, container []byte) ([]byte, error)
}

// cryptoViews is what a Crypto offers when it can restrict the epochs it
// opens: Strict opens only each enclave's current epoch, History every
// epoch it holds. SetCrypto implements it; a Crypto without it opens the
// same way in every view.
type cryptoViews interface {
	Strict() Crypto
	History() Crypto
}

// SetCrypto adapts a crypt.Set to Crypto. A nil set opens nothing.
func SetCrypto(s *crypt.Set) Crypto {
	if s == nil {
		s = &crypt.Set{}
	}
	return setCrypto{s}
}

type setCrypto struct{ *crypt.Set }

func (s setCrypto) Strict() Crypto  { return setCrypto{s.Set.Strict()} }
func (s setCrypto) History() Crypto { return setCrypto{s.Set.History()} }

// Rules is the intra-file rules engine. The default is package rules.
type Rules interface {
	ToTarget(source, live []byte, spec rules.Spec, s rules.Sealer) ([]byte, error)
	ToSource(target, prevSource []byte, spec rules.Spec, s rules.Sealer) ([]byte, []rules.Violation, error)
	Reseal(source []byte, spec rules.Spec, e model.EnclaveName, s rules.Sealer) ([]byte, error)
}

type pkgRules struct{}

func (pkgRules) ToTarget(source, live []byte, spec rules.Spec, s rules.Sealer) ([]byte, error) {
	return rules.ToTarget(source, live, spec, s)
}

func (pkgRules) ToSource(target, prev []byte, spec rules.Spec, s rules.Sealer) ([]byte, []rules.Violation, error) {
	return rules.ToSource(target, prev, spec, s)
}

func (pkgRules) Reseal(src []byte, spec rules.Spec, e model.EnclaveName, s rules.Sealer) ([]byte, error) {
	return rules.Reseal(src, spec, e, s)
}

// Text is the in-process merge and template patcher. The default is package textmerge.
type Text interface {
	Merge3(base, ours, theirs []byte) ([]byte, []textmerge.Region, error)
	PatchTemplate(tmpl, lastRender, target []byte) ([]byte, error)
}

type pkgText struct{}

func (pkgText) Merge3(b, o, t []byte) ([]byte, []textmerge.Region, error) {
	return textmerge.Merge3(b, o, t)
}

func (pkgText) PatchTemplate(tmpl, last, target []byte) ([]byte, error) {
	return textmerge.PatchTemplate(tmpl, last, target)
}

// Deps are the collaborators an Engine needs. cli wires them.
type Deps struct {
	Store    store.Store
	Self     model.MachineID
	Identity *crypt.Identity
	Pins     crypt.PinStore
	State    StateDB
	Home     string
	User     string
	StateDir string
	Tasks    *tasks.Runner
	Now      func() time.Time
	// Allow is the local allow list for weakened protections and owned
	// roots. Nil falls back to Tasks.Allow; with neither, nothing is allowed.
	Allow tasks.AllowList
	// OnDemand names the enclaves this machine reads on demand only
	// (machine.toml on_demand). Load leaves their keys out of Keys and
	// Crypto, so apply, capture and backups treat them as a non-member does.
	OnDemand []model.EnclaveName

	// Optional. Zero values pick the defaults.
	LoadSnapshot func(ctx context.Context, rev model.CommitID) (*Snapshot, error) // replaces Load (tests, bisect sandboxes)
	Rules        Rules                                                            // default: package rules
	Text         Text                                                             // default: package textmerge
	StatTimeout  time.Duration                                                    // default DefaultStatTimeout
	ScanBudget   time.Duration                                                    // default DefaultScanBudget
}

// Engine runs apply, scan, capture and adopt.
type Engine struct {
	Deps
	fs fsys
}

// New returns an Engine.
func New(d Deps) *Engine {
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Rules == nil {
		d.Rules = pkgRules{}
	}
	if d.Text == nil {
		d.Text = pkgText{}
	}
	if d.StatTimeout <= 0 {
		d.StatTimeout = DefaultStatTimeout
	}
	if d.ScanBudget <= 0 {
		d.ScanBudget = DefaultScanBudget
	}
	return &Engine{Deps: d, fs: osFS{}}
}

// RetagOptions describes a change of which machines get a target.
type RetagOptions struct {
	Types   []model.TypeName  // the target goes to machines with any of these types
	Enclave model.EnclaveName // seal for this enclave; empty stores plaintext
	Source  model.SourcePath  // picks one of several entries for the target by its source
	DryRun  bool
}

// TrackOptions says which machines a tracked file goes to.
type TrackOptions struct {
	When    string            // condition for the new entry; empty means every machine
	Enclave model.EnclaveName // seal for this enclave; empty stores plaintext
	// Variant adds one more entry for a target that entries already name,
	// with the variant name before the source's extension; When is then
	// required and must apply on this machine.
	Variant string
}

// ResolveOptions says how to resolve a hold.
type ResolveOptions struct {
	Take string // "source", "target", or a path to a file with the merged content
}
