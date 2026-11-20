package sync

import (
	"context"
	"errors"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
)

// Defaults.
const (
	DefaultQuiet      = 2 * time.Hour
	DefaultMaxRetries = 5
	DefaultMassChange = 50 // more changed files than this in one scope are held
	LockFile          = "lock"
	LeaseDir          = "leases"
)

// ErrLocked means another sync holds the lock.
var ErrLocked = errors.New("another yadm process holds the lock")

// Options tunes one sync.
type Options struct {
	Auto       bool // timer run: auto-commit by policy; otherwise commit nothing
	Push       bool
	DryRun     bool
	MaxRetries int
}

// Report is the outcome of one sync.
type Report struct {
	Captured  []model.Target     `json:"captured"`
	Committed []model.CommitID   `json:"committed"`
	Fetched   model.CommitID     `json:"fetched"`
	Replayed  int                `json:"replayed"`
	Applied   model.CommitID     `json:"applied"`
	Pushed    bool               `json:"pushed"`
	Retries   int                `json:"retries"`
	Holds     []model.Hold       `json:"holds"`
	Alerts    []Alert            `json:"alerts,omitempty"`
	Tasks     []model.TaskResult `json:"tasks,omitempty"`
}

// Alert is an event sent through the notify hook.
type Alert struct {
	Kind    string          `json:"kind"` // "non_member_enclave_commit", "held", "task_failed", ...
	Commit  model.CommitID  `json:"commit,omitempty"`
	Machine model.MachineID `json:"machine,omitempty"`
	Detail  string          `json:"detail"`
}

// Lock is the exclusive sync lock.
type Lock interface {
	Acquire(ctx context.Context) (release func(), err error)
}

// FileLock returns the flock-based lock in stateDir.
func FileLock(stateDir string) Lock { return fileLock{dir: stateDir} }

type fileLock struct{ dir string }

func (fileLock) Acquire(context.Context) (func(), error) { return nil, model.ErrNotImplemented }

// Lease marks paths an agent session is editing; auto-commit skips them.
type Lease struct {
	Holder  string    `json:"holder"`
	Paths   []string  `json:"paths"` // globs relative to $HOME
	Expires time.Time `json:"expires"`
}

// Leases stores leases in the state directory.
type Leases interface {
	List() ([]Lease, error)
	Take(Lease) error
	Release(holder string) error
}

// Policy is the auto-commit policy.
type Policy struct {
	Quiet      time.Duration
	MassChange int
	Protected  []string // built-in plus manifest globs
}

// PlannedCommit is one auto-commit to make.
type PlannedCommit struct {
	Scope   model.Scope
	Changes []store.Change
	Message store.Message
}

// PlanCommits splits captured changes into per-scope commits and holds.
func PlanCommits(c apply.Capture, st *apply.State, p Policy, leases []Lease, self model.MachineID, now time.Time) ([]PlannedCommit, []model.Hold, error) {
	return nil, nil, model.ErrNotImplemented
}

// FileLeases returns the Leases stored under LeaseDir in stateDir.
func FileLeases(stateDir string) Leases { return fileLeases{dir: stateDir} }

type fileLeases struct{ dir string }

func (fileLeases) List() ([]Lease, error) { return nil, model.ErrNotImplemented }
func (fileLeases) Take(Lease) error       { return model.ErrNotImplemented }
func (fileLeases) Release(string) error   { return model.ErrNotImplemented }

// Deps are the collaborators a Syncer needs.
type Deps struct {
	Store    store.Store
	Apply    *apply.Engine
	Fleet    *fleet.File
	Status   fleet.StatusRefs
	Keys     *crypt.Set
	Exec     extexec.Runner
	Identity fleet.Identity
	Gate     tasks.Gate
	Lock     Lock
	Leases   Leases
	Policy   Policy
	Version  string
	Now      func() time.Time
}

// Syncer runs the sync loop.
type Syncer struct{ Deps }

// Run performs one sync.
func (s *Syncer) Run(ctx context.Context, opts Options) (Report, error) {
	return Report{}, model.ErrNotImplemented
}

// CommitOptions tunes a manual commit.
type CommitOptions struct {
	Message string
	Paths   []model.Target // empty means every captured, unheld path
	DryRun  bool
}

// Commit makes a manual commit: capture, gate, one commit per scope through a
// fresh private index. It bypasses the quiet period and leases but never the
// gate or the seal guard. Protected paths need to be named in Paths.
func (s *Syncer) Commit(ctx context.Context, opts CommitOptions) (Report, error) {
	return Report{}, model.ErrNotImplemented
}

// LockTimeout bounds how long any command waits for the lock before failing
// with ErrLocked. Commands never wait without a bound.
const LockTimeout = 30 * time.Second

// ReviewItem is one unreviewed commit with its plaintext diff (members only
// see plaintext for enclave scopes).
type ReviewItem struct {
	Commit store.Commit `json:"commit"`
	Scope  model.Scope  `json:"scope"`
	Diff   string       `json:"diff"`
}

// Unreviewed lists commits in RefReviewed(scope)..main that touch scope.
func Unreviewed(ctx context.Context, st store.Store, keys *crypt.Set, scope model.Scope) ([]ReviewItem, error) {
	return nil, model.ErrNotImplemented
}

// Ack fast-forwards the reviewed ref for scope to upTo. It refuses a non-ancestor.
func Ack(ctx context.Context, st store.Store, scope model.Scope, upTo model.CommitID) error {
	return model.ErrNotImplemented
}
