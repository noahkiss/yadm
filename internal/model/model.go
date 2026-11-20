package model

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrNotImplemented is returned by every stub. The CLI maps it to its own exit code.
var ErrNotImplemented = errors.New("not implemented")

// MachineID is the stable, random identifier of a machine. It never is a hostname.
type MachineID string

// TypeName is a user-defined machine type from the fleet file. No type name is
// built into the tool.
type TypeName string

// EnclaveName names an enclave. An enclave is a type whose fleet entry sets
// enclave = true, so an EnclaveName is always also a TypeName.
type EnclaveName string

// Scope is the review and commit scope of a file: ScopeShared or an enclave name.
type Scope string

// ScopeShared is the scope of plaintext files every machine may read.
const ScopeShared Scope = "shared"

// Target is a slash-separated path relative to $HOME, for example ".config/app/settings.json".
type Target string

// SourcePath is a slash-separated path relative to the root of the source clone,
// for example "files/.zshrc" or "sealed/personal/.ssh/config".
type SourcePath string

// CommitID is a full hexadecimal git object id.
type CommitID string

// Epoch numbers the generations of one enclave's key. It starts at 1.
type Epoch uint32

// Machine is one registry entry from the fleet file.
type Machine struct {
	ID        MachineID         `json:"id"`
	Name      string            `json:"name"`
	Nicknames []string          `json:"nicknames,omitempty"`
	Types     []TypeName        `json:"types"`
	OS        string            `json:"os"`
	Arch      string            `json:"arch"`
	Facts     map[string]string `json:"facts,omitempty"` // declared facts
}

// HasType reports whether the machine declares the type.
func (m Machine) HasType(t TypeName) bool {
	for _, x := range m.Types {
		if x == t {
			return true
		}
	}
	return false
}

// ObservedFact is the normalized output of one collector on one machine.
// Items holds line output (trimmed, sorted, unique). Data holds a collector's
// JSON object when it returns one.
type ObservedFact struct {
	Collector   string          `json:"collector"`
	Items       []string        `json:"items,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
	CollectedAt time.Time       `json:"collected_at"`
	Error       string          `json:"error,omitempty"`
}

// Context is the whole input a render or a rule evaluation may read. It holds
// only this machine's own data, so a render is a pure function of the source
// commit and the Context.
type Context struct {
	Machine  Machine                 `json:"machine"`
	Home     string                  `json:"home"`
	User     string                  `json:"user"`
	Observed map[string]ObservedFact `json:"observed,omitempty"`
}

// HoldReason says why a file is held.
type HoldReason string

// Hold reasons. A held file is neither applied nor committed until resolved.
const (
	HoldDrifted       HoldReason = "drifted"        // target changed and apply would overwrite it
	HoldUncapturable  HoldReason = "uncapturable"   // capture failed the round-trip check
	HoldConflict      HoldReason = "conflict"       // replay produced a content conflict
	HoldProtected     HoldReason = "protected"      // path is on the never-auto-commit list
	HoldSecretScan    HoldReason = "secret_scan"    // capture found a secret-looking value outside a seal
	HoldSealGuard     HoldReason = "seal_guard"     // capture would drop or unseal a sealed part
	HoldSourceDirty   HoldReason = "source_dirty"   // the source clone's worktree has local edits
	HoldTaskUntrusted HoldReason = "task_untrusted" // a task, check or collector definition changed and is not allowed here
	HoldCheckFailed   HoldReason = "check_failed"   // a commit-gate check failed or timed out
	HoldRenderedEdit  HoldReason = "rendered_edit"  // a hand edit to a rendered target could not be captured into its template
)

// Hold is one file, or one task, the tool refuses to move. Its JSON shape is
// a stable contract for external resolvers (agents): fields are only added,
// never renamed or removed, within a schema version.
type Hold struct {
	ID     string     `json:"id"` // stable: hex SHA-256 of reason, target or task, and Since
	Target Target     `json:"target,omitempty"`
	Task   string     `json:"task,omitempty"`
	Scope  Scope      `json:"scope"`
	Reason HoldReason `json:"reason"`
	Since  time.Time  `json:"since"`
	Detail string     `json:"detail,omitempty"`
	// Conflict detail: blob ids of the three sides, readable with `yadm hold show <id>`.
	Base   string   `json:"base,omitempty"`
	Ours   string   `json:"ours,omitempty"`
	Theirs string   `json:"theirs,omitempty"`
	Next   []string `json:"next,omitempty"` // suggested commands, such as "yadm hold resolve <id> --take source"
}

// TaskResult records one run of an on-change task.
type TaskResult struct {
	Task     string        `json:"task"`
	Trigger  string        `json:"trigger"` // "paths", "remove", "first-apply" or "unit"
	Commit   CommitID      `json:"commit"`
	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration_ns"`
	ExitCode int           `json:"exit_code"`
	Error    string        `json:"error,omitempty"`
}

// StatusSchema is the version of the Status record.
const StatusSchema = 1

// Status is the record a machine publishes in its own status ref after a sync
// that changed something, and at least hourly.
type Status struct {
	Schema     int                     `json:"schema"`
	Machine    MachineID               `json:"machine"`
	Version    string                  `json:"version"`
	Applied    CommitID                `json:"applied"`
	LastSync   time.Time               `json:"last_sync"`
	Pending    int                     `json:"pending"`
	Held       int                     `json:"held"`
	Conflicts  int                     `json:"conflicts"`
	OldestHeld *time.Time              `json:"oldest_held,omitempty"`
	Epochs     map[EnclaveName]Epoch   `json:"epochs,omitempty"`
	Observed   map[string]ObservedFact `json:"observed,omitempty"` // only collectors with publish = "plain"
	Sealed     map[EnclaveName][]byte  `json:"sealed,omitempty"`   // sealed observed facts, per enclave
	Tasks      []TaskResult            `json:"tasks,omitempty"`    // last result per task
}
