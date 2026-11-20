package manifest

import (
	"io/fs"
	"strings"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
)

// FileName is the manifest's path at the source root.
const FileName = "manifest.toml"

// Schema is the manifest format version.
const Schema = 1

// Format names a structured format for intra-file rules.
type Format string

// Formats. FormatWhole means no intra-file rules: the file moves as bytes.
const (
	FormatWhole Format = ""
	FormatJSON  Format = "json"
	FormatJSONC Format = "jsonc"
	FormatTOML  Format = "toml"
	FormatText  Format = "text" // marked regions only
)

// Defaults apply to every entry that does not override them.
type Defaults struct {
	Quiet model.Duration `toml:"quiet" json:"quiet"` // auto-commit quiet period; default 2m
}

// Entry maps one target (or a glob of targets) to its source and rules.
type Entry struct {
	Target   model.Target                 `toml:"target" json:"target"`
	Source   model.SourcePath             `toml:"source" json:"source,omitempty"`
	When     string                       `toml:"when" json:"when,omitempty"`
	Enclave  model.EnclaveName            `toml:"enclave" json:"enclave,omitempty"`   // whole file sealed for this enclave
	Template bool                         `toml:"template" json:"template,omitempty"` // render with package render
	Mode     fs.FileMode                  `toml:"mode" json:"mode,omitempty"`         // 0 means 0644 (0755 if the source is executable), sealed or not
	Format   Format                       `toml:"format" json:"format,omitempty"`
	Keep     []string                     `toml:"keep" json:"keep,omitempty"`         // key paths the repo owns; others belong to the app
	Drop     []string                     `toml:"drop" json:"drop,omitempty"`         // key paths never captured
	Seal     map[string]model.EnclaveName `toml:"seal" json:"seal,omitempty"`         // key path -> enclave
	Regions  bool                         `toml:"regions" json:"regions,omitempty"`   // honour `yadm:seal` region markers
	Quiet    *model.Duration              `toml:"quiet" json:"quiet,omitempty"`       // override Defaults.Quiet; 0 commits at once
	Review   bool                         `toml:"review" json:"review,omitempty"`     // never auto-commit; always held for a manual commit
	Merge    MergePolicy                  `toml:"merge" json:"merge,omitempty"`       // how a sync conflict resolves; "" means text
	Volatile []string                     `toml:"volatile" json:"volatile,omitempty"` // key paths that stay machine-local in a merge
}

// MergePolicy says how a sync conflict on an entry's targets resolves.
type MergePolicy string

// Merge policies (design section 10).
const (
	MergeText       MergePolicy = "text"       // key-level merge for json, jsonc and toml, else a line merge
	MergeUnion      MergePolicy = "union"      // line sets: union of additions, minus removals
	MergeAddOnly    MergePolicy = "add-only"   // lines only ever added; a modify or delete holds
	MergeOurs       MergePolicy = "ours"       // take this machine's side
	MergeTheirs     MergePolicy = "theirs"     // take the remote side
	MergeGenerated  MergePolicy = "generated"  // a tool writes it: never auto-committed; conflicts take the remote side
	MergeJSONKeys   MergePolicy = "json-keys"  // key-level merge as JSON; a failure holds
	MergeTOMLKeys   MergePolicy = "toml-keys"  // key-level merge as TOML; a failure holds
	MergeStructural MergePolicy = "structural" // key-level merge in the entry's format; a failure holds
)

// Scope returns the entry's commit and review scope.
func (e Entry) Scope() model.Scope {
	if e.Enclave != "" {
		return model.Scope(e.Enclave)
	}
	return model.ScopeShared
}

// Root is an owned root: a directory where a new, unmanaged file is reported.
type Root struct {
	Path    model.Target      `toml:"path" json:"path"`
	When    string            `toml:"when" json:"when,omitempty"`
	Enclave model.EnclaveName `toml:"enclave" json:"enclave,omitempty"` // new files here are captured sealed
	Ignore  []string          `toml:"ignore" json:"ignore,omitempty"`   // globs, relative to Path, of files left untracked on purpose
}

// Ignored reports whether t, a path inside the root, matches one of its
// ignore globs. An ignored file is never reported as new.
func (r Root) Ignored(t model.Target) bool {
	rel, ok := strings.CutPrefix(string(t), string(r.Path)+"/")
	if !ok {
		return false
	}
	for _, g := range r.Ignore {
		if Match(g, rel) {
			return true
		}
	}
	return false
}

// TaskDef declares an on-change task. It triggers when an apply changes a
// target matching any `On` glob, or on this machine's first apply when
// FirstApply is set. The core knows no package manager: a bootstrap step is
// a task with FirstApply.
type TaskDef struct {
	On         []string       `toml:"on" json:"on,omitempty"`               // a matching target was written
	OnRemove   []string       `toml:"on_remove" json:"on_remove,omitempty"` // a matching target was removed
	FirstApply bool           `toml:"first_apply" json:"first_apply,omitempty"`
	When       string         `toml:"when" json:"when,omitempty"`
	Command    []string       `toml:"command" json:"command"`
	Timeout    model.Duration `toml:"timeout" json:"timeout"` // default 5m
	// OnFact runs the task when one of these inputs changes on this
	// machine: a collector name (its observed items) or "fact:KEY" (a
	// declared fact).
	OnFact []string `toml:"on_fact" json:"on_fact,omitempty"`
	// OnRender runs the task when the render context changes: this
	// machine's types, declared facts and observed facts, or the fleet.
	OnRender bool `toml:"on_render" json:"on_render,omitempty"`
	// Outputs are target globs the task writes. They are generated: never
	// captured or committed, never gated, and shown by status as
	// generated. A managed target may not match one.
	Outputs []string `toml:"outputs" json:"outputs,omitempty"`
}

// CheckDef declares a commit-gate check. Before every commit, manual or
// automatic, each check whose Paths match a staged target runs through the
// extexec contract with the staged targets in the request. A failure or a
// timeout holds the matching files (fail closed); other files still commit.
type CheckDef struct {
	Paths   []string       `toml:"paths" json:"paths"` // globs over targets; empty means every target
	When    string         `toml:"when" json:"when,omitempty"`
	Command []string       `toml:"command" json:"command"`
	Timeout model.Duration `toml:"timeout" json:"timeout"` // default 30s
}

// UnitKind is a service manager.
type UnitKind string

// Unit kinds the built-in reload task handles.
const (
	UnitLaunchd UnitKind = "launchd"
	UnitSystemd UnitKind = "systemd"
)

// Unit marks a target as a service unit. Apply copies it like any file; the
// built-in unit task reloads it only when its bytes changed.
type Unit struct {
	Target model.Target `toml:"target" json:"target"`
	Kind   UnitKind     `toml:"kind" json:"kind"`
	When   string       `toml:"when" json:"when,omitempty"`
	Reload UnitReload   `toml:"reload" json:"reload,omitempty"` // "" means auto
}

// UnitReload says whether the built-in unit task reloads a unit.
type UnitReload string

// Unit reload modes.
const (
	// ReloadAuto reloads on a byte change. The launchd reloader still
	// skips a KeepAlive job and the job running the reload.
	ReloadAuto UnitReload = "auto"
	// ReloadNever never reloads; the new bytes take effect at the next login.
	ReloadNever UnitReload = "never"
)

// Manifest is the parsed manifest file.
type Manifest struct {
	Schema    int                 `toml:"schema" json:"schema"`
	Defaults  Defaults            `toml:"defaults" json:"defaults"`
	Entries   []Entry             `toml:"file" json:"files"`
	Roots     []Root              `toml:"root" json:"roots,omitempty"`
	Tasks     map[string]TaskDef  `toml:"tasks" json:"tasks,omitempty"`
	Checks    map[string]CheckDef `toml:"checks" json:"checks,omitempty"`
	Units     []Unit              `toml:"unit" json:"units,omitempty"`
	Protected []string            `toml:"protected" json:"protected,omitempty"` // extra never-auto-commit globs
	// Conditions is the raw `[conditions]` table: named conditions and
	// `include`. Parse turns it into Definitions and Includes.
	Conditions map[string]any `toml:"conditions" json:"-"`

	named namedConds
}

// Resolved is one target's winning entry.
type Resolved struct {
	Target model.Target     `json:"target"`
	Source model.SourcePath `json:"source"`
	Entry  Entry            `json:"entry"`
	Index  int              `json:"index"` // position of the entry in Manifest.Entries
	Unit   *Unit            `json:"unit,omitempty"`
}

// Plan is the resolved manifest for one machine.
type Plan struct {
	Targets map[model.Target]Resolved
	Roots   []Root
	Tasks   map[string]TaskDef  // only tasks whose `when` matched
	Checks  map[string]CheckDef // only checks whose `when` matched

	m     *Manifest
	cands [][]candidate // per entry: what it would produce
	conds []cond.Expr   // per entry: its parsed `when`
	apply []bool        // per entry: its `when` is true here
}

// Explanation answers `yadm why <path>`.
type Explanation struct {
	Target    model.Target `json:"target"`
	Managed   bool         `json:"managed"`
	Resolved  *Resolved    `json:"resolved,omitempty"`
	Rejected  []Rejection  `json:"rejected,omitempty"` // entries that named the target but did not apply
	Protected bool         `json:"protected"`
	InRoot    *Root        `json:"in_root,omitempty"`
	// WhenExpanded is the winning entry's `when` with every `cond:NAME`
	// inlined. It is set only when the `when` names a condition.
	WhenExpanded string `json:"when_expanded,omitempty"`
}

// Rejection says why one entry did not apply.
type Rejection struct {
	Index  int    `json:"index"`
	When   string `json:"when"`
	Reason string `json:"reason"`
	// Expanded is When with every `cond:NAME` inlined, set only when When
	// names a condition.
	Expanded string `json:"expanded,omitempty"`
}

// BuiltinProtected lists the paths that never auto-commit, whatever the manifest says.
var BuiltinProtected = []string{FileName, "fleet.toml", "keys/**"}
