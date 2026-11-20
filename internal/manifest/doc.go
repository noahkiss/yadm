// Package manifest decides which file goes where. It parses `manifest.toml`
// at the source root and resolves it, for one machine Context, into a Plan: a
// map from each target path to the one entry that produces it.
//
// The manifest also declares owned roots (where new files are noticed),
// on-change tasks, units and the never-auto-commit list. Package tasks runs
// the tasks; this package only parses and selects them.
//
// Resolution rules:
//
//   - An entry applies when its `when` condition (package cond) is true.
//   - Two applying entries for one target are an error ("collision"), reported
//     by `yadm check` and by every command that resolves.
//   - An entry without `source` reads `files/<target>`, or
//     `sealed/<enclave>/<target>` when it sets `enclave`.
//   - Glob entries (`target = ".config/tool/**"`) expand against the source tree.
//     The glob's fixed prefix maps to `files/<prefix>`, `sealed/<enclave>/<prefix>`
//     or the entry's `source` directory. `**` matches zero or more segments.
//   - There is no precedence: an explicit entry does not override a glob, and
//     order does not break ties. Variants need mutually exclusive `when`s.
//   - Resolve checks every condition and enclave name against the fleet,
//     including entries that do not apply on this machine.
//   - A unit attaches to its target only when the target is in the plan.
//
// Parse is strict: unknown keys, unknown enum values, unsafe paths, sources
// outside `files/` or the entry's own `sealed/<enclave>/`, and rule options
// that do not fit the format are errors. Parse fills the defaults (quiet 2m,
// task timeout 5m, check timeout 30s).
//
// Exported API:
//
//	type Manifest struct{ Schema; Defaults; Entries ([[file]]); Roots ([[root]]); Tasks ([tasks.x]); Checks ([checks.x]); Units ([[unit]]); Protected }
//	type Entry struct{ Target, Source, When, Enclave, Template, Mode, Format, Keep, Drop, Seal, Regions, Quiet, Review, Merge, Volatile }
//	type Root struct{ Path model.Target; When string; Enclave model.EnclaveName; Ignore []string }
//	type MergePolicy string // text, union, add-only, ours, theirs, generated, json-keys, toml-keys, structural
//	func (r Root) Ignored(t model.Target) bool
//	type TaskDef struct{ On, OnRemove []string; FirstApply bool; When string; Command []string; Timeout model.Duration }
//	type CheckDef struct{ Paths []string; When string; Command []string; Timeout model.Duration }
//	type Unit struct{ Target model.Target; Kind UnitKind; When string; Reload UnitReload } // reload: "" or auto, never
//	func Parse(b []byte) (*Manifest, error)
//	func (m *Manifest) Resolve(ctx model.Context, tree []model.SourcePath, v cond.Vocabulary) (*Plan, error)
//	type Plan struct{ Targets map[model.Target]Resolved; Roots []Root; Tasks map[string]TaskDef; Checks map[string]CheckDef }
//	func (m *Manifest) Validate(v cond.Vocabulary) error
//	func (m *Manifest) Quiet(e Entry) model.Duration
//	type CollisionError struct{ Collisions []Collision }
//	func (r Resolved) FileMode(sourceExecutable bool) fs.FileMode
//	func (p *Plan) Why(t model.Target) (Explanation, error)
//	func (p *Plan) Protected(t model.Target) bool
//	func (p *Plan) Root(t model.Target) *Root
//	func Expand(e Entry, tree []model.SourcePath) []Resolved // every (target, source) pair of an entry
//	func Match(pattern, name string) bool
//	func ValidPattern(pattern string) error
//	func IsGlob(s string) bool
//	var BuiltinProtected []string
package manifest
