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
//
// Exported API:
//
//	type Manifest struct{ Schema; Defaults; Entries ([[file]]); Roots ([[root]]); Tasks ([tasks.x]); Checks ([checks.x]); Units ([[unit]]); Protected }
//	type Entry struct{ Target, Source, When, Enclave, Template, Mode, Format, Keep, Drop, Seal, Regions, Quiet, Review }
//	type TaskDef struct{ On, OnRemove []string; FirstApply bool; When string; Command []string; Timeout model.Duration }
//	type CheckDef struct{ Paths []string; When string; Command []string; Timeout model.Duration }
//	type Unit struct{ Target model.Target; Kind UnitKind; When string }
//	func Parse(b []byte) (*Manifest, error)
//	func (m *Manifest) Resolve(ctx model.Context, tree []model.SourcePath, v cond.Vocabulary) (*Plan, error)
//	type Plan struct{ Targets map[model.Target]Resolved; Roots []Root; Tasks map[string]TaskDef; Checks map[string]CheckDef }
//	func (p *Plan) Why(t model.Target) (Explanation, error)
//	var BuiltinProtected []string
package manifest
