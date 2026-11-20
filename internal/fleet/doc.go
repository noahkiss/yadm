// Package fleet owns the machine registry: the tracked fleet file, this
// machine's local identity, observed-fact collectors, and the per-machine
// status refs that `yadm fleet` reads.
//
// The fleet file (`fleet.toml` at the source root) declares user-defined
// types, machines with declared facts, and collectors. The tool hard-codes no
// type name. The fleet file is display and routing data only: it never grants
// enclave membership. The enclave key log in package crypt is the authority,
// and `yadm check` reports any mismatch between the two.
//
// Facts come in two kinds:
//
//   - Declared facts: `[machines.<id>.facts]` in the fleet file.
//   - Observed facts: each collector runs on every machine its `when` matches,
//     on sync, through the extexec contract with a timeout. Its normalized
//     output is stored locally and, per the collector's publish mode, in the
//     machine's status ref. Templates and conditions read only this machine's
//     observed facts, from local state, so a render never depends on another
//     machine's status ref.
//
// Exported API:
//
//	type File struct{ Schema int; Types map[model.TypeName]TypeDef; Machines map[model.MachineID]model.Machine; Collectors map[string]CollectorDef }
//	type TypeDef struct{ Enclave, HidePaths bool }
//	type CollectorDef struct{ Command []string; Timeout time.Duration; When string; Publish Publish }
//	type Publish struct{ Mode PublishMode; Enclave model.EnclaveName }
//	func Parse(b []byte) (*File, error)
//	func (f *File) Lookup(nameOrNickOrID string) (model.Machine, error)
//	func (f *File) Vocabulary() cond.Vocabulary
//	func (f *File) Enclaves() []model.EnclaveName
//	type Identity struct{ Machine model.MachineID; Remote string; Notify, Busy []string }
//	func LoadIdentity(path string) (Identity, error)
//	func Collect(ctx, f *File, mctx model.Context, r extexec.Runner, allowed func(string, CollectorDef) bool) (facts map[string]model.ObservedFact, skipped []string, err error)
//	type StatusRefs interface{ ReadAll(ctx) (map[model.MachineID]model.Status, error); Publish(ctx, model.Status) error }
//	func StatusRef(id model.MachineID) string
//	func DiffObserved(statuses map[model.MachineID]model.Status, collector string) ObservedDiff
package fleet
