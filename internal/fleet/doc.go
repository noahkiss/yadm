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
//     machine's status ref. A member of an enclave opens the facts other
//     machines sealed for it (OpenAll, Visible) for read-only queries; a
//     non-member gets none.
//
// Exported API:
//
//	type File struct{ Schema int; Types map[model.TypeName]TypeDef; Machines map[model.MachineID]model.Machine; Collectors map[string]CollectorDef }
//	type TypeDef struct{ Enclave, HidePaths bool }
//	type CollectorDef struct{ Command []string; Timeout model.Duration; When string; Publish Publish }
//	type Publish struct{ Mode PublishMode; Enclave model.EnclaveName }  // TOML: "local" | "plain" | "sealed:<enclave>"
//	func Parse(b []byte) (*File, error)
//	func (f *File) Lookup(nameOrNickOrID string) (model.Machine, error)
//	func (f *File) Vocabulary() cond.Vocabulary
//	func (f *File) Enclaves() []model.EnclaveName
//	type Identity struct{ Machine model.MachineID; Remote string; Notify, Busy []string }
//	func LoadIdentity(path string) (Identity, error)
//	func SaveIdentity(path string, id Identity) error
//	func NewMachineID() (model.MachineID, error)
//	func Collect(ctx, f *File, mctx model.Context, r extexec.Runner, allowed func(string, CollectorDef) bool) (facts map[string]model.ObservedFact, skipped []string, err error)
//	func CollectWith(ctx, f, mctx, r, allowed, base extexec.Request) (...) // base carries source and commit
//	func Published(f *File, facts map[string]model.ObservedFact, s FactSealer) (plain map[string]model.ObservedFact, sealed map[model.EnclaveName][]byte, problems []error)
//	func OpenSealed(st model.Status, e model.EnclaveName, o FactOpener) (map[string]model.ObservedFact, error)
//	func OpenAll(f *File, st model.Status, o FactOpener) (map[model.EnclaveName]map[string]model.ObservedFact, []error)
//	func Visible(f *File, st model.Status, o FactOpener, opened map[model.EnclaveName]map[string]model.ObservedFact) map[string]model.ObservedFact
//	func WithVisible(f *File, statuses map[model.MachineID]model.Status, o FactOpener) (map[model.MachineID]model.Status, []error)
//	type StatusRefs interface{ ReadAll(ctx) (map[model.MachineID]model.Status, error); Publish(ctx, model.Status) error }
//	func NewMemoryStatusRefs(self model.MachineID, seed map[model.MachineID]model.Status) *MemoryStatusRefs
//	func StatusRef(id model.MachineID) string
//	func PublishDue(last *model.Status, changed bool, at time.Time) bool
//	func List(f *File, statuses map[model.MachineID]model.Status, at time.Time) []Summary
//	func DiffObserved(statuses map[model.MachineID]model.Status, collector string) (ObservedDiff, error)
package fleet
