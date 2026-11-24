// Package pause holds sync fleet-wide for a bounded time (docs/design.md
// section 10.1).
//
// A pause is a signed record on the ref Ref: a chain of commits whose tree
// holds one `<id>.json` per pause, the latest record of that pause. Sync
// fetches it with the other refs/yadm/* refs. It never enters main, so it
// never auto-commits, is never applied and passes no commit gate.
//
// Trust. A record counts only when its signer is a member of the head of a
// key log this machine has pinned (TrustedSigners) and its Ed25519
// signature verifies (crypt.VerifyStatement, kind "pause"). A pause record
// must be signed by its initiator; a resume by any trusted signer. An
// unsigned, badly signed or untrusted record is ignored and kept in
// View.Ignored for `yadm check`.
//
// Local state is the authority. Evaluate merges every record it reads into
// StateFile: the first time this machine saw each pause, the latest signed
// deadline, and whether a signed resume lifted it. A ref that a writer
// rewinds, deletes or fills with garbage changes nothing already accepted. A
// pause holds until
//
//	min(signed deadline, created + MaxSpan, first seen here + MaxSpan)
//
// by this machine's own clock, so a lost initiator never wedges the fleet
// and a machine offline for the whole window sees an expired record and
// ignores it. A lifted pause stays lifted, so a replayed pause record does
// not freeze a machine again; a shorter deadline for a known pause is
// ignored.
//
// Exported API:
//
//	const Ref, RemoteRef, StateFile, Kind, Schema; const MaxSpan, DefaultFor
//	type Op string; const OpPause, OpResume
//	type Record struct{ Schema; Op; ID; Initiator; Reason; Created; Deadline; Signer; Sig }
//	func NewID() (string, error)
//	func (r Record) SignedBytes() ([]byte, error)
//	func Sign(r Record, id *crypt.Identity) (Record, error)
//	type Signers map[model.MachineID][]crypt.Member
//	func TrustedSigners(loads map[model.EnclaveName]crypt.EnclaveLoad, pins crypt.PinStore) Signers
//	func (s Signers) Verify(r Record) error // ErrUntrusted, crypt.ErrBadStatement, ErrMalformed
//	type Active struct{ ID; Initiator; Reason; Created; Until; Requested; Clamped }
//	type Ignored struct{ ID; Signer; Why }
//	type View struct{ Active []Active; Ignored []Ignored; Lifted []string }
//	func (v View) Holding(self model.MachineID) *Active // the pause that holds self, if any
//	func (v View) Find(id string) *Active
//	func Read(ctx, st store.Store) ([]Record, []Ignored, error) // records on Ref and RemoteRef
//	func Evaluate(ctx, st store.Store, stateDir string, self model.MachineID, signers Signers, now time.Time, save bool) (View, error)
//	func HeldUntil(stateDir string) time.Time // the deadline the last Evaluate held this machine to
//	func Write(ctx, st store.Store, recs []Record, now time.Time) (model.CommitID, error) // commit on RemoteRef, set Ref
//	func Spec(ctx, st store.Store) (string, error) // the refspec when Ref is ahead of RemoteRef
//	type HeldError struct{ Active Active; Self model.MachineID; Name string }; var ErrHeld
package pause
