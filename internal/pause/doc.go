// Package pause holds sync fleet-wide for a bounded time (docs/design.md
// section 10.1).
//
// A pause is a signed record on the ref Ref: a chain of commits whose tree
// holds one `<id>.json` per pause, the latest record of that pause. Sync
// fetches it with the other refs/yadm/* refs. It never enters main, so it
// never auto-commits, is never applied and passes no commit gate.
//
// Trust. A record counts when it is well formed and its signer is a
// machine in fleet.toml (Trust). It is verified when the signer is a member
// of the head of a key log this machine pinned and its Ed25519 signature
// verifies (crypt.VerifyStatement, kind "pause"); a signature that fails
// under such a key is forged and the record does not count. Unverified
// records count unless fleet.toml sets pause_requires = "member". A pause
// record must be signed by its initiator; a resume by any fleet machine; an
// unverified record never extends a verified pause. A record that does not
// count is kept in View.Ignored for `yadm check`. Read bounds what it takes
// from the ref and never fails a sync over it.
//
// Local state is the authority. Evaluate merges every record it reads into
// StateFile: the first time this machine saw each pause, the latest signed
// deadline, and whether a signed resume lifted it. A ref that a writer
// rewinds, deletes or fills with garbage changes nothing already accepted. A
// pause holds until
//
//	min(signed deadline, created + MaxSpan,
//	    first seen here + min(deadline - created, MaxSpan), end of the hold run)
//
// by this machine's own clock, so a lost initiator never wedges the fleet
// and a machine offline for the whole window sees an expired record and
// ignores it. A lifted pause stays lifted, so a replayed pause record does
// not freeze a machine again; a shorter deadline for a known pause is
// ignored. A pause first seen while another holds this machine ends with
// that hold run, so chained pauses hold at most MaxSpan in a row. While a
// machine runs its own pause, only an earlier pause holds it.
//
// Exported API:
//
//	const Ref, RemoteRef, StateFile, Kind, Schema; const MaxSpan, DefaultFor
//	type Op string; const OpPause, OpResume
//	type Record struct{ Schema; Op; ID; Initiator; Reason; Created; Deadline; Signer; Sig }
//	func NewID() (string, error)
//	func (r Record) SignedBytes() ([]byte, error)
//	func Sign(r Record, id *crypt.Identity) (Record, error)
//	type Trust struct{ Fleet; Members; RequireMember }; var ErrForged
//	func NewTrust(fleet []model.MachineID, loads map[model.EnclaveName]crypt.EnclaveLoad, pins crypt.PinStore, requireMember bool) Trust
//	func (t Trust) Verify(r Record) (verified bool, err error) // ErrUntrusted, ErrForged, ErrMalformed
//	func (t Trust) Can(m model.MachineID, signKey string) bool
//	type Active struct{ ID; Initiator; Reason; Created; Until; Requested; Clamped; Verified }
//	type Ignored struct{ ID; Signer; Why }
//	type View struct{ Active []Active; Ignored []Ignored; Lifted []string }
//	func (v View) Holding(self model.MachineID) *Active // the pause that holds self, if any
//	func (v View) Find(id string) *Active
//	func Read(ctx, st store.Store) ([]Record, []Ignored, error) // records on Ref and RemoteRef
//	func Evaluate(ctx, st store.Store, stateDir string, self model.MachineID, trust Trust, now time.Time, save bool) (View, error)
//	func HeldUntil(stateDir string) time.Time // the deadline the last Evaluate held this machine to
//	func Write(ctx, st store.Store, recs []Record, now time.Time) (model.CommitID, error) // commit on RemoteRef, set Ref
//	func Restage(ctx, st store.Store, now time.Time) error // carry unpushed records onto a moved RemoteRef
//	func Spec(ctx, st store.Store) (string, error) // the refspec when Ref is ahead of RemoteRef
//	type HeldError struct{ Active Active; Self model.MachineID; Name string }; var ErrHeld
package pause
