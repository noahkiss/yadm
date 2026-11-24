// Package reroot announces a deliberate rewrite of the shared history
// (docs/design.md section 10.2): a force-push of a purged or squashed main.
//
// A re-root is a signed record on the ref Ref, a chain of commits whose
// tree holds one `<id>.json` per re-root, like the pause ref. It names the
// old and the new remote main. Sync fetches it with the other refs/yadm/*
// refs; it never enters main.
//
// Trust mirrors a fleet pause (package pause), with one difference: a
// re-root replaces history, so only a verified record counts. Verify
// accepts a record only when its signer is its initiator, a machine in
// fleet.toml, and a member of a key log this machine pinned, and the
// Ed25519 signature (crypt.VerifyStatement, kind "reroot") verifies under
// that member's key. Read bounds what it takes from the ref and never
// fails a sync over it. Write keeps the newest records only.
//
// Local state (StateFile) records when this machine joined and the
// re-roots it switched to; a record not newer than both is a replay.
// Backups are git bundles of the old history in BackupDir, beside the
// source clone, named by time and old head; List and Prune manage them.
//
// Exported API:
//
//	const Ref, RemoteRef, StateFile, Kind, Schema, DefaultKeep
//	type Record struct{ Schema; ID; Initiator; Reason; Created; OldHead; NewHead; PauseID; Signer; Sig }
//	func NewID() (string, error); func (Record) SignedBytes() ([]byte, error)
//	func Sign(r Record, id *crypt.Identity) (Record, error)
//	func Verify(t pause.Trust, r Record) error // ErrMalformed, ErrUntrusted, ErrUnverified, ErrForged
//	type Ignored struct{ ID; Signer; Why }
//	func Read(ctx, st store.Store) ([]Record, []Ignored, error) // newest first
//	func Write(ctx, st store.Store, rec Record) (prev, next model.CommitID, err error)
//	func Unwrite(ctx, st store.Store, prev, next model.CommitID) error
//	type Accepted struct{ ID; By; OldHead; NewHead; Created; At; Backup; Carried }
//	type Local struct{ Since; Accepted []Accepted }; func (Local) Last() *Accepted
//	func Load(stateDir string) Local; func RecordAccepted(stateDir string, a Accepted) error
//	func SeedSince(stateDir string, at time.Time) error // init; never replaces a time
//	func BackupDir(source string) string; func BundleName(at time.Time, old model.CommitID) string
//	type Bundle struct{ Path; Name; Taken; OldHead; Size }
//	func List(dir string) ([]Bundle, error); func Prune(dir string, keep int, pin ...string) ([]Bundle, error); func EnsureDir(dir string) error
package reroot
