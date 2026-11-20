// Package crypt owns enclave secrecy: machine identities, the signed key log
// per enclave, epoch keys, and deterministic sealing of whole files, values and
// text regions. Nothing here is a git filter; the tool seals and opens in
// memory, and plaintext is written only to a member's $HOME or to stdout.
//
// Construction (docs/design.md has the full rationale):
//
//   - Cipher: AES-SIV (RFC 5297, 512-bit key) from tink-go daead/subtle.
//     Deterministic: equal plaintext and AD give equal ciphertext, so an
//     unchanged file reseals to the same blob and two machines that capture the
//     same edit converge.
//   - Keys: one random 256-bit key per enclave per epoch. Subkeys come from
//     HKDF-SHA256 with info "yadm v1 <purpose> <enclave>", purpose in
//     {file, value, region, name}.
//   - Wrapping: every key-log entry carries all epoch keys so far, age-encrypted
//     (X25519) to each member's recipient plus the recovery recipient.
//   - Authentication: every key-log entry is signed (Ed25519) by a member of the
//     previous entry, or by the recovery identity. A machine pins the head it
//     last verified and accepts only signed descendants of that pin. An unsigned
//     entry, or one signed by a non-member, is rejected.
//
// Exported API:
//
//	type Identity                       // a machine's age X25519 + Ed25519 key pair
//	func GenerateIdentity(m model.MachineID) (*Identity, error)
//	func LoadIdentity(stateDir string) (*Identity, error)
//	func (*Identity) Save(stateDir string) error
//	func (*Identity) Member() Member
//	type Member struct{ Machine model.MachineID; Recipient, SignKey string }
//	type LogEntry struct{ Enclave; Seq; Prev; Epoch; Op; Members; Recovery; Wrapped; Signer; Sig }
//	func LogDir(e) model.SourcePath; func LogPath(e, seq) model.SourcePath
//	func ParseLogEntry(b []byte) (LogEntry, error); func MarshalLogEntry(LogEntry) ([]byte, error); func SignedBytes(LogEntry) ([]byte, error)
//	type Pin struct{ Seq uint64; Hash string }
//	type PinStore interface{ Get(e) (*Pin, error); Set(e, Pin) error }; func FilePins(stateDir string) PinStore
//	func Fingerprint(e LogEntry) (string, error)
//	func VerifyLog(entries []LogEntry, pin *Pin) (head LogEntry, err error)
//	func Create(enclave, by *Identity, recovery Member) (LogEntry, *Keyring, error)
//	func (*Keyring) Add(head LogEntry, m Member, by *Identity) (LogEntry, error)
//	func (*Keyring) Remove(head LogEntry, m model.MachineID, by *Identity) (LogEntry, *Keyring, error) // new epoch
//	func (*Keyring) Rotate(head LogEntry, by *Identity) (LogEntry, *Keyring, error) // new epoch
//	func Recover(head LogEntry, recovery *Identity, members []Member) (LogEntry, *Keyring, error)
//	func Open(head LogEntry, id *Identity) (*Keyring, error)
//	func LoadSet(logs map[model.EnclaveName][]LogEntry, pins PinStore, id *Identity) (*Set, map[model.EnclaveName]EnclaveLoad, error)
//	type Keyring                        // one enclave's epoch keys
//	func (*Keyring) SealFile / OpenFile / SealValue / OpenValue / SealRegion / OpenRegion
//	type Set                            // keyrings this machine holds; implements rules.Sealer
//	func IsSealedFile(b []byte) bool; func ParseValueToken(s string) (ValueToken, bool)
//	type NameScheme interface{ Stored(t model.Target) (string, error) }
//	type PlainNames struct{}; type HiddenNames struct{}  // HiddenNames is a reserved stub
package crypt
