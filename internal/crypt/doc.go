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
//     previous entry; the recovery identity signs only recover and
//     set-recovery. A machine pins the head it last verified and accepts only
//     signed descendants of that pin. An unsigned entry, or one signed by a
//     non-member, is rejected. A member write needs the head to be its pin.
//   - Commitments: each entry carries a hash (KeyCommit) of every epoch key and
//     keeps the previous entry's list; Open checks the unwrapped keys against
//     it. A signed min_epoch, raised only by a retire entry, is the lowest
//     epoch a keyring opens for delivery. Set.Strict opens only the current
//     epoch, for content new to this machine; Set.History opens every epoch,
//     for bytes that are never delivered.
//   - Binding: a whole file's AD holds its source path; a value's or region's
//     AD holds PartName(source path, concrete key path or label).
//
// Exported API:
//
//	type Identity                       // a machine's age X25519 + Ed25519 key pair
//	func GenerateIdentity(m model.MachineID) (*Identity, error)
//	func LoadIdentity(stateDir string) (*Identity, error)
//	func (*Identity) Save(stateDir string) error
//	func (*Identity) Member() Member
//	func (*Identity) SignStatement(kind string, body []byte) ([]byte, error) // domain-separated from key-log signatures
//	func VerifyStatement(m Member, kind string, body, sig []byte) error // ErrBadStatement
//	type Member struct{ Machine model.MachineID; Recipient, SignKey string }
//	type LogEntry struct{ Enclave; Seq; Prev; Epoch; MinEpoch; Op; Subject; Members; Recovery; KeyCommits; Wrapped; Signer; Sig }
//	const OpCreate, OpAdd, OpRemove, OpRotate, OpRetire, OpRecover, OpSetRecovery Op
//	func KeyCommit(e, epoch, key []byte) string
//	func CheckLogAppendOnly(old, next []LogEntry) error // ErrRewritten; sync runs it on every fetched commit
//	func ParseLogPath(p model.SourcePath) (model.EnclaveName, uint64, bool)
//	func LogDir(e) model.SourcePath; func LogPath(e, seq) model.SourcePath
//	func ParseLogEntry(b []byte) (LogEntry, error); func MarshalLogEntry(LogEntry) ([]byte, error); func SignedBytes(LogEntry) ([]byte, error)
//	type Pin struct{ Seq uint64; Hash string }
//	type PinStore interface{ Get(e) (*Pin, error); Set(e, Pin) error }; func FilePins(stateDir string) PinStore; func MemPins() PinStore
//	func Fingerprint(e LogEntry) (string, error); func PinOf(e LogEntry) (Pin, error)
//	func VerifyLog(entries []LogEntry, pin *Pin) (head LogEntry, err error)
//	func Join(entries []LogEntry, expect string, pins PinStore) (head LogEntry, err error) // enclave join --expect
//	func JoinCode(fingerprint string) (string, error) // XXXX-XXXX: argon2id over the fingerprint, Crockford base32
//	func ParseJoinCode(s string) (string, error)      // normalize a typed code
//	func JoinWithCode(entries []LogEntry, code string, self model.MachineID, pins PinStore) (head LogEntry, err error) // enclave join --code
//	func SetJoinCodeCostForTest(JoinCodeCost) (restore func()) // test hook only
//	// Every write takes the signer's PinStore and pins the entry it writes.
//	func Create(enclave, by *Identity, recovery Member, pins PinStore) (LogEntry, *Keyring, error)
//	func (*Keyring) Add(head LogEntry, m Member, by *Identity, pins PinStore) (LogEntry, error)
//	func (*Keyring) Remove(head LogEntry, m model.MachineID, by *Identity, pins PinStore) (LogEntry, *Keyring, error) // new epoch
//	func (*Keyring) Rotate(head LogEntry, by *Identity, pins PinStore) (LogEntry, *Keyring, error) // new epoch
//	func (*Keyring) Retire(head LogEntry, by *Identity, pins PinStore) (LogEntry, error) // min_epoch = epoch, after the reseal
//	func Recover(head LogEntry, recovery *Identity, members []Member, pins PinStore) (LogEntry, *Keyring, error)
//	func SetRecovery(head LogEntry, recovery *Identity, to Member, pins PinStore) (LogEntry, error)
//	func Open(head LogEntry, id *Identity) (*Keyring, error)
//	func LoadSet(logs map[model.EnclaveName][]LogEntry, pins PinStore, id *Identity) (*Set, map[model.EnclaveName]EnclaveLoad, error)
//	type Keyring                        // one enclave's epoch keys
//	func (*Keyring) SealFile(path, pt) / OpenFile(path, ct) / SealValue / OpenValue / SealRegion / OpenRegion
//	func PartName(source model.SourcePath, keyOrLabel string) string
//	type Set                            // keyrings this machine holds; implements rules.Sealer
//	func (s *Set) SealFile(e, path, plaintext) ([]byte, error); func (s *Set) OpenFile(e, path, container) ([]byte, error)
//	func (s *Set) Strict() *Set; func (s *Set) History() *Set; func (s *Set) Only(keep func(e) bool) *Set
//	func IsSealedFile(b []byte) bool; func FileEpoch(b []byte) (model.EnclaveName, model.Epoch, bool); func ParseValueToken(s string) (ValueToken, bool)
//	type NameScheme interface{ Stored(t model.Target) (string, error) }
//	type PlainNames struct{}; type HiddenNames struct{}  // HiddenNames is a reserved stub
package crypt
