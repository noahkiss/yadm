package crypt

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"filippo.io/age"
	daead "github.com/tink-crypto/tink-go/v2/daead/subtle"

	"github.com/noahkiss/yadm/internal/model"
)

// Sizes and labels of the construction.
const (
	EpochKeySize = 32                  // random key per enclave per epoch
	SIVKeySize   = daead.AESSIVKeySize // 64: AES-SIV-CMAC-256 needs two 256-bit keys
	FileMagic    = "yadm-sealed\x00"   // whole-file container prefix
	FormatV1     = 1
	ValuePrefix  = "yadm:1:" // value token: yadm:1:<enclave>:<epoch>:<base64url>
	RegionPrefix = "yadm:sealed 1 "
)

// Purpose selects an HKDF subkey.
type Purpose string

// Subkey purposes.
const (
	PurposeFile   Purpose = "file"
	PurposeValue  Purpose = "value"
	PurposeRegion Purpose = "region"
	PurposeName   Purpose = "name" // reserved for HiddenNames
)

// Errors callers branch on.
var (
	ErrNotMember    = errors.New("this machine is not a member of the enclave")
	ErrBadSignature = errors.New("key log entry signature invalid or signer not a member")
	ErrBrokenChain  = errors.New("key log entry does not extend the pinned head")
	ErrUnknownEpoch = errors.New("ciphertext names an epoch this keyring does not hold")
	ErrNotSealed    = errors.New("input is not a sealed container")
	ErrAuthFailed   = errors.New("ciphertext failed authentication")
)

// Identity is a machine's key pair: an age X25519 identity for unwrapping and
// an Ed25519 key for signing key-log entries. Stored as two 0600 files in the
// state directory.
type Identity struct {
	Machine model.MachineID
	age     *age.X25519Identity
	sign    ed25519.PrivateKey
}

// Identity file names inside the state directory.
const (
	AgeIdentityFile = "identity.age.key"
	SigningKeyFile  = "identity.sign.key"
)

// GenerateIdentity creates a fresh identity for a machine.
func GenerateIdentity(m model.MachineID) (*Identity, error) { return nil, model.ErrNotImplemented }

// LoadIdentity reads the identity files; it refuses files readable by group or others.
func LoadIdentity(stateDir string) (*Identity, error) { return nil, model.ErrNotImplemented }

// Save writes the identity files with mode 0600.
func (id *Identity) Save(stateDir string) error { return model.ErrNotImplemented }

// Member returns the public half of the identity.
func (id *Identity) Member() Member { return Member{Machine: id.Machine} }

// Member is one key-log member: an age recipient and an Ed25519 public key.
type Member struct {
	Machine   model.MachineID `toml:"machine" json:"machine"`     // "recovery" for the recovery identity
	Recipient string          `toml:"recipient" json:"recipient"` // age1...
	SignKey   string          `toml:"sign_key" json:"sign_key"`   // base64 Ed25519 public key
}

// RecoveryMachine is the Member.Machine value of the recovery identity.
const RecoveryMachine model.MachineID = "recovery"

// Op is the kind of a key-log entry.
type Op string

// Key-log operations.
const (
	OpCreate  Op = "create"
	OpAdd     Op = "add"
	OpRemove  Op = "remove"  // always starts a new epoch
	OpRotate  Op = "rotate"  // new epoch, same members
	OpRecover Op = "recover" // signed by the recovery identity
)

// LogEntry is one file `keys/<enclave>/<seq>.toml` in the source tree.
type LogEntry struct {
	Enclave  model.EnclaveName `toml:"enclave" json:"enclave"`
	Seq      uint64            `toml:"seq" json:"seq"`
	Prev     string            `toml:"prev" json:"prev"` // hex SHA-256 of the previous entry's signed bytes; empty at seq 1
	Epoch    model.Epoch       `toml:"epoch" json:"epoch"`
	Op       Op                `toml:"op" json:"op"`
	Subject  model.MachineID   `toml:"subject" json:"subject,omitempty"` // machine added or removed
	Members  []Member          `toml:"members" json:"members"`
	Recovery Member            `toml:"recovery" json:"recovery"`
	Wrapped  model.Base64      `toml:"wrapped" json:"wrapped"` // age file: all epoch keys 1..Epoch
	Signer   model.MachineID   `toml:"signer" json:"signer"`
	Sig      model.Base64      `toml:"sig" json:"sig"` // Ed25519 over the canonical bytes with Sig empty
}

// LogDir returns the source directory of an enclave's key log.
func LogDir(e model.EnclaveName) model.SourcePath { return model.SourcePath("keys/" + string(e)) }

// LogPath returns the source path of one key-log entry: keys/<enclave>/<seq>.toml,
// with seq zero-padded to 6 digits so a directory listing sorts in order.
func LogPath(e model.EnclaveName, seq uint64) model.SourcePath {
	return model.SourcePath(fmt.Sprintf("keys/%s/%06d.toml", e, seq))
}

// ParseLogEntry decodes one entry file. It checks syntax only; VerifyLog checks trust.
func ParseLogEntry(b []byte) (LogEntry, error) { return LogEntry{}, model.ErrNotImplemented }

// MarshalLogEntry encodes an entry file.
func MarshalLogEntry(e LogEntry) ([]byte, error) { return nil, model.ErrNotImplemented }

// SignedBytes returns the canonical bytes an entry's signature and fingerprint
// cover: the entry encoded with Sig empty.
func SignedBytes(e LogEntry) ([]byte, error) { return nil, model.ErrNotImplemented }

// Pin is the key-log head a machine has verified. Stored in the state
// directory under pins/<enclave>. A new member gets its first pin from
// `yadm enclave join --expect <fingerprint>`, given to it out of band.
type Pin struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// PinStore keeps this machine's pins, one file per enclave under pins/ in the
// state directory.
type PinStore interface {
	Get(e model.EnclaveName) (*Pin, error) // nil, nil when the enclave is not pinned
	Set(e model.EnclaveName, p Pin) error
}

// FilePins returns the file-backed PinStore in stateDir.
func FilePins(stateDir string) PinStore { return filePins{dir: stateDir} }

type filePins struct{ dir string }

func (filePins) Get(model.EnclaveName) (*Pin, error) { return nil, model.ErrNotImplemented }
func (filePins) Set(model.EnclaveName, Pin) error    { return model.ErrNotImplemented }

// Fingerprint is the hex SHA-256 of an entry's signed bytes (its Prev link value).
func Fingerprint(e LogEntry) (string, error) { return "", model.ErrNotImplemented }

// VerifyLog checks the chain from the pin (or from seq 1 when pin is nil and
// the caller accepts trust on first use) to the last entry: Prev links, a
// valid signature by a member or the recovery identity of the previous entry,
// and epoch rules. It returns the verified head.
func VerifyLog(entries []LogEntry, pin *Pin) (LogEntry, error) {
	return LogEntry{}, model.ErrNotImplemented
}

// Keyring holds one enclave's epoch keys on a member machine.
type Keyring struct {
	Enclave model.EnclaveName
	Current model.Epoch
	keys    map[model.Epoch][]byte
}

// Create starts a new enclave at epoch 1 with the creator as the only member.
func Create(enclave model.EnclaveName, by *Identity, recovery Member) (LogEntry, *Keyring, error) {
	return LogEntry{}, nil, model.ErrNotImplemented
}

// Open unwraps a verified head entry with this machine's identity.
func Open(head LogEntry, id *Identity) (*Keyring, error) { return nil, model.ErrNotImplemented }

// Add appends an entry that wraps the existing epoch keys to one more member.
func (k *Keyring) Add(head LogEntry, m Member, by *Identity) (LogEntry, error) {
	return LogEntry{}, model.ErrNotImplemented
}

// Remove appends an entry with a new epoch key wrapped to the remaining
// members. The removed machine keeps every key up to the old epoch.
func (k *Keyring) Remove(head LogEntry, m model.MachineID, by *Identity) (LogEntry, *Keyring, error) {
	return LogEntry{}, nil, model.ErrNotImplemented
}

// Rotate appends an entry with a new epoch key and the same members.
func (k *Keyring) Rotate(head LogEntry, by *Identity) (LogEntry, *Keyring, error) {
	return LogEntry{}, nil, model.ErrNotImplemented
}

// Recover appends an entry signed by the recovery identity that sets a new
// member list and a new epoch. Use it when no member remains.
func Recover(head LogEntry, recovery *Identity, members []Member) (LogEntry, *Keyring, error) {
	return LogEntry{}, nil, model.ErrNotImplemented
}

// SealFile seals a whole file under the current epoch. AD is the container
// header (magic, version, enclave, epoch) plus the purpose; it carries no
// path, so a rename keeps the ciphertext.
func (k *Keyring) SealFile(plaintext []byte) ([]byte, error) { return nil, model.ErrNotImplemented }

// OpenFile opens a container sealed under any epoch this keyring holds.
func (k *Keyring) OpenFile(container []byte) ([]byte, error) { return nil, model.ErrNotImplemented }

// SealValue seals one structured value. AD binds the key path.
func (k *Keyring) SealValue(keyPath string, plaintext []byte) (string, error) {
	return "", model.ErrNotImplemented
}

// OpenValue opens a value token for a key path.
func (k *Keyring) OpenValue(keyPath, token string) ([]byte, error) {
	return nil, model.ErrNotImplemented
}

// SealRegion seals one text region body. AD binds the region label.
func (k *Keyring) SealRegion(label string, body []byte) (string, error) {
	return "", model.ErrNotImplemented
}

// OpenRegion opens a region token.
func (k *Keyring) OpenRegion(label, token string) ([]byte, error) {
	return nil, model.ErrNotImplemented
}

// Set is the keyrings this machine holds. It implements rules.Sealer.
type Set struct {
	Rings map[model.EnclaveName]*Keyring
}

// EnclaveLoad is the outcome of loading one enclave.
type EnclaveLoad struct {
	Head   LogEntry
	Member bool
	Err    error // verification failure: the enclave is refused and its files are not applied
}

// LoadSet verifies every enclave's key log against this machine's pins,
// opens the keyrings this machine is a member of, and advances pins to the
// verified heads. An enclave whose log fails verification is reported in the
// map and left out of the Set; other enclaves still load.
func LoadSet(logs map[model.EnclaveName][]LogEntry, pins PinStore, id *Identity) (*Set, map[model.EnclaveName]EnclaveLoad, error) {
	return nil, nil, model.ErrNotImplemented
}

// CanOpen reports whether this machine is a member of the enclave.
func (s *Set) CanOpen(e model.EnclaveName) bool { _, ok := s.Rings[e]; return ok }

// SealValue implements rules.Sealer.
func (s *Set) SealValue(e model.EnclaveName, keyPath string, pt []byte) (string, error) {
	r, ok := s.Rings[e]
	if !ok {
		return "", ErrNotMember
	}
	return r.SealValue(keyPath, pt)
}

// OpenValue implements rules.Sealer.
func (s *Set) OpenValue(e model.EnclaveName, keyPath, token string) ([]byte, error) {
	r, ok := s.Rings[e]
	if !ok {
		return nil, ErrNotMember
	}
	return r.OpenValue(keyPath, token)
}

// SealRegion implements rules.Sealer.
func (s *Set) SealRegion(e model.EnclaveName, label string, body []byte) (string, error) {
	r, ok := s.Rings[e]
	if !ok {
		return "", ErrNotMember
	}
	return r.SealRegion(label, body)
}

// OpenRegion implements rules.Sealer.
func (s *Set) OpenRegion(e model.EnclaveName, label, token string) ([]byte, error) {
	r, ok := s.Rings[e]
	if !ok {
		return nil, ErrNotMember
	}
	return r.OpenRegion(label, token)
}

// IsSealedFile reports whether b starts with the container magic.
func IsSealedFile(b []byte) bool {
	return len(b) >= len(FileMagic) && string(b[:len(FileMagic)]) == FileMagic
}

// ValueToken is a parsed value token.
type ValueToken struct {
	Enclave model.EnclaveName
	Epoch   model.Epoch
	Body    []byte
}

// ParseValueToken parses "yadm:1:<enclave>:<epoch>:<base64url>".
func ParseValueToken(s string) (ValueToken, bool) { return ValueToken{}, false }

// NameScheme maps a target to its stored name under sealed/<enclave>/.
type NameScheme interface {
	Stored(t model.Target) (string, error)
}

// PlainNames stores a sealed file under its real target path. It is the default.
type PlainNames struct{}

// Stored returns the target path unchanged.
func (PlainNames) Stored(t model.Target) (string, error) { return string(t), nil }

// HiddenNames stores a sealed file under base32(HMAC(name key, path)). It is
// reserved for types with hide_paths = true and is not built yet.
type HiddenNames struct{ Ring *Keyring }

// Stored is not implemented.
func (HiddenNames) Stored(model.Target) (string, error) { return "", model.ErrNotImplemented }
