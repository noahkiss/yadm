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
	ErrInvalidLog   = errors.New("key log entry breaks a structural rule")
	ErrNotPinned    = errors.New("this machine is listed as a member but has not pinned the enclave's key log")
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

// MemPins returns an in-memory PinStore, for tests and for a write whose pin
// is not kept.
func MemPins() PinStore { return memPins{} }

type memPins map[model.EnclaveName]Pin

func (m memPins) Get(e model.EnclaveName) (*Pin, error) {
	p, ok := m[e]
	if !ok {
		return nil, nil
	}
	return &p, nil
}

func (m memPins) Set(e model.EnclaveName, p Pin) error { m[e] = p; return nil }

// Keyring holds one enclave's epoch keys on a member machine.
type Keyring struct {
	Enclave model.EnclaveName
	Current model.Epoch
	keys    map[model.Epoch][]byte
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

// CanOpen reports whether this machine is a member of the enclave.
func (s *Set) CanOpen(e model.EnclaveName) bool {
	if s == nil {
		return false
	}
	_, ok := s.Rings[e]
	return ok
}

// SealValue implements rules.Sealer.
func (s *Set) SealValue(e model.EnclaveName, keyPath string, pt []byte) (string, error) {
	r, ok := s.ring(e)
	if !ok {
		return "", ErrNotMember
	}
	return r.SealValue(keyPath, pt)
}

// OpenValue implements rules.Sealer.
func (s *Set) OpenValue(e model.EnclaveName, keyPath, token string) ([]byte, error) {
	r, ok := s.ring(e)
	if !ok {
		return nil, ErrNotMember
	}
	return r.OpenValue(keyPath, token)
}

// SealRegion implements rules.Sealer.
func (s *Set) SealRegion(e model.EnclaveName, label string, body []byte) (string, error) {
	r, ok := s.ring(e)
	if !ok {
		return "", ErrNotMember
	}
	return r.SealRegion(label, body)
}

// OpenRegion implements rules.Sealer.
func (s *Set) OpenRegion(e model.EnclaveName, label, token string) ([]byte, error) {
	r, ok := s.ring(e)
	if !ok {
		return nil, ErrNotMember
	}
	return r.OpenRegion(label, token)
}

func (s *Set) ring(e model.EnclaveName) (*Keyring, bool) {
	if s == nil {
		return nil, false
	}
	r, ok := s.Rings[e]
	return r, ok && r != nil
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
