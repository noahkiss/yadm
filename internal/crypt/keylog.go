package crypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/model"
)

// ParseLogEntry decodes one entry file. It checks syntax only; VerifyLog checks trust.
func ParseLogEntry(b []byte) (LogEntry, error) {
	var e LogEntry
	d := toml.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return LogEntry{}, fmt.Errorf("%w: %v", ErrInvalidLog, err)
	}
	return e, nil
}

// MarshalLogEntry encodes an entry file.
//
// The encoding is this package's own, not a TOML library's, because it is
// also the canonical form that signatures and fingerprints cover: a library
// upgrade must not change it. Every field is always written, in a fixed order.
func MarshalLogEntry(e LogEntry) ([]byte, error) {
	var b bytes.Buffer
	str := func(k, v string) error {
		q, err := tomlString(v)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		fmt.Fprintf(&b, "%s = %s\n", k, q)
		return nil
	}
	member := func(m Member) (string, error) {
		var parts [3]string
		for i, v := range []string{string(m.Machine), m.Recipient, m.SignKey} {
			q, err := tomlString(v)
			if err != nil {
				return "", err
			}
			parts[i] = q
		}
		return fmt.Sprintf("{ machine = %s, recipient = %s, sign_key = %s }", parts[0], parts[1], parts[2]), nil
	}
	if err := str("enclave", string(e.Enclave)); err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "seq = %d\n", e.Seq)
	if err := str("prev", e.Prev); err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "epoch = %d\n", e.Epoch)
	if err := str("op", string(e.Op)); err != nil {
		return nil, err
	}
	if err := str("subject", string(e.Subject)); err != nil {
		return nil, err
	}
	if len(e.Members) == 0 {
		b.WriteString("members = []\n")
	} else {
		b.WriteString("members = [\n")
		for _, m := range e.Members {
			s, err := member(m)
			if err != nil {
				return nil, fmt.Errorf("members: %w", err)
			}
			b.WriteString("  " + s + ",\n")
		}
		b.WriteString("]\n")
	}
	rs, err := member(e.Recovery)
	if err != nil {
		return nil, fmt.Errorf("recovery: %w", err)
	}
	b.WriteString("recovery = " + rs + "\n")
	fmt.Fprintf(&b, "wrapped = %q\n", base64.StdEncoding.EncodeToString(e.Wrapped))
	if err := str("signer", string(e.Signer)); err != nil {
		return nil, err
	}
	fmt.Fprintf(&b, "sig = %q\n", base64.StdEncoding.EncodeToString(e.Sig))
	return b.Bytes(), nil
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", errors.New("string is not valid UTF-8")
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// SignedBytes returns the canonical bytes an entry's signature and fingerprint
// cover: the entry encoded with Sig empty.
func SignedBytes(e LogEntry) ([]byte, error) {
	e.Sig = nil
	return MarshalLogEntry(e)
}

// Fingerprint is the hex SHA-256 of an entry's signed bytes (its Prev link value).
func Fingerprint(e LogEntry) (string, error) {
	b, err := SignedBytes(e)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// PinOf returns the pin that names entry e.
func PinOf(e LogEntry) (Pin, error) {
	fp, err := Fingerprint(e)
	if err != nil {
		return Pin{}, err
	}
	return Pin{Seq: e.Seq, Hash: fp}, nil
}

// VerifyLog checks the chain from the pin (or from seq 1 when pin is nil and
// the caller accepts trust on first use) to the last entry: Prev links, a
// valid signature by a member or the recovery identity of the previous entry,
// and epoch rules. It returns the verified head.
//
// The whole chain is always checked from entry 1; the pin adds the demand that
// the entry at pin.Seq is exactly the pinned one, so a replayed, truncated or
// forked log fails with ErrBrokenChain.
//
// Beyond the epoch rules, each op must change membership only as it says:
// add appends exactly its subject, remove drops exactly its subject, rotate
// keeps the members, and only recover (signed by the recovery identity) may
// set an arbitrary member list. No entry may change the recovery identity.
func VerifyLog(entries []LogEntry, pin *Pin) (LogEntry, error) {
	if len(entries) == 0 {
		return LogEntry{}, fmt.Errorf("%w: empty key log", ErrInvalidLog)
	}
	fps := make([]string, len(entries))
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			return LogEntry{}, fmt.Errorf("%w: entry %d has seq %d", ErrBrokenChain, i+1, e.Seq)
		}
		if e.Enclave != entries[0].Enclave {
			return LogEntry{}, fmt.Errorf("%w: entry %d names enclave %q", ErrInvalidLog, e.Seq, e.Enclave)
		}
		if err := checkShape(e); err != nil {
			return LogEntry{}, err
		}
		var err error
		if i == 0 {
			err = verifyFirst(e)
		} else {
			err = verifyNext(entries[i-1], fps[i-1], e)
		}
		if err != nil {
			return LogEntry{}, err
		}
		if fps[i], err = Fingerprint(e); err != nil {
			return LogEntry{}, err
		}
	}
	if pin != nil {
		if pin.Seq == 0 || pin.Seq > uint64(len(entries)) {
			return LogEntry{}, fmt.Errorf("%w: pinned seq %d is not in a log of %d entries", ErrBrokenChain, pin.Seq, len(entries))
		}
		if fps[pin.Seq-1] != pin.Hash {
			return LogEntry{}, fmt.Errorf("%w: entry %d differs from the pinned one", ErrBrokenChain, pin.Seq)
		}
	}
	return entries[len(entries)-1], nil
}

// checkShape validates one entry on its own: names, keys and the recovery member.
func checkShape(e LogEntry) error {
	if err := checkEnclaveName(e.Enclave); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidLog, err)
	}
	if e.Epoch == 0 {
		return fmt.Errorf("%w: entry %d has epoch 0", ErrInvalidLog, e.Seq)
	}
	if len(e.Members) == 0 {
		return fmt.Errorf("%w: entry %d has no members", ErrInvalidLog, e.Seq)
	}
	seen := map[model.MachineID]bool{}
	for _, m := range e.Members {
		if m.Machine == RecoveryMachine || checkMachineID(m.Machine) != nil {
			return fmt.Errorf("%w: entry %d has a member named %q", ErrInvalidLog, e.Seq, m.Machine)
		}
		if seen[m.Machine] {
			return fmt.Errorf("%w: entry %d lists %s twice", ErrInvalidLog, e.Seq, m.Machine)
		}
		seen[m.Machine] = true
		if _, err := m.publicKey(); err != nil {
			return err
		}
		if _, err := m.recipient(); err != nil {
			return err
		}
	}
	if e.Recovery.Machine != RecoveryMachine {
		return fmt.Errorf("%w: entry %d recovery member is named %q", ErrInvalidLog, e.Seq, e.Recovery.Machine)
	}
	if _, err := e.Recovery.publicKey(); err != nil {
		return err
	}
	if _, err := e.Recovery.recipient(); err != nil {
		return err
	}
	if len(e.Wrapped) == 0 {
		return fmt.Errorf("%w: entry %d wraps no keys", ErrInvalidLog, e.Seq)
	}
	return nil
}

func checkEnclaveName(e model.EnclaveName) error {
	s := string(e)
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\: \t\n\r\"") {
		return fmt.Errorf("invalid enclave name %q", s)
	}
	return nil
}

func verifyFirst(e LogEntry) error {
	if e.Op != OpCreate || e.Epoch != 1 || e.Prev != "" {
		return fmt.Errorf("%w: entry 1 must be a create at epoch 1 with no prev", ErrInvalidLog)
	}
	if len(e.Members) != 1 || e.Signer != e.Members[0].Machine {
		return fmt.Errorf("%w: entry 1 must have its creator as sole member and signer", ErrBadSignature)
	}
	return verifySig(e, e.Members[0])
}

func verifyNext(prev LogEntry, prevFP string, e LogEntry) error {
	if e.Prev != prevFP {
		return fmt.Errorf("%w: entry %d prev does not match entry %d", ErrBrokenChain, e.Seq, prev.Seq)
	}
	// The signer's key comes from the previous entry, never from this one.
	var signer Member
	if e.Signer == RecoveryMachine {
		signer = prev.Recovery
	} else {
		m, ok := findMember(prev.Members, e.Signer)
		if !ok {
			return fmt.Errorf("%w: entry %d signer %s is not a member of entry %d", ErrBadSignature, e.Seq, e.Signer, prev.Seq)
		}
		signer = m
	}
	if err := verifySig(e, signer); err != nil {
		return err
	}
	if e.Recovery != prev.Recovery {
		return fmt.Errorf("%w: entry %d changes the recovery identity", ErrInvalidLog, e.Seq)
	}
	bad := func(why string) error {
		return fmt.Errorf("%w: entry %d (%s): %s", ErrInvalidLog, e.Seq, e.Op, why)
	}
	switch e.Op {
	case OpAdd:
		if e.Epoch != prev.Epoch {
			return bad("add must keep the epoch")
		}
		if _, ok := findMember(prev.Members, e.Subject); ok {
			return bad("subject is already a member")
		}
		if len(e.Members) != len(prev.Members)+1 || !equalMembers(e.Members[:len(prev.Members)], prev.Members) || e.Members[len(prev.Members)].Machine != e.Subject {
			return bad("members must be the previous members plus the subject")
		}
	case OpRemove:
		if e.Epoch != prev.Epoch+1 {
			return bad("remove must start the next epoch")
		}
		if _, ok := findMember(prev.Members, e.Subject); !ok {
			return bad("subject is not a member")
		}
		if !equalMembers(e.Members, without(prev.Members, e.Subject)) {
			return bad("members must be the previous members without the subject")
		}
	case OpRotate:
		if e.Epoch != prev.Epoch+1 {
			return bad("rotate must start the next epoch")
		}
		if !equalMembers(e.Members, prev.Members) {
			return bad("rotate must keep the members")
		}
	case OpRecover:
		if e.Signer != RecoveryMachine {
			return fmt.Errorf("%w: entry %d: recover must be signed by the recovery identity", ErrBadSignature, e.Seq)
		}
		if e.Epoch != prev.Epoch+1 {
			return bad("recover must start the next epoch")
		}
	default:
		return bad("unknown or misplaced op")
	}
	return nil
}

func verifySig(e LogEntry, signer Member) error {
	pub, err := signer.publicKey()
	if err != nil {
		return err
	}
	msg, err := SignedBytes(e)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidLog, err)
	}
	if len(e.Sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, e.Sig) {
		return fmt.Errorf("%w: entry %d", ErrBadSignature, e.Seq)
	}
	return nil
}

func findMember(ms []Member, id model.MachineID) (Member, bool) {
	for _, m := range ms {
		if m.Machine == id {
			return m, true
		}
	}
	return Member{}, false
}

func without(ms []Member, id model.MachineID) []Member {
	out := make([]Member, 0, len(ms))
	for _, m := range ms {
		if m.Machine != id {
			out = append(out, m)
		}
	}
	return out
}

// Join pins entry `expect` (a fingerprint received out of band) of an
// enclave's key log. It verifies the whole log with that entry as the pin,
// and also against any pin already held, so a join never moves a machine off
// a chain it accepted before. It returns the verified head. LoadSet advances
// the pin to the head on the next load.
func Join(entries []LogEntry, expect string, pins PinStore) (LogEntry, error) {
	if len(entries) == 0 {
		return LogEntry{}, fmt.Errorf("%w: empty key log", ErrInvalidLog)
	}
	enclave := entries[0].Enclave
	var want *Pin
	for _, e := range entries {
		fp, err := Fingerprint(e)
		if err != nil {
			return LogEntry{}, err
		}
		if fp == strings.ToLower(strings.TrimSpace(expect)) {
			want = &Pin{Seq: e.Seq, Hash: fp}
			break
		}
	}
	if want == nil {
		return LogEntry{}, fmt.Errorf("%w: no entry of %s has fingerprint %s", ErrBrokenChain, enclave, expect)
	}
	head, err := VerifyLog(entries, want)
	if err != nil {
		return LogEntry{}, err
	}
	old, err := pins.Get(enclave)
	if err != nil {
		return LogEntry{}, err
	}
	if old != nil {
		if _, err := VerifyLog(entries, old); err != nil {
			return LogEntry{}, err
		}
		if old.Seq > want.Seq {
			return head, nil // already pinned further along the same chain
		}
	}
	return head, pins.Set(enclave, *want)
}

// Get reads pins/<enclave>.
func (p filePins) Get(e model.EnclaveName) (*Pin, error) {
	if err := checkEnclaveName(e); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(p.dir, "pins", string(e)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pin Pin
	if err := json.Unmarshal(b, &pin); err != nil {
		return nil, fmt.Errorf("pin %s: %w", e, err)
	}
	if pin.Seq == 0 || len(pin.Hash) != 64 {
		return nil, fmt.Errorf("pin %s: malformed", e)
	}
	return &pin, nil
}

// Set writes pins/<enclave> with mode 0600.
func (p filePins) Set(e model.EnclaveName, pin Pin) error {
	if err := checkEnclaveName(e); err != nil {
		return err
	}
	dir := filepath.Join(p.dir, "pins")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(pin)
	if err != nil {
		return err
	}
	return writeSecret(filepath.Join(dir, string(e)), append(b, '\n'))
}
