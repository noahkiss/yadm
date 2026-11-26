package crypt

import (
	"errors"
	"fmt"
	"strings"

	"filippo.io/age"

	"github.com/noahkiss/yadm/internal/model"
)

// RecoveryKey is the age half of an enclave's recovery identity. It opens
// the enclave's keys for reading. It cannot sign, so it never writes a
// key-log entry.
type RecoveryKey struct{ age *age.X25519Identity }

// ParseRecoveryKey reads the content of a recovery identity.age.key file:
// an optional "# machine: recovery" line, then the AGE-SECRET-KEY line.
// Blank lines and surrounding space are ignored. It refuses a file that
// names another machine: a member's key is not a recovery key. Its errors
// never quote the key.
func ParseRecoveryKey(b []byte) (*RecoveryKey, error) {
	if len(b) > maxKeyFile {
		return nil, errors.New("recovery key: input is too large for an age identity")
	}
	var key string
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "":
		case strings.HasPrefix(l, machineComment):
			if m := model.MachineID(strings.TrimSpace(strings.TrimPrefix(l, machineComment))); m != RecoveryMachine {
				return nil, fmt.Errorf("recovery key: the file names machine %q, not %q; give the enclave's recovery identity", m, RecoveryMachine)
			}
		case strings.HasPrefix(l, "#"):
		default:
			key = l
			n++
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("recovery key: want one AGE-SECRET-KEY line, found %d key lines", n)
	}
	a, err := age.ParseX25519Identity(key)
	if err != nil {
		return nil, errors.New("recovery key: not an age X25519 identity (AGE-SECRET-KEY-1...)")
	}
	return &RecoveryKey{age: a}, nil
}

// LoadRecoveryKey reads a recovery identity.age.key file with the checks
// LoadIdentity applies to a key file: a regular file, not a symlink, owned
// by this user, with no group or other access.
func LoadRecoveryKey(path string) (*RecoveryKey, error) {
	b, err := readSecretFile(path)
	if err != nil {
		return nil, err
	}
	return ParseRecoveryKey(b)
}

// Recipient returns the age recipient (age1...) of the key.
func (r *RecoveryKey) Recipient() string { return r.age.Recipient().String() }

// OpenRecovery unwraps a verified head entry with an enclave's recovery
// key, for reading only. It refuses a key whose recipient is not the head's
// recovery recipient, and checks every unwrapped key against the head's key
// commitments, as Open does. The keyring's floor is the head's min_epoch.
//
// A verified head proves only that the log is consistent, not that it is
// the enclave's own log: any writer can forge a log that names the public
// recovery recipient and wraps keys of its own choosing. Ciphertext sealed
// under the genuine keys never opens under forged ones, but a writer who
// also replaced the sealed files controls what they open to. The caller
// anchors the log to a fingerprint received out of band (VerifyLog with a
// pin) when it must trust the plaintext.
func OpenRecovery(head LogEntry, r *RecoveryKey) (*Keyring, error) {
	if r == nil || r.age == nil {
		return nil, ErrNotMember
	}
	if head.Recovery.Machine != RecoveryMachine || head.Recovery.Recipient != r.Recipient() {
		return nil, fmt.Errorf("%w: this key is not the recovery identity of %s (the key log names %s)", ErrNotMember, head.Enclave, head.Recovery.Recipient)
	}
	return unwrap(head, r.age)
}
