package pause

import (
	"errors"
	"fmt"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
)

// ErrForged means a record carries a signature that fails under every key
// a pinned key log gives its signer.
var ErrForged = errors.New("forged pause record")

// Trust is who may pause or resume on this machine, and which records it
// can verify.
//
// A record counts when it is well formed and its signer is a machine in
// fleet.toml. It is verified when its signer is a member of a key log this
// machine pinned and the signature verifies under that member's key. A
// signature that fails under such a key marks the record forged; a missing
// signature, or a signer no pinned log lists, leaves it unverified. With
// RequireMember (fleet.toml `pause_requires = "member"`), an unverified
// record does not count.
type Trust struct {
	Fleet         map[model.MachineID]bool
	Members       map[model.MachineID][]crypt.Member
	RequireMember bool
}

// NewTrust builds the trust of this machine from the machines in fleet.toml
// at its local main, the key logs it loaded, and its pins. A log counts only
// when it verified against a pin this machine holds: a writer can replace an
// unpinned log with one that lists its own key.
func NewTrust(fleet []model.MachineID, loads map[model.EnclaveName]crypt.EnclaveLoad, pins crypt.PinStore, requireMember bool) Trust {
	t := Trust{Fleet: map[model.MachineID]bool{}, Members: map[model.MachineID][]crypt.Member{}, RequireMember: requireMember}
	for _, m := range fleet {
		t.Fleet[m] = true
	}
	if pins == nil {
		return t
	}
	for e, l := range loads {
		if l.Err != nil {
			continue
		}
		if p, err := pins.Get(e); err != nil || p == nil {
			continue
		}
		for _, m := range l.Head.Members {
			t.Members[m.Machine] = append(t.Members[m.Machine], m)
		}
	}
	return t
}

// Can reports whether m may sign a pause or resume that this machine
// counts, given its own key.
func (t Trust) Can(m model.MachineID, signKey string) bool {
	if !t.Fleet[m] {
		return false
	}
	if !t.RequireMember {
		return true
	}
	for _, k := range t.Members[m] {
		if k.SignKey == signKey {
			return true
		}
	}
	return false
}

// Verify checks a record. It returns whether a pinned member's signature
// verified it, or why the record does not count: ErrMalformed, ErrUntrusted
// (a signer outside fleet.toml, or unverified while RequireMember holds) or
// ErrForged.
func (t Trust) Verify(r Record) (verified bool, err error) {
	if err := r.shape(); err != nil {
		return false, err
	}
	if !t.Fleet[r.Signer] {
		return false, fmt.Errorf("%w: %s is not a machine in fleet.toml", ErrUntrusted, r.Signer)
	}
	keys := t.Members[r.Signer]
	if len(r.Sig) > 0 && len(keys) > 0 {
		body, err := r.SignedBytes()
		if err != nil {
			return false, err
		}
		for _, m := range keys {
			if crypt.VerifyStatement(m, Kind, body, r.Sig) == nil {
				return true, nil
			}
		}
		return false, fmt.Errorf("%w: the signature fails under every pinned key of %s", ErrForged, r.Signer)
	}
	if t.RequireMember {
		return false, fmt.Errorf("%w: fleet.toml requires a pinned key-log member's signature, and %s gave none this machine can check", ErrUntrusted, r.Signer)
	}
	return false, nil
}
