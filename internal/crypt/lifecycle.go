package crypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"sort"

	"filippo.io/age"

	"github.com/noahkiss/yadm/internal/model"
)

// Create starts a new enclave at epoch 1 with the creator as the only member.
func Create(enclave model.EnclaveName, by *Identity, recovery Member) (LogEntry, *Keyring, error) {
	if err := checkEnclaveName(enclave); err != nil {
		return LogEntry{}, nil, err
	}
	if by == nil || by.Machine == RecoveryMachine {
		return LogEntry{}, nil, fmt.Errorf("%w: the creator must be a machine identity", ErrInvalidLog)
	}
	if recovery.Machine != RecoveryMachine {
		return LogEntry{}, nil, fmt.Errorf("%w: recovery member must be named %q", ErrInvalidLog, RecoveryMachine)
	}
	k := &Keyring{Enclave: enclave, keys: map[model.Epoch][]byte{}}
	if err := k.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := LogEntry{
		Enclave:  enclave,
		Seq:      1,
		Epoch:    1,
		Op:       OpCreate,
		Subject:  by.Machine,
		Members:  []Member{by.Member()},
		Recovery: recovery,
	}
	if err := finish(&e, k, by); err != nil {
		return LogEntry{}, nil, err
	}
	return e, k, nil
}

// Open unwraps a verified head entry with this machine's identity.
func Open(head LogEntry, id *Identity) (*Keyring, error) {
	if id == nil {
		return nil, ErrNotMember
	}
	if !holds(head, id) {
		return nil, ErrNotMember
	}
	r, err := age.Decrypt(bytes.NewReader(head.Wrapped), id.age)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap: %v", ErrNotMember, err)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%w: unwrap: %v", ErrNotMember, err)
	}
	if head.Epoch == 0 || len(raw) != int(head.Epoch)*EpochKeySize {
		return nil, fmt.Errorf("%w: wrapped keys hold %d bytes for %d epochs", ErrInvalidLog, len(raw), head.Epoch)
	}
	k := &Keyring{Enclave: head.Enclave, Current: head.Epoch, keys: map[model.Epoch][]byte{}}
	for i := model.Epoch(1); i <= head.Epoch; i++ {
		k.keys[i] = raw[(i-1)*EpochKeySize : i*EpochKeySize]
	}
	return k, nil
}

// holds reports whether id is a member, or the recovery identity, of head.
func holds(head LogEntry, id *Identity) bool {
	if id.Machine == RecoveryMachine {
		return id.matches(head.Recovery)
	}
	m, ok := findMember(head.Members, id.Machine)
	return ok && id.matches(m)
}

// Add appends an entry that wraps the existing epoch keys to one more member.
func (k *Keyring) Add(head LogEntry, m Member, by *Identity) (LogEntry, error) {
	if err := k.check(head, by); err != nil {
		return LogEntry{}, err
	}
	if m.Machine == RecoveryMachine {
		return LogEntry{}, fmt.Errorf("%w: cannot add the recovery identity as a member", ErrInvalidLog)
	}
	if _, ok := findMember(head.Members, m.Machine); ok {
		return LogEntry{}, fmt.Errorf("%w: %s is already a member", ErrInvalidLog, m.Machine)
	}
	e := next(head, OpAdd, m.Machine, head.Epoch, append(append([]Member{}, head.Members...), m))
	if err := finish(&e, k, by); err != nil {
		return LogEntry{}, err
	}
	return e, nil
}

// Remove appends an entry with a new epoch key wrapped to the remaining
// members. The removed machine keeps every key up to the old epoch.
func (k *Keyring) Remove(head LogEntry, m model.MachineID, by *Identity) (LogEntry, *Keyring, error) {
	if err := k.check(head, by); err != nil {
		return LogEntry{}, nil, err
	}
	if _, ok := findMember(head.Members, m); !ok {
		return LogEntry{}, nil, fmt.Errorf("%w: %s is not a member", ErrInvalidLog, m)
	}
	rest := without(head.Members, m)
	if len(rest) == 0 {
		return LogEntry{}, nil, fmt.Errorf("%w: cannot remove the last member; use recover", ErrInvalidLog)
	}
	nk := k.clone()
	if err := nk.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := next(head, OpRemove, m, nk.Current, rest)
	if err := finish(&e, nk, by); err != nil {
		return LogEntry{}, nil, err
	}
	return e, nk, nil
}

// Rotate appends an entry with a new epoch key and the same members.
func (k *Keyring) Rotate(head LogEntry, by *Identity) (LogEntry, *Keyring, error) {
	if err := k.check(head, by); err != nil {
		return LogEntry{}, nil, err
	}
	nk := k.clone()
	if err := nk.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := next(head, OpRotate, "", nk.Current, append([]Member{}, head.Members...))
	if err := finish(&e, nk, by); err != nil {
		return LogEntry{}, nil, err
	}
	return e, nk, nil
}

// Recover appends an entry signed by the recovery identity that sets a new
// member list and a new epoch. Use it when no member remains.
func Recover(head LogEntry, recovery *Identity, members []Member) (LogEntry, *Keyring, error) {
	if recovery == nil || recovery.Machine != RecoveryMachine || !recovery.matches(head.Recovery) {
		return LogEntry{}, nil, fmt.Errorf("%w: not the recovery identity of %s", ErrBadSignature, head.Enclave)
	}
	k, err := Open(head, recovery)
	if err != nil {
		return LogEntry{}, nil, err
	}
	if err := k.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := next(head, OpRecover, "", k.Current, append([]Member{}, members...))
	if err := finish(&e, k, recovery); err != nil {
		return LogEntry{}, nil, err
	}
	return e, k, nil
}

// check refuses a write by a signer the verifier would reject, or on a
// keyring that does not match the head.
func (k *Keyring) check(head LogEntry, by *Identity) error {
	if k == nil || k.Enclave != head.Enclave || k.Current != head.Epoch {
		return fmt.Errorf("%w: keyring does not match the head entry", ErrInvalidLog)
	}
	if by == nil || !holds(head, by) {
		return fmt.Errorf("%w: the signer is neither a member nor the recovery identity", ErrBadSignature)
	}
	return nil
}

func next(head LogEntry, op Op, subject model.MachineID, epoch model.Epoch, members []Member) LogEntry {
	prev, err := Fingerprint(head)
	if err != nil {
		prev = "" // an unencodable head; finish's shape check and VerifyLog reject the entry
	}
	return LogEntry{
		Enclave:  head.Enclave,
		Seq:      head.Seq + 1,
		Prev:     prev,
		Epoch:    epoch,
		Op:       op,
		Subject:  subject,
		Members:  members,
		Recovery: head.Recovery,
	}
}

// finish wraps the keyring to e's members and the recovery identity, then
// signs e as by.
func finish(e *LogEntry, k *Keyring, by *Identity) error {
	if err := checkShapeForWrite(*e); err != nil {
		return err
	}
	wrapped, err := k.wrap(append(append([]Member{}, e.Members...), e.Recovery))
	if err != nil {
		return err
	}
	e.Wrapped = wrapped
	e.Signer = by.Machine
	msg, err := SignedBytes(*e)
	if err != nil {
		return err
	}
	e.Sig = ed25519.Sign(by.sign, msg)
	return nil
}

func checkShapeForWrite(e LogEntry) error {
	if e.Seq > 1 && e.Prev == "" {
		return fmt.Errorf("%w: the head entry cannot be encoded", ErrInvalidLog)
	}
	e.Wrapped = []byte{0} // not wrapped yet
	return checkShape(e)
}

func (k *Keyring) wrap(to []Member) ([]byte, error) {
	var rs []age.Recipient
	for _, m := range to {
		r, err := m.recipient()
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
	}
	var raw []byte
	for i := model.Epoch(1); i <= k.Current; i++ {
		key, ok := k.keys[i]
		if !ok {
			return nil, fmt.Errorf("%w: keyring lacks epoch %d", ErrUnknownEpoch, i)
		}
		raw = append(raw, key...)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rs...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(raw); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (k *Keyring) addEpoch() error {
	key := make([]byte, EpochKeySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	k.Current++
	k.keys[k.Current] = key
	return nil
}

func (k *Keyring) clone() *Keyring {
	n := &Keyring{Enclave: k.Enclave, Current: k.Current, keys: map[model.Epoch][]byte{}}
	for e, v := range k.keys {
		n.keys[e] = v
	}
	return n
}

// LoadSet verifies every enclave's key log against this machine's pins,
// opens the keyrings this machine is a member of, and advances pins to the
// verified heads. An enclave whose log fails verification is reported in the
// map and left out of the Set; other enclaves still load.
//
// A keyring opens only for an enclave this machine has pinned (by create,
// add or `enclave join --expect`). An unpinned log is still verified from
// entry 1, but trust on first use never yields a keyring: a writer could
// replace the whole log with one that lists this machine and so make it seal
// new files under keys the writer holds. When this machine is listed in an
// unpinned log, the enclave reports ErrNotPinned. Unpinned enclaves are not
// pinned here.
//
// The returned error is reserved for failures that are not about one enclave;
// a nil id verifies logs without opening any keyring.
func LoadSet(logs map[model.EnclaveName][]LogEntry, pins PinStore, id *Identity) (*Set, map[model.EnclaveName]EnclaveLoad, error) {
	set := &Set{Rings: map[model.EnclaveName]*Keyring{}}
	out := map[model.EnclaveName]EnclaveLoad{}
	names := make([]model.EnclaveName, 0, len(logs))
	for e := range logs {
		names = append(names, e)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, name := range names {
		out[name] = loadOne(name, logs[name], pins, id, set)
	}
	return set, out, nil
}

func loadOne(name model.EnclaveName, entries []LogEntry, pins PinStore, id *Identity, set *Set) EnclaveLoad {
	for _, e := range entries {
		if e.Enclave != name {
			return EnclaveLoad{Err: fmt.Errorf("%w: log of %s holds an entry for %q", ErrInvalidLog, name, e.Enclave)}
		}
	}
	var pin *Pin
	if pins != nil {
		p, err := pins.Get(name)
		if err != nil {
			return EnclaveLoad{Err: err}
		}
		pin = p
	}
	head, err := VerifyLog(entries, pin)
	if err != nil {
		return EnclaveLoad{Err: err}
	}
	if id == nil {
		return EnclaveLoad{Head: head}
	}
	listed := holds(head, id)
	if !listed {
		if pin != nil {
			if err := advance(pins, head, pin); err != nil {
				return EnclaveLoad{Head: head, Err: err}
			}
		}
		return EnclaveLoad{Head: head}
	}
	if pin == nil {
		return EnclaveLoad{Head: head, Err: ErrNotPinned}
	}
	k, err := Open(head, id)
	if err != nil {
		return EnclaveLoad{Head: head, Err: err}
	}
	if err := advance(pins, head, pin); err != nil {
		return EnclaveLoad{Head: head, Err: err}
	}
	set.Rings[name] = k
	return EnclaveLoad{Head: head, Member: true}
}

func advance(pins PinStore, head LogEntry, old *Pin) error {
	if head.Seq == old.Seq {
		return nil
	}
	p, err := PinOf(head)
	if err != nil {
		return err
	}
	return pins.Set(head.Enclave, p)
}
