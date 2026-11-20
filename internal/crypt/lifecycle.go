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
// It pins the new entry in pins, the creator's PinStore, and refuses when that
// store already pins the enclave.
func Create(enclave model.EnclaveName, by *Identity, recovery Member, pins PinStore) (LogEntry, *Keyring, error) {
	if err := checkEnclaveName(enclave); err != nil {
		return LogEntry{}, nil, err
	}
	if by == nil || by.Machine == RecoveryMachine {
		return LogEntry{}, nil, fmt.Errorf("%w: the creator must be a machine identity", ErrInvalidLog)
	}
	if recovery.Machine != RecoveryMachine {
		return LogEntry{}, nil, fmt.Errorf("%w: recovery member must be named %q", ErrInvalidLog, RecoveryMachine)
	}
	if err := checkPinForWrite(pins, enclave, nil, false); err != nil {
		return LogEntry{}, nil, err
	}
	k := &Keyring{Enclave: enclave, Min: 1, keys: map[model.Epoch][]byte{}}
	if err := k.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := LogEntry{
		Enclave:  enclave,
		Seq:      1,
		Epoch:    1,
		MinEpoch: 1,
		Op:       OpCreate,
		Subject:  by.Machine,
		Members:  []Member{by.Member()},
		Recovery: recovery,
	}
	if err := finish(&e, k, by, pins); err != nil {
		return LogEntry{}, nil, err
	}
	return e, k, nil
}

// Open unwraps a verified head entry with this machine's identity. It checks
// every unwrapped key against the head's key commitments, so a signer who
// wraps a different key for an earlier epoch is refused, and it sets the
// keyring's floor to the head's min_epoch.
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
	if len(head.KeyCommits) != int(head.Epoch) || head.MinEpoch == 0 || head.MinEpoch > head.Epoch {
		return nil, fmt.Errorf("%w: head of %s has no valid key commitments", ErrInvalidLog, head.Enclave)
	}
	k := &Keyring{Enclave: head.Enclave, Current: head.Epoch, Min: head.MinEpoch, keys: map[model.Epoch][]byte{}}
	for i := model.Epoch(1); i <= head.Epoch; i++ {
		key := raw[(i-1)*EpochKeySize : i*EpochKeySize]
		if KeyCommit(head.Enclave, i, key) != head.KeyCommits[i-1] {
			return nil, fmt.Errorf("%w: wrapped key of epoch %d does not match its commitment", ErrInvalidLog, i)
		}
		k.keys[i] = key
	}
	return k, nil
}

// commits returns the key commitments of epochs 1..k.Current.
func (k *Keyring) commits() ([]string, error) {
	out := make([]string, 0, k.Current)
	for i := model.Epoch(1); i <= k.Current; i++ {
		key, ok := k.keys[i]
		if !ok {
			return nil, fmt.Errorf("%w: keyring lacks epoch %d", ErrUnknownEpoch, i)
		}
		out = append(out, KeyCommit(k.Enclave, i, key))
	}
	return out, nil
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
// Like every write, it pins the new entry in pins, the signer's PinStore.
func (k *Keyring) Add(head LogEntry, m Member, by *Identity, pins PinStore) (LogEntry, error) {
	if err := k.check(head, by, pins); err != nil {
		return LogEntry{}, err
	}
	if m.Machine == RecoveryMachine {
		return LogEntry{}, fmt.Errorf("%w: cannot add the recovery identity as a member", ErrInvalidLog)
	}
	if _, ok := findMember(head.Members, m.Machine); ok {
		return LogEntry{}, fmt.Errorf("%w: %s is already a member", ErrInvalidLog, m.Machine)
	}
	e := next(head, OpAdd, m.Machine, head.Epoch, append(append([]Member{}, head.Members...), m))
	if err := finish(&e, k, by, pins); err != nil {
		return LogEntry{}, err
	}
	return e, nil
}

// Remove appends an entry with a new epoch key wrapped to the remaining
// members. The removed machine keeps every key up to the old epoch.
func (k *Keyring) Remove(head LogEntry, m model.MachineID, by *Identity, pins PinStore) (LogEntry, *Keyring, error) {
	if err := k.check(head, by, pins); err != nil {
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
	if err := finish(&e, nk, by, pins); err != nil {
		return LogEntry{}, nil, err
	}
	return e, nk, nil
}

// Rotate appends an entry with a new epoch key and the same members.
func (k *Keyring) Rotate(head LogEntry, by *Identity, pins PinStore) (LogEntry, *Keyring, error) {
	if err := k.check(head, by, pins); err != nil {
		return LogEntry{}, nil, err
	}
	nk := k.clone()
	if err := nk.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := next(head, OpRotate, "", nk.Current, append([]Member{}, head.Members...))
	if err := finish(&e, nk, by, pins); err != nil {
		return LogEntry{}, nil, err
	}
	return e, nk, nil
}

// Retire appends an entry that raises min_epoch to the current epoch, so no
// member opens ciphertext of an older epoch for delivery again. Run it once
// the reseal commit after a remove or rotate has landed.
func (k *Keyring) Retire(head LogEntry, by *Identity, pins PinStore) (LogEntry, error) {
	if err := k.check(head, by, pins); err != nil {
		return LogEntry{}, err
	}
	if head.MinEpoch >= head.Epoch {
		return LogEntry{}, fmt.Errorf("%w: min_epoch of %s is already the current epoch", ErrInvalidLog, head.Enclave)
	}
	e := next(head, OpRetire, "", head.Epoch, append([]Member{}, head.Members...))
	e.MinEpoch = head.Epoch
	if err := finish(&e, k, by, pins); err != nil {
		return LogEntry{}, err
	}
	return e, nil
}

// SetRecovery appends an entry, signed by the current recovery identity,
// that names a new recovery identity. Epoch and members stay; the keys are
// wrapped to the new recovery recipient.
func SetRecovery(head LogEntry, recovery *Identity, to Member, pins PinStore) (LogEntry, error) {
	if recovery == nil || recovery.Machine != RecoveryMachine || !recovery.matches(head.Recovery) {
		return LogEntry{}, fmt.Errorf("%w: not the recovery identity of %s", ErrBadSignature, head.Enclave)
	}
	if to.Machine != RecoveryMachine {
		return LogEntry{}, fmt.Errorf("%w: recovery member must be named %q", ErrInvalidLog, RecoveryMachine)
	}
	if to == head.Recovery {
		return LogEntry{}, fmt.Errorf("%w: the new recovery identity equals the old one", ErrInvalidLog)
	}
	if err := checkPinForWrite(pins, head.Enclave, &head, true); err != nil {
		return LogEntry{}, err
	}
	k, err := Open(head, recovery)
	if err != nil {
		return LogEntry{}, err
	}
	e := next(head, OpSetRecovery, "", head.Epoch, append([]Member{}, head.Members...))
	e.Recovery = to
	if err := finish(&e, k, recovery, pins); err != nil {
		return LogEntry{}, err
	}
	return e, nil
}

// Recover appends an entry signed by the recovery identity that sets a new
// member list and a new epoch. Use it when no member remains.
func Recover(head LogEntry, recovery *Identity, members []Member, pins PinStore) (LogEntry, *Keyring, error) {
	if recovery == nil || recovery.Machine != RecoveryMachine || !recovery.matches(head.Recovery) {
		return LogEntry{}, nil, fmt.Errorf("%w: not the recovery identity of %s", ErrBadSignature, head.Enclave)
	}
	if err := checkPinForWrite(pins, head.Enclave, &head, true); err != nil {
		return LogEntry{}, nil, err
	}
	k, err := Open(head, recovery)
	if err != nil {
		return LogEntry{}, nil, err
	}
	if err := k.addEpoch(); err != nil {
		return LogEntry{}, nil, err
	}
	e := next(head, OpRecover, "", k.Current, append([]Member{}, members...))
	if err := finish(&e, k, recovery, pins); err != nil {
		return LogEntry{}, nil, err
	}
	return e, k, nil
}

// check refuses a member write by a signer the verifier would reject, or on
// a keyring that does not match the head. The recovery identity writes only
// through Recover and SetRecovery.
func (k *Keyring) check(head LogEntry, by *Identity, pins PinStore) error {
	if k == nil || k.Enclave != head.Enclave || k.Current != head.Epoch {
		return fmt.Errorf("%w: keyring does not match the head entry", ErrInvalidLog)
	}
	if by == nil || by.Machine == RecoveryMachine || !holds(head, by) {
		return fmt.Errorf("%w: the signer is not a member of %s", ErrBadSignature, head.Enclave)
	}
	return checkPinForWrite(pins, head.Enclave, &head, false)
}

// checkPinForWrite refuses a write the signer's own pin contradicts. A
// create needs an unpinned enclave. A member write needs a pin, and the head
// must be exactly the pinned entry: LoadSet verified the chain from the old
// pin to that head before it advanced the pin, so the write descends from
// every entry this machine ever accepted. A head past the pin is refused
// until a load advances the pin. The recovery identity (unpinned true) may
// write without a pin, because it runs on its own; with a pin it obeys the
// same rule. Writes pin their new entry in finish, so the acting machine
// never needs a join.
func checkPinForWrite(pins PinStore, e model.EnclaveName, head *LogEntry, unpinned bool) error {
	if pins == nil {
		return fmt.Errorf("a PinStore is required to write the key log of %s", e)
	}
	p, err := pins.Get(e)
	if err != nil {
		return err
	}
	if p == nil {
		if head == nil || unpinned {
			return nil
		}
		return fmt.Errorf("%w: %s is not pinned on this machine; load or join the enclave before writing its key log", ErrNotPinned, e)
	}
	if head == nil {
		return fmt.Errorf("%w: %s is already pinned on this machine at seq %d", ErrBrokenChain, e, p.Seq)
	}
	if p.Seq > head.Seq {
		return fmt.Errorf("%w: head seq %d of %s is behind the pin at seq %d", ErrBrokenChain, head.Seq, e, p.Seq)
	}
	if p.Seq < head.Seq {
		return fmt.Errorf("%w: head seq %d of %s is past the pin at seq %d; load the key log to verify and pin it first", ErrBrokenChain, head.Seq, e, p.Seq)
	}
	fp, err := Fingerprint(*head)
	if err != nil {
		return err
	}
	if fp != p.Hash {
		return fmt.Errorf("%w: head of %s differs from the pinned entry", ErrBrokenChain, e)
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
		MinEpoch: head.MinEpoch,
		Op:       op,
		Subject:  subject,
		Members:  members,
		Recovery: head.Recovery,
	}
}

// finish wraps the keyring to e's members and the recovery identity, signs e
// as by, and pins e in pins.
func finish(e *LogEntry, k *Keyring, by *Identity, pins PinStore) error {
	commits, err := k.commits()
	if err != nil {
		return err
	}
	e.KeyCommits = commits
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
	p, err := PinOf(*e)
	if err != nil {
		return err
	}
	return pins.Set(e.Enclave, p)
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
	n := &Keyring{Enclave: k.Enclave, Current: k.Current, Min: k.Min, keys: map[model.Epoch][]byte{}}
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
		return EnclaveLoad{Head: head, Err: notPinned(head)}
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

// notPinned names the enclave and the join step. The fingerprint to pass is
// the one the adding member's `yadm enclave add` printed, received out of
// band. The message shows no local fingerprint: the local log is what a
// pusher controls, so a value read from it must never look like one to trust.
func notPinned(head LogEntry) error {
	return fmt.Errorf("%w: enclave %s: get the fingerprint that `yadm enclave add` printed from the member who added this machine, "+
		"then run `yadm enclave join %s --expect <fingerprint>`; never copy the fingerprint from this machine's own copy of the log",
		ErrNotPinned, head.Enclave, head.Enclave)
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
