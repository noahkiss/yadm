package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
)

func (a *app) registerEnclave(root *cobra.Command) {
	en := a.group(root, "enclave", "Enclave keys and membership")
	leaf := a.leaf
	leaf(en, "list", "List enclaves, epochs and members", a.cmdEnclaveList)
	cr := leaf(en, "create <type>", "Create an enclave key log for a type", a.cmdEnclaveCreate)
	cr.Args = cobra.ExactArgs(1)
	addRecoveryFlags(cr)
	ad := leaf(en, "add <machine>", "Wrap the enclave keys to a machine (members only)", a.cmdEnclaveAdd)
	ad.Args = cobra.ExactArgs(1)
	ad.Flags().String("enclave", "", "enclave to add the machine to (default: the only enclave this machine opens)")
	ad.Flags().String("recipient", "", "the new machine's age recipient, from its `yadm init`")
	ad.Flags().String("sign-key", "", "the new machine's signing key, from its `yadm init`")
	rm := leaf(en, "remove <machine>", "Remove a member and start a new epoch", a.cmdEnclaveRemove)
	rm.Args = cobra.ExactArgs(1)
	rm.Flags().String("enclave", "", "enclave to remove the machine from (default: the only enclave this machine opens)")
	rm.Flags().Bool("confirm", false, "required: removal is not reversible")
	jn := leaf(en, "join <enclave>", "Pin an enclave's key log on this machine", a.cmdEnclaveJoin)
	jn.Args = cobra.ExactArgs(1)
	jn.Flags().String("expect", "", "required: fingerprint of the key-log entry that added this machine, received out of band")
	leaf(en, "verify", "Verify every key log against the local pins", a.cmdEnclaveVerify)
	od := leaf(en, "on-demand <enclave>", "Read an enclave on demand only on this machine: never apply, capture or back it up", a.cmdEnclaveOnDemand)
	od.Args = cobra.ExactArgs(1)
	od.Flags().Bool("off", false, "clear the mark: deliver the enclave again where types and membership say so")
	rt := leaf(en, "retire", "Stop opening ciphertext of older epochs for delivery (after a remove's reseal)", a.cmdEnclaveRetire)
	rt.Flags().String("enclave", "", "enclave to retire old epochs of (default: the only enclave this machine opens)")
	sr := leaf(en, "set-recovery", "Name a new recovery identity, signed by the current one", a.cmdEnclaveSetRecovery)
	sr.Flags().String("enclave", "", "enclave whose recovery identity changes")
	sr.Flags().String("recovery-dir", "", "required: directory holding the current recovery identity")
	addRecoveryFlags(sr)
}

func addRecoveryFlags(c *cobra.Command) {
	c.Flags().String("recovery-recipient", "", "age recipient of the offline recovery identity")
	c.Flags().String("recovery-sign-key", "", "signing key of the offline recovery identity")
	c.Flags().String("new-recovery", "", "generate a recovery identity into this directory (outside the source and state); store it offline")
}

// recoveryMember reads the recovery flags. With --new-recovery it generates
// and saves a recovery identity.
func recoveryMember(cmd *cobra.Command, forbidden ...string) (crypt.Member, string, error) {
	rr, _ := cmd.Flags().GetString("recovery-recipient")
	rs, _ := cmd.Flags().GetString("recovery-sign-key")
	dir, _ := cmd.Flags().GetString("new-recovery")
	switch {
	case dir != "" && (rr != "" || rs != ""):
		return crypt.Member{}, "", usagef("give --new-recovery or --recovery-recipient with --recovery-sign-key, not both")
	case dir != "":
		abs, err := filepath.Abs(dir)
		if err != nil {
			return crypt.Member{}, "", err
		}
		for _, f := range forbidden {
			if f == "" {
				continue
			}
			if rel, err := filepath.Rel(f, abs); err == nil && !strings.HasPrefix(rel, "..") {
				return crypt.Member{}, "", usagef("--new-recovery must be outside %s", f)
			}
		}
		id, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
		if err != nil {
			return crypt.Member{}, "", err
		}
		if err := id.Save(abs); err != nil {
			return crypt.Member{}, "", err
		}
		return id.Member(), abs, nil
	case rr == "" || rs == "":
		return crypt.Member{}, "", usagef("the recovery identity is required: --recovery-recipient and --recovery-sign-key, or --new-recovery <dir>")
	}
	return crypt.Member{Machine: crypt.RecoveryMachine, Recipient: rr, SignKey: rs}, "", nil
}

type enclaveInfo struct {
	Enclave     model.EnclaveName `json:"enclave"`
	Seq         uint64            `json:"seq"`
	Epoch       model.Epoch       `json:"epoch"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Members     []model.MachineID `json:"members"`
	Member      bool              `json:"member"`
	OnDemand    bool              `json:"on_demand,omitempty"` // this machine reads it on demand only
	Pinned      *crypt.Pin        `json:"pinned"`
	Error       string            `json:"error,omitempty"`
}

func (a *app) cmdEnclaveList(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	pins := crypt.FilePins(m.paths.State)
	out := []enclaveInfo{}
	var b strings.Builder
	for _, e := range m.snap.Fleet.Enclaves() {
		info := enclaveInfo{Enclave: e, Members: []model.MachineID{}}
		info.Pinned, _ = pins.Get(e)
		info.OnDemand = m.snap.IsOnDemand(e)
		if l, ok := m.snap.Enclaves[e]; ok {
			info.Seq, info.Epoch = l.Head.Seq, l.Head.Epoch
			info.Member = m.snap.Readable().CanOpen(e)
			for _, mb := range l.Head.Members {
				info.Members = append(info.Members, mb.Machine)
			}
			if l.Head.Seq > 0 {
				info.Fingerprint, _ = crypt.Fingerprint(l.Head)
			}
			if l.Err != nil {
				info.Error = l.Err.Error()
			}
		}
		out = append(out, info)
		fmt.Fprintf(&b, "%-12s seq %d epoch %d member=%v on_demand=%v members=%v %s\n", e, info.Seq, info.Epoch, info.Member, info.OnDemand, info.Members, info.Error)
	}
	return result{data: map[string]any{"enclaves": out}, text: b.String()}, nil
}

// requireMember loads this machine and checks it can sign.
func requireIdentity(ctx context.Context) (*machineEnv, error) {
	m, err := openLoaded(ctx)
	if err != nil {
		return m, err
	}
	if m.id == nil {
		return m, fmt.Errorf("%w: this machine has no identity keys", ErrRefused)
	}
	return m, nil
}

// pickEnclave returns the --enclave flag, or the only enclave this machine opens.
func pickEnclave(cmd *cobra.Command, m *machineEnv) (model.EnclaveName, error) {
	if e, _ := cmd.Flags().GetString("enclave"); e != "" {
		return model.EnclaveName(e), nil
	}
	var opened []model.EnclaveName
	for _, e := range m.snap.Fleet.Enclaves() {
		if m.snap.Readable().CanOpen(e) {
			opened = append(opened, e)
		}
	}
	if len(opened) == 1 {
		return opened[0], nil
	}
	return "", usagef("name the enclave with --enclave (this machine opens %d)", len(opened))
}

// machineID resolves a fleet id, name or nickname; an unknown "m-..." id is
// taken as is (a machine not yet in the fleet).
func machineID(m *machineEnv, key string) (model.MachineID, error) {
	mc, err := m.snap.Fleet.Lookup(key)
	if err == nil {
		return lookupID(m.snap.Fleet, mc), nil
	}
	if strings.HasPrefix(key, "m-") {
		return model.MachineID(key), nil
	}
	return "", err
}

type entryData struct {
	Enclave     model.EnclaveName `json:"enclave"`
	Op          crypt.Op          `json:"op"`
	Seq         uint64            `json:"seq"`
	Epoch       model.Epoch       `json:"epoch"`
	Subject     model.MachineID   `json:"subject,omitempty"`
	Fingerprint string            `json:"fingerprint"`
	Members     []model.MachineID `json:"members"`
	Commit      model.CommitID    `json:"commit"`
	Recovery    string            `json:"recovery_dir,omitempty"`
	Resealed    []model.Target    `json:"resealed,omitempty"`
	PushError   string            `json:"push_error,omitempty"` // the commit landed; the next sync pushes it
	Holds       []model.Hold      `json:"holds,omitempty"`
}

// pendingPins reads this machine's pins, so a write checks that its head is
// the pinned one, but keeps the pin a write sets in memory: writeEntry moves
// the file pin only after the commit lands.
func (m *machineEnv) pendingPins() crypt.PinStore {
	return pendingPins{file: crypt.FilePins(m.paths.State), mem: crypt.MemPins()}
}

type pendingPins struct{ file, mem crypt.PinStore }

func (p pendingPins) Get(e model.EnclaveName) (*crypt.Pin, error) {
	if x, err := p.mem.Get(e); err != nil || x != nil {
		return x, err
	}
	return p.file.Get(e)
}

func (p pendingPins) Set(e model.EnclaveName, pin crypt.Pin) error { return p.mem.Set(e, pin) }

// writeEntry commits a key-log entry (plus a reseal capture) on main through
// sync.Commit, so the gate and the lock apply, pushes it, and pins it. The
// pin moves only after the commit lands.
func (m *machineEnv) writeEntry(ctx context.Context, version string, e crypt.LogEntry, reseal *apply.Capture, subject string) (entryData, error) {
	b, err := crypt.MarshalLogEntry(e)
	if err != nil {
		return entryData{}, err
	}
	fp, err := crypt.Fingerprint(e)
	if err != nil {
		return entryData{}, err
	}
	d := entryData{Enclave: e.Enclave, Op: e.Op, Seq: e.Seq, Epoch: e.Epoch, Subject: e.Subject, Fingerprint: fp, Members: []model.MachineID{}}
	for _, mb := range e.Members {
		d.Members = append(d.Members, mb.Machine)
	}
	opts := sync.CommitOptions{
		Message:      subject,
		Changes:      []store.Change{{Path: crypt.LogPath(e.Enclave, e.Seq), Blob: b, Mode: 0o100644}},
		ChangesScope: model.Scope(e.Enclave),
		Capture:      reseal,
		Push:         true,
	}
	if reseal == nil {
		opts.Capture = &apply.Capture{}
	}
	rep, pushErr, err := m.commitThrough(ctx, version, opts)
	if pushErr != nil {
		d.PushError = pushErr.Error()
	}
	if len(rep.Holds) > 0 {
		d.Holds = withHoldNext(rep.Holds)
	}
	var id model.CommitID
	if err == nil {
		id, err = m.landed(ctx, rep, crypt.LogPath(e.Enclave, e.Seq))
	}
	d.Commit = id
	if id == "" {
		return d, err
	}
	pin, perr := crypt.PinOf(e)
	if perr == nil {
		perr = crypt.FilePins(m.paths.State).Set(e.Enclave, pin)
	}
	return d, errors.Join(err, perr)
}

func (a *app) cmdEnclaveCreate(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := requireIdentity(ctx)
	if err != nil {
		return notInit(err), err
	}
	e := model.EnclaveName(args[0])
	td, ok := m.snap.Fleet.Types[model.TypeName(e)]
	if !ok || !td.Enclave {
		return result{}, usagef("%s is not a type with enclave = true in fleet.toml", e)
	}
	if !m.snap.Context.Machine.HasType(model.TypeName(e)) {
		return result{}, fmt.Errorf("%w: this machine is not of type %s", ErrRefused, e)
	}
	if l, ok := m.snap.Enclaves[e]; ok && l.Head.Seq > 0 {
		return result{}, fmt.Errorf("enclave %s already has a key log", e)
	}
	if p, _ := crypt.FilePins(m.paths.State).Get(e); p != nil {
		return result{}, fmt.Errorf("%w: this machine already pins enclave %s", ErrRefused, e)
	}
	rec, dir, err := recoveryMember(cmd, m.paths.Source, m.paths.State, m.home+"/.local")
	if err != nil {
		return result{}, err
	}
	entry, _, err := crypt.Create(e, m.id, rec, m.pendingPins())
	if err != nil {
		return result{}, err
	}
	d, err := m.writeEntry(ctx, a.version, entry, nil, "enclave "+string(e)+": create")
	d.Recovery = dir
	next := []string{"yadm sync"}
	if dir != "" {
		next = append(next, "move the recovery identity in "+dir+" offline, then delete it from this machine")
	}
	return result{data: d, next: next, text: "created " + string(e) + " fingerprint " + d.Fingerprint}, err
}

func (a *app) cmdEnclaveAdd(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := requireIdentity(ctx)
	if err != nil {
		return notInit(err), err
	}
	recipient, _ := cmd.Flags().GetString("recipient")
	signKey, _ := cmd.Flags().GetString("sign-key")
	if recipient == "" || signKey == "" {
		return result{next: []string{"run `yadm init` on the new machine; it prints both"}}, usagef("--recipient and --sign-key are required")
	}
	e, err := pickEnclave(cmd, m)
	if err != nil {
		return result{}, err
	}
	who, err := machineID(m, args[0])
	if err != nil {
		return result{}, usagef("%v", err)
	}
	ring, head, err := ringFor(m, e)
	if err != nil {
		return result{}, err
	}
	entry, err := ring.Add(head, crypt.Member{Machine: who, Recipient: recipient, SignKey: signKey}, m.id, m.pendingPins())
	if err != nil {
		return result{}, err
	}
	d, err := m.writeEntry(ctx, a.version, entry, nil, fmt.Sprintf("enclave %s: add %s", e, who))
	next := []string{"yadm sync", fmt.Sprintf("on %s, after it fetches: yadm enclave join %s --expect %s", who, model.ShellQuote(string(e)), model.ShellQuote(d.Fingerprint))}
	return result{data: d, next: next, text: "fingerprint " + d.Fingerprint}, err
}

// ringFor returns this machine's keyring and the verified head of an enclave.
func ringFor(m *machineEnv, e model.EnclaveName) (*crypt.Keyring, crypt.LogEntry, error) {
	l, ok := m.snap.Enclaves[e]
	if !ok {
		return nil, crypt.LogEntry{}, fmt.Errorf("enclave %s has no key log", e)
	}
	if l.Err != nil {
		return nil, crypt.LogEntry{}, fmt.Errorf("enclave %s: %w", e, l.Err)
	}
	if m.snap.Readable() == nil || m.snap.Readable().Rings[e] == nil {
		return nil, crypt.LogEntry{}, fmt.Errorf("enclave %s: %w", e, crypt.ErrNotMember)
	}
	return m.snap.Readable().Rings[e], l.Head, nil
}

func (a *app) cmdEnclaveRemove(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	if ok, _ := cmd.Flags().GetBool("confirm"); !ok {
		return result{next: []string{"yadm enclave remove " + model.ShellQuote(args[0]) + " --confirm"}}, usagef("removal starts a new epoch and cannot be undone; pass --confirm")
	}
	m, err := requireIdentity(ctx)
	if err != nil {
		return notInit(err), err
	}
	e, err := pickEnclave(cmd, m)
	if err != nil {
		return result{}, err
	}
	who, err := machineID(m, args[0])
	if err != nil {
		return result{}, usagef("%v", err)
	}
	ring, head, err := ringFor(m, e)
	if err != nil {
		return result{}, err
	}
	entry, newRing, err := ring.Remove(head, who, m.id, m.pendingPins())
	if err != nil {
		return result{}, err
	}
	// Reseal under the new epoch with a snapshot that holds the new keyring.
	rings := map[model.EnclaveName]*crypt.Keyring{}
	for k, v := range m.snap.Readable().Rings {
		rings[k] = v
	}
	rings[e] = newRing
	snap := *m.snap
	snap.Keys = &crypt.Set{Rings: rings}
	snap.Crypto = apply.SetCrypto(snap.Keys)
	c, err := m.eng.Reseal(ctx, &snap, e)
	if err != nil {
		return result{}, err
	}
	d, err := m.writeEntry(ctx, a.version, entry, &c, fmt.Sprintf("enclave %s: remove %s", e, who))
	d.Resealed = c.Paths
	retired := false
	if err == nil && d.Commit != "" {
		// The reseal landed: retire the old epochs now, so a forgery pushed
		// under an old key is never opened for delivery again.
		var re crypt.LogEntry
		if re, err = newRing.Retire(entry, m.id, m.pendingPins()); err == nil {
			var rd entryData
			rd, err = m.writeEntry(ctx, a.version, re, nil, fmt.Sprintf("enclave %s: retire epochs below %d", e, re.MinEpoch))
			retired = err == nil && rd.Commit != ""
		}
	}
	next := []string{}
	if !retired {
		next = append(next, "yadm enclave retire --enclave "+model.ShellQuote(string(e)))
	}
	next = append(next,
		"revoke "+string(who)+"'s access to the repository remote",
		"rotate every real secret stored in enclave "+string(e)+": "+string(who)+" keeps all keys up to epoch "+fmt.Sprint(head.Epoch),
	)
	return result{data: d, next: next}, err
}

func (a *app) cmdEnclaveRetire(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := requireIdentity(ctx)
	if err != nil {
		return notInit(err), err
	}
	e, err := pickEnclave(cmd, m)
	if err != nil {
		return result{}, err
	}
	ring, head, err := ringFor(m, e)
	if err != nil {
		return result{}, err
	}
	entry, err := ring.Retire(head, m.id, m.pendingPins())
	if err != nil {
		return result{}, err
	}
	d, err := m.writeEntry(ctx, a.version, entry, nil, fmt.Sprintf("enclave %s: retire epochs below %d", e, entry.MinEpoch))
	return result{data: d}, err
}

func (a *app) cmdEnclaveSetRecovery(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	dir, _ := cmd.Flags().GetString("recovery-dir")
	if dir == "" {
		return result{}, usagef("--recovery-dir with the current recovery identity is required")
	}
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	e, _ := cmd.Flags().GetString("enclave")
	if e == "" {
		return result{}, usagef("name the enclave with --enclave")
	}
	l, ok := m.snap.Enclaves[model.EnclaveName(e)]
	if !ok {
		return result{}, fmt.Errorf("enclave %s has no key log", e)
	}
	if l.Err != nil {
		return result{}, fmt.Errorf("enclave %s: %w", e, l.Err)
	}
	cur, err := crypt.LoadIdentity(dir)
	if err != nil {
		return result{}, fmt.Errorf("%w: recovery identity: %v", ErrRefused, err)
	}
	to, saved, err := recoveryMember(cmd, m.paths.Source, m.paths.State)
	if err != nil {
		return result{}, err
	}
	entry, err := crypt.SetRecovery(l.Head, cur, to, m.pendingPins())
	if err != nil {
		return result{}, err
	}
	d, err := m.writeEntry(ctx, a.version, entry, nil, fmt.Sprintf("enclave %s: set recovery", e))
	d.Recovery = saved
	return result{data: d}, err
}

func (a *app) cmdEnclaveJoin(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	expect, _ := cmd.Flags().GetString("expect")
	if expect == "" {
		return result{next: []string{"yadm enclave join " + model.ShellQuote(args[0]) + " --expect <fingerprint>"}},
			usagef("--expect is required: the fingerprint printed by `yadm enclave add` on a member, received out of band")
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	h, err := m.head(ctx)
	if err != nil {
		return result{}, err
	}
	e := model.EnclaveName(args[0])
	logs, err := m.keyLogs(ctx, h, []model.EnclaveName{e})
	if err != nil {
		return result{}, err
	}
	if len(logs[e]) == 0 {
		return result{next: []string{"yadm sync"}}, fmt.Errorf("enclave %s has no key log at main", e)
	}
	head, err := crypt.Join(logs[e], expect, crypt.FilePins(m.paths.State))
	if err != nil {
		return result{}, fmt.Errorf("enclave %s: %w", e, err)
	}
	member := false
	for _, mb := range head.Members {
		if mb.Machine == m.local.Machine {
			member = true
		}
	}
	pin, _ := crypt.FilePins(m.paths.State).Get(e)
	d := map[string]any{"enclave": e, "pinned": pin, "head_seq": head.Seq, "epoch": head.Epoch, "member": member}
	next := []string{"yadm apply"}
	if !member {
		next = []string{"ask a member: yadm enclave add " + string(m.local.Machine)}
	}
	return result{data: d, next: next}, nil
}

func (a *app) cmdEnclaveVerify(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	type row struct {
		Enclave model.EnclaveName `json:"enclave"`
		OK      bool              `json:"ok"`
		Seq     uint64            `json:"seq"`
		Epoch   model.Epoch       `json:"epoch"`
		Member  bool              `json:"member"`
		Error   string            `json:"error,omitempty"`
	}
	rows := []row{}
	var errs []error
	names := m.snap.Fleet.Enclaves()
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, e := range names {
		l, ok := m.snap.Enclaves[e]
		r := row{Enclave: e, OK: true}
		if ok {
			r.Seq, r.Epoch = l.Head.Seq, l.Head.Epoch
			r.Member = m.snap.Readable().CanOpen(e)
			if l.Err != nil {
				r.OK, r.Error = false, l.Err.Error()
				errs = append(errs, fmt.Errorf("enclave %s: %w", e, l.Err))
			}
		}
		rows = append(rows, r)
	}
	res := result{data: map[string]any{"enclaves": rows}}
	if len(errs) > 0 {
		return res, fmt.Errorf("%w: %w", ErrRefused, errors.Join(errs...))
	}
	return res, nil
}
