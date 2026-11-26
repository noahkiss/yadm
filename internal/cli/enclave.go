package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
)

func (a *app) registerEnclave(root *cobra.Command) {
	en := a.group(root, "enclave", "Enclave keys and membership")
	en.Long = enclaveLong
	leaf := a.leaf
	leaf(en, "list", "List enclaves, epochs and members", a.cmdEnclaveList)
	cr := leaf(en, "create <type>", "Create an enclave key log for a type", a.cmdEnclaveCreate)
	cr.Args = cobra.ExactArgs(1)
	addRecoveryFlags(cr)
	ad := leaf(en, "add <machine>", "Wrap the enclave keys to a machine (members only)", a.cmdEnclaveAdd)
	ad.Args = cobra.ExactArgs(1)
	ad.Long = enclaveAddLong
	ad.Flags().String("enclave", "", "enclave to add the machine to (default: the only enclave this machine opens)")
	ad.Flags().String("recipient", "", "the new machine's age recipient, from \"yadm machine\" on it (optional when a pinned key log vouches for it)")
	ad.Flags().String("sign-key", "", "the new machine's signing key, from \"yadm machine\" on it (optional when a pinned key log vouches for it)")
	rm := leaf(en, "remove <machine>", "Remove a member and start a new epoch", a.cmdEnclaveRemove)
	rm.Args = cobra.ExactArgs(1)
	rm.Flags().String("enclave", "", "enclave to remove the machine from (default: the only enclave this machine opens)")
	rm.Flags().Bool("confirm", false, "required: removal is not reversible")
	jn := leaf(en, "join <enclave>", "Pin an enclave's key log on this machine", a.cmdEnclaveJoin)
	jn.Args = cobra.ExactArgs(1)
	jn.Long = enclaveJoinLong
	jn.Flags().String("code", "", "join code XXXX-XXXX that \"yadm enclave add\" printed on the member, received out of band")
	jn.Flags().String("expect", "", "fingerprint of the key-log entry that added this machine, received out of band (instead of --code)")
	leaf(en, "verify", "Verify every key log against the local pins", a.cmdEnclaveVerify)
	od := leaf(en, "on-demand <enclave>", "Read an enclave on demand only on this machine: never apply, capture or back it up", a.cmdEnclaveOnDemand)
	od.Args = cobra.ExactArgs(1)
	od.Flags().Bool("off", false, "clear the mark: deliver the enclave again where types and membership say so")
	rt := leaf(en, "retire", "Stop opening ciphertext of older epochs for delivery (after a remove's reseal)", a.cmdEnclaveRetire)
	rt.Flags().String("enclave", "", "enclave to retire old epochs of (default: the only enclave this machine opens)")
	nr := leaf(en, "new-recovery <dir>", "Generate a recovery identity into a new directory; print its public keys for enclave create", a.cmdEnclaveNewRecovery)
	nr.Args = cobra.ExactArgs(1)
	nr.Long = newRecoveryLong
	nr.Flags().String("enclave", "", "the enclave type, to fill in the printed create command")
	sr := leaf(en, "set-recovery", "Name a new recovery identity, signed by the current one", a.cmdEnclaveSetRecovery)
	sr.Flags().String("enclave", "", "enclave whose recovery identity changes")
	sr.Flags().String("recovery-dir", "", "required: directory holding the current recovery identity")
	addRecoveryFlags(sr)
	rc := leaf(en, "recover <enclave> [path...]", "Read an enclave's sealed files with its recovery identity, when no member is left (--read-only)", a.cmdEnclaveRecover)
	rc.Long = enclaveRecoverLong
	rc.Flags().Bool("read-only", false, "required: read the enclave; writes nothing but --out (re-admitting a machine is not built yet)")
	rc.Flags().String("identity", "", "the recovery identity.age.key file (mode 0600), or - to read it from stdin")
	rc.Flags().String("out", "", "a new directory for the opened files (mode 0700, files 0600), or - to print one file to stdout")
	rc.Flags().String("expect", "", "fingerprint of the newest key-log entry, kept with the recovery identity; the log must contain it, and only the head anchors the log")
	rc.Flags().String("repo", "", "a clone of the remote to read main from (default: the source clone)")
}

const enclaveLong = `An enclave is a set of files only its member machines can read. Members hold
its keys; the key log under keys/<enclave>/ records who they are.

Add a machine to an enclave (host-b joins enclave "personal", host-a is a member):

  1. On host-b (the new machine): run "yadm init <remote>". It prints the
     machine id, its age recipient, its signing key, and the exact
     "enclave add" command for step 3. If host-b is not in fleet.toml yet,
     add it there and commit, as init's output says.
  2. On host-b, only if it should read the enclave on demand (never write its
     files into $HOME): run "yadm enclave on-demand personal" now, before join.
  3. On host-a (a member), with host-b's fleet name or its machine id, and the
     keys "yadm machine" prints on host-b:
       yadm enclave add host-b --enclave personal --recipient <age1...> --sign-key <key>
     When host-a has pinned another enclave that host-b is in, the flags may
     be left out, with host-b's machine id in place of its name
     ("yadm enclave add --help" says when).
       yadm sync
     add prints a join code, such as 7K3M-Q9TD.
  4. Carry the code to host-b yourself: read it off host-a's screen. Never copy
     it from the repository or from host-b's own output.
  5. On host-b:
       yadm sync
       yadm enclave join personal --code 7K3M-Q9TD
       yadm apply
     join pins the key log only when the code matches; otherwise it pins nothing.

"yadm enclave add --help" and "yadm enclave join --help" give the details.`

const enclaveAddLong = `Run on a machine that is already a member. add appends an "add" entry to the
enclave's key log, wraps the enclave keys to the new machine, commits and
pushes the entry, and prints two values for the new machine:

  join code    XXXX-XXXX, 8 characters; type it on the new machine:
               yadm enclave join <enclave> --code XXXX-XXXX
  fingerprint  the full entry hash, for "join --expect" instead of the code

Pass the code to the new machine out of band: read it off this screen. The
repository is the channel the code protects against. Computing the code takes
about a second on purpose.

The new machine's keys: "yadm machine" (or "yadm init") on it prints its
--recipient and --sign-key. Compare them on both screens before you pass them.

add may leave both flags out when this machine already holds the keys from a
trusted source: the verified head of another enclave's key log that this
machine has pinned lists the machine, and the entry that introduced that key
pair was signed by this machine or by a current member of this enclave, with
the signing key this enclave's log lists for it. A signer like that already
holds this enclave's keys, so a false key from it gains it nothing.

Without the flags, name the machine by its id (m-..., from "yadm machine" on
it), never by a fleet name: the id alone selects the keys, and any writer can
edit fleet.toml. add still asks for the flags when any pinned log lists other
keys for the machine, or when this enclave's log listed it before (a removed
machine comes back only with keys you compared). fleet.toml, status records
and logs this machine has not pinned are never a source of keys. Output
"keys from" names the source.`

const enclaveJoinLong = `Run on the new machine, after a member ran "yadm enclave add" for it and this
machine fetched the entry ("yadm sync"). join verifies the enclave's key log
and pins it on this machine. Without a pin, this machine never opens the
enclave's keys.

Give the value the member's "enclave add" printed, received out of band:

  yadm enclave join <enclave> --code XXXX-XXXX     (case and dash optional)
  yadm enclave join <enclave> --expect <fingerprint>

With --code, join recomputes the code from the newest entry that adds this
machine and pins only on a match. A wrong code pins nothing. Never copy the
code or fingerprint from this machine's own copy of the log.

For a machine that should read the enclave on demand only, run
"yadm enclave on-demand <enclave>" before join.`

func addRecoveryFlags(c *cobra.Command) {
	c.Flags().String("recovery-recipient", "", "age recipient of the offline recovery identity")
	c.Flags().String("recovery-sign-key", "", "signing key of the offline recovery identity")
	c.Flags().String("new-recovery", "", "generate a recovery identity into this new directory (outside the source and state); store it offline")
}

// recoveryMember reads the recovery flags. With --new-recovery it generates
// and saves a recovery identity.
func recoveryMember(cmd *cobra.Command, g recoveryGuard) (crypt.Member, string, error) {
	rr, _ := cmd.Flags().GetString("recovery-recipient")
	rs, _ := cmd.Flags().GetString("recovery-sign-key")
	dir, _ := cmd.Flags().GetString("new-recovery")
	switch {
	case dir != "" && (rr != "" || rs != ""):
		return crypt.Member{}, "", usagef("give --new-recovery or --recovery-recipient with --recovery-sign-key, not both")
	case dir != "":
		mem, abs, err := newRecovery(dir, "--new-recovery", g)
		return mem, abs, err
	case rr == "" || rs == "":
		return crypt.Member{}, "", usagef("the recovery identity is required: --recovery-recipient and --recovery-sign-key, or --new-recovery <dir>")
	}
	return crypt.Member{Machine: crypt.RecoveryMachine, Recipient: rr, SignKey: rs}, "", nil
}

// recoveryGuard says where a recovery identity must never be written: the
// tool's own directories, ~/.local, and on an initialized machine any path
// the manifest manages, an owned root or an applying glob, where the next
// sync would capture the secret.
type recoveryGuard struct {
	forbidden []string
	home      string
	plan      *manifest.Plan
}

func guardFor(p Paths) recoveryGuard {
	g := recoveryGuard{forbidden: []string{p.Source, p.State, p.Config}}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		g.home = home
		g.forbidden = append(g.forbidden, filepath.Join(home, ".local"))
	}
	return g
}

func (m *machineEnv) recoveryGuard() recoveryGuard {
	g := guardFor(m.paths)
	if m.home != "" {
		g.home = m.home
		g.forbidden = append(g.forbidden, filepath.Join(m.home, ".local"))
	}
	if m.snap != nil {
		g.plan = m.snap.Plan
	}
	return g
}

// check refuses dir when it lies inside a forbidden directory or names a
// managed path. It compares existing ancestors by file identity, so a
// symlink or a case-insensitive file system leads nowhere else, and also
// lexically, for a forbidden directory that does not exist yet.
func (g recoveryGuard) check(dir, what string) error {
	return g.checkFiles(dir, what, []string{crypt.AgeIdentityFile, crypt.SigningKeyFile})
}

// checkFiles is check for a directory that will hold the files names,
// slash paths relative to dir.
func (g recoveryGuard) checkFiles(dir, what string, names []string) error {
	real := resolveExisting(dir)
	for _, f := range g.forbidden {
		if f == "" {
			continue
		}
		roots := []string{f, resolveExisting(f)}
		for _, c := range []string{dir, real} {
			for _, r := range roots {
				if rel, err := filepath.Rel(r, c); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return usagef("%s must be outside %s", what, f)
				}
			}
		}
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		for q := real; ; q = filepath.Dir(q) {
			if qi, err := os.Stat(q); err == nil && os.SameFile(fi, qi) {
				return usagef("%s must be outside %s", what, f)
			}
			if filepath.Dir(q) == q {
				break
			}
		}
	}
	if g.plan == nil || g.home == "" {
		return nil
	}
	homes := []string{g.home, resolveExisting(g.home)}
	for _, c := range []string{dir, real} {
		for _, h := range homes {
			for _, f := range names {
				t, err := target(h, filepath.Join(c, filepath.FromSlash(f)))
				if err != nil {
					continue
				}
				_, managed := g.plan.Targets[t]
				_, globbed, _ := g.plan.GlobNew(t)
				if managed || globbed || g.plan.Root(t) != nil || g.plan.Protected(t) {
					return usagef("%s must not be a path yadm manages (%s): the next sync would capture the secret", what, t)
				}
			}
		}
	}
	return nil
}

// resolveExisting resolves the symlinks of p's deepest existing ancestor
// and appends the rest of p unchanged.
func resolveExisting(p string) string {
	for q := p; ; q = filepath.Dir(q) {
		if r, err := filepath.EvalSymlinks(q); err == nil {
			rel, err := filepath.Rel(q, p)
			if err != nil {
				return p
			}
			return filepath.Join(r, rel)
		}
		if filepath.Dir(q) == q {
			return p
		}
	}
}

// newRecovery generates a recovery identity into dir, a new directory with
// mode 0700 that g allows, and returns its public half. It refuses an
// existing dir, so it never overwrites a recovery identity, and checks the
// created directory again before it writes a key into it.
func newRecovery(dir, what string, g recoveryGuard) (crypt.Member, string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return crypt.Member{}, "", err
	}
	if err := g.check(abs, what); err != nil {
		return crypt.Member{}, "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return crypt.Member{}, "", err
	}
	if err := os.Mkdir(abs, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return crypt.Member{}, "", usagef("%s %s already exists; give a new directory, so no recovery identity is overwritten", what, abs)
		}
		return crypt.Member{}, "", err
	}
	// A parent swapped for a symlink since the check lands here.
	if err := g.check(abs, what); err != nil {
		os.Remove(abs)
		return crypt.Member{}, "", err
	}
	id, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
	if err == nil {
		err = id.Save(abs)
	}
	if err != nil {
		os.RemoveAll(abs)
		return crypt.Member{}, "", err
	}
	return id.Member(), abs, nil
}

const newRecoveryLong = `Generate an enclave's recovery identity on this machine, for an enclave that
another machine creates. Run it on a machine you trust with the secret, not on
the creator. It needs no enclave membership and no "yadm init".

The directory must not exist yet. It must be outside yadm's source, state
and config directories and ~/.local, symlinks resolved. On an initialized
machine it must also be outside every path the manifest manages, owned roots
included. new-recovery creates the directory with mode 0700 and writes two
secret files with mode 0600:

  identity.age.key   the age identity every key-log entry wraps the keys to
  identity.sign.key  the Ed25519 key that signs "recover" and "set-recovery"

It prints the public half and the command to run on the creating machine:

  yadm enclave create <type> --recovery-recipient <age1...> --recovery-sign-key <key>

Store both files in a password manager or other offline place, then delete
the directory from disk. Only the public values travel to the creator. To use
the identity later ("set-recovery --recovery-dir"), restore the two files into
a directory with mode 0700.`

func (a *app) cmdEnclaveNewRecovery(cmd *cobra.Command, args []string) (result, error) {
	// It needs no init; on an initialized machine the guard also knows the
	// manifest's managed paths and owned roots.
	// A machine that is set up but fails to load refuses: the guard would
	// not know its owned roots.
	var g recoveryGuard
	if m, err := openLoaded(cmd.Context()); err == nil {
		g = m.recoveryGuard()
	} else if !errors.Is(err, errNotInitialized) {
		return result{}, fmt.Errorf("new-recovery needs the manifest to keep the identity out of managed paths: %w", err)
	} else {
		p, err := DefaultPaths()
		if err != nil {
			return result{}, err
		}
		g = guardFor(p)
	}
	mem, dir, err := newRecovery(args[0], "the recovery directory", g)
	if err != nil {
		return result{}, err
	}
	typ, _ := cmd.Flags().GetString("enclave")
	if typ == "" {
		typ = "<type>"
	} else {
		typ = model.ShellQuote(typ)
	}
	create := fmt.Sprintf("yadm enclave create %s --recovery-recipient %s --recovery-sign-key %s", typ, model.ShellQuote(mem.Recipient), model.ShellQuote(mem.SignKey))
	d := map[string]any{"dir": dir, "recipient": mem.Recipient, "sign_key": mem.SignKey, "create": create}
	next := []string{
		"on the creating machine: " + create,
		"store " + filepath.Join(dir, crypt.AgeIdentityFile) + " and " + filepath.Join(dir, crypt.SigningKeyFile) + " in a password manager, then delete " + dir,
	}
	text := fmt.Sprintf("recovery identity in %s (store it offline, then delete it here)\nrecipient %s\nsign_key  %s\non the creating machine:\n  %s", dir, mem.Recipient, mem.SignKey, create)
	return result{data: d, next: next, text: text}, nil
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
		role := "not a member"
		switch {
		case info.Error != "":
			role = "refused"
		case info.Member && info.OnDemand:
			role = "member (on demand)"
		case info.Member:
			role = "member"
		}
		fmt.Fprintf(&b, "%-12s seq %d epoch %d %s; members %v %s\n", e, info.Seq, info.Epoch, role, info.Members, info.Error)
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
	JoinCode    string            `json:"join_code,omitempty"` // add only: the short form of the fingerprint
	Members     []model.MachineID `json:"members"`
	Commit      model.CommitID    `json:"commit"`
	Recovery    string            `json:"recovery_dir,omitempty"`
	KeysFrom    string            `json:"keys_from,omitempty"` // add only: "flags", or the pinned key log that vouched for the keys
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

// entryBuild computes a key-log entry, plus the reseal capture an entry
// that starts an epoch needs, from m.snap.
type entryBuild func(ctx context.Context) (crypt.LogEntry, *apply.Capture, error)

// writeEntry commits a key-log entry (plus a reseal capture) on main through
// sync.Commit, so the gate and the lock apply, pushes it, and pins it. The
// pin moves only after the commit lands. The caller has run build once to
// refuse early; writeEntry runs it again under the commit's hold of the
// sync lock, on the main the commit lands on, so an entry another process
// appended meanwhile is extended, never overwritten. A sequence number the
// source already holds is refused: the key log is append-only. It returns
// the entry and reseal that landed.
func (m *machineEnv) writeEntry(ctx context.Context, version string, enc model.EnclaveName, subject string, build entryBuild) (entryData, crypt.LogEntry, *apply.Capture, error) {
	var e crypt.LogEntry
	var reseal *apply.Capture
	opts := sync.CommitOptions{
		Message:      subject,
		ChangesScope: model.Scope(enc),
		// A reseal lands whole with its entry, or nothing lands: an entry
		// that starts an epoch must never commit without the reseal.
		Atomic: true,
		Push:   true,
		Build: func(ctx context.Context) (*apply.Capture, []store.Change, error) {
			if _, err := m.reload(ctx); err != nil {
				return nil, nil, err
			}
			x, r, err := build(ctx)
			if err != nil {
				return nil, nil, err
			}
			p := crypt.LogPath(x.Enclave, x.Seq)
			if _, ok := m.snap.Tree[p]; ok || x.Enclave != enc {
				return nil, nil, fmt.Errorf("%w: key log of %s already holds seq %d", crypt.ErrBrokenChain, x.Enclave, x.Seq)
			}
			b, err := crypt.MarshalLogEntry(x)
			if err != nil {
				return nil, nil, err
			}
			e, reseal = x, r
			cp := r
			if cp == nil {
				cp = &apply.Capture{}
			}
			return cp, []store.Change{{Path: p, Blob: b, Mode: 0o100644}}, nil
		},
	}
	rep, pushErr, err := m.commitThrough(ctx, version, opts)
	if e.Enclave == "" {
		if err == nil {
			err = fmt.Errorf("enclave %s: no key-log entry was written", enc)
		}
		return entryData{Enclave: enc, Members: []model.MachineID{}}, e, nil, err
	}
	fp, ferr := crypt.Fingerprint(e)
	if ferr != nil {
		return entryData{}, e, reseal, errors.Join(err, ferr)
	}
	d := entryData{Enclave: e.Enclave, Op: e.Op, Seq: e.Seq, Epoch: e.Epoch, Subject: e.Subject, Fingerprint: fp, Members: []model.MachineID{}}
	for _, mb := range e.Members {
		d.Members = append(d.Members, mb.Machine)
	}
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
		return d, e, reseal, err
	}
	pin, perr := crypt.PinOf(e)
	if perr == nil {
		perr = crypt.FilePins(m.paths.State).Set(e.Enclave, pin)
	}
	return d, e, reseal, errors.Join(err, perr)
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
	rec, dir, err := recoveryMember(cmd, m.recoveryGuard())
	if err != nil {
		return result{}, err
	}
	build := func(context.Context) (crypt.LogEntry, *apply.Capture, error) {
		if l, ok := m.snap.Enclaves[e]; ok && l.Head.Seq > 0 {
			return crypt.LogEntry{}, nil, fmt.Errorf("enclave %s already has a key log", e)
		}
		entry, _, err := crypt.Create(e, m.id, rec, m.pendingPins())
		return entry, nil, err
	}
	if _, _, err := build(ctx); err != nil {
		return result{}, err
	}
	d, _, _, err := m.writeEntry(ctx, a.version, e, "enclave "+string(e)+": create", build)
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
	if (recipient == "") != (signKey == "") {
		return result{}, usagef("give --recipient and --sign-key together, or neither")
	}
	e, err := pickEnclave(cmd, m)
	if err != nil {
		return result{}, err
	}
	var who model.MachineID
	if recipient == "" {
		// The id alone selects the keys, so it must not come from
		// fleet.toml: a writer could point a name or nickname at another
		// machine that a pinned log vouches for.
		if !strings.HasPrefix(args[0], "m-") {
			return result{next: []string{"on " + args[0] + ": yadm machine (it prints its machine id and keys)"}},
				usagef("without --recipient and --sign-key, name the machine by its id (m-..., from `yadm machine` on it), not by a fleet name: any writer can edit fleet.toml")
		}
		who = model.MachineID(args[0])
	} else if who, err = machineID(m, args[0]); err != nil {
		return result{}, usagef("%v", err)
	}
	_, head, err := ringFor(m, e)
	if err != nil {
		return result{}, err
	}
	vouched, listed, removed, err := m.vouchedKeys(ctx, e, head, who)
	if err != nil {
		return result{}, err
	}
	var warn []string
	from := "flags"
	if recipient == "" {
		v, err := pickVouched(who, vouched, listed, removed)
		if err != nil {
			return result{next: []string{"on " + args[0] + ": yadm machine (it prints the recipient and signing key)"}}, err
		}
		recipient, signKey, from = v.member.Recipient, v.member.SignKey, v.from
	} else {
		for _, v := range listed {
			if v.member.Recipient != recipient || v.member.SignKey != signKey {
				warn = append(warn, fmt.Sprintf("the flags differ from the keys the key log of %s lists for %s; check `yadm machine` on it", v.from, who))
			}
		}
	}
	member := crypt.Member{Machine: who, Recipient: recipient, SignKey: signKey}
	build := func(context.Context) (crypt.LogEntry, *apply.Capture, error) {
		ring, head, err := ringFor(m, e)
		if err != nil {
			return crypt.LogEntry{}, nil, err
		}
		entry, err := ring.Add(head, member, m.id, m.pendingPins())
		return entry, nil, err
	}
	if _, _, err := build(ctx); err != nil {
		return result{}, err
	}
	d, _, _, err := m.writeEntry(ctx, a.version, e, fmt.Sprintf("enclave %s: add %s", e, who), build)
	d.KeysFrom = from
	if d.Commit == "" {
		return result{data: d, next: warn}, err
	}
	code, cerr := crypt.JoinCode(d.Fingerprint)
	if cerr != nil {
		return result{data: d}, errors.Join(err, cerr)
	}
	d.JoinCode = code
	next := append(warn, "yadm sync", fmt.Sprintf("on %s, after it fetches: yadm enclave join %s --code %s", who, model.ShellQuote(string(e)), code))
	text := fmt.Sprintf("join code   %s\nfingerprint %s\nkeys from   %s\n", code, d.Fingerprint, from)
	return result{data: d, next: next, text: text}, err
}

// vouch is a key pair of a machine that a pinned key log vouches for.
type vouch struct {
	member crypt.Member
	from   string // "<enclave> seq <n>"
}

// vouchedKeys reads the pinned key logs of every enclave but e for machine
// who (design section 7.3). vouched holds the key pairs this machine may
// add to e without the human passing them: the verified head of a pinned
// log lists them, and the entry that introduced that pair was signed by
// this machine or by a current member of e, under the same signing key
// that e's head lists for it. Such a signer already holds e's keys, so
// vouching for a false key gives it no access it lacks. listed holds every
// pair a verified pinned log lists for who, trusted signer or not. removed
// reports that e's own log once listed who. fleet.toml, status records and
// unpinned logs carry no trusted keys: any writer can edit or forge them.
func (m *machineEnv) vouchedKeys(ctx context.Context, e model.EnclaveName, head crypt.LogEntry, who model.MachineID) (vouched, listed []vouch, removed bool, err error) {
	// A signer is trusted by its signing key, never by its id alone: a
	// member of the other log could list a target member's id there under
	// keys it holds.
	trusted := map[crypt.Member]bool{}
	if m.id != nil {
		self := m.id.Member()
		trusted[crypt.Member{Machine: self.Machine, SignKey: self.SignKey}] = true
	}
	for _, mb := range head.Members {
		trusted[crypt.Member{Machine: mb.Machine, SignKey: mb.SignKey}] = true
	}
	pins := crypt.FilePins(m.paths.State)
	pinned := map[model.EnclaveName]*crypt.Pin{}
	var others []model.EnclaveName
	for _, x := range m.snap.Fleet.Enclaves() {
		if x == e {
			continue
		}
		p, err := pins.Get(x)
		if err != nil {
			return nil, nil, false, err
		}
		if p != nil {
			pinned[x] = p
			others = append(others, x)
		}
	}
	sort.Slice(others, func(i, j int) bool { return others[i] < others[j] })
	logs, err := m.keyLogs(ctx, m.snap.Commit, append([]model.EnclaveName{e}, others...))
	if err != nil {
		return nil, nil, false, err
	}
	for _, x := range logs[e] {
		if slices.ContainsFunc(x.Members, func(mb crypt.Member) bool { return mb.Machine == who }) {
			removed = true
		}
	}
	for _, x := range others {
		mb, signer, ok, err := crypt.Vouched(logs[x], pinned[x], who)
		if err != nil || !ok {
			continue // a refused log vouches for nothing
		}
		v := vouch{member: mb, from: fmt.Sprintf("%s seq %d", x, len(logs[x]))}
		listed = append(listed, v)
		if trusted[crypt.Member{Machine: signer.Machine, SignKey: signer.SignKey}] {
			vouched = append(vouched, v)
		}
	}
	return vouched, listed, removed, nil
}

// pickVouched chooses the keys an add without flags wraps to. It refuses
// when no log vouches, when any verified pinned log lists other keys for
// who than the vouching one, and when the target enclave once listed who:
// a removed machine comes back only with keys the human compared.
func pickVouched(who model.MachineID, vouched, listed []vouch, removed bool) (vouch, error) {
	if removed {
		return vouch{}, usagef("the key log already listed %s once; to add it again, pass --recipient and --sign-key from `yadm machine` on it", who)
	}
	if len(vouched) == 0 {
		return vouch{}, usagef("no key log this machine has pinned vouches for %s's keys (see `yadm enclave add --help`); pass --recipient and --sign-key", who)
	}
	for _, v := range listed {
		if v.member != vouched[0].member {
			return vouch{}, usagef("pinned key logs list different keys for %s (%s, %s); compare with `yadm machine` on it and pass --recipient and --sign-key", who, vouched[0].from, v.from)
		}
	}
	return vouched[0], nil
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
	if m.snap.IsOnDemand(e) {
		// The reseal commit passes the gate, whose checks read plaintext
		// from a temp file in the state directory: never for an on-demand
		// enclave. Refuse before writing any entry.
		return result{next: []string{"yadm enclave on-demand " + model.ShellQuote(string(e)) + " --off"}},
			fmt.Errorf("%w: %s is on demand on this machine, and its reseal would need the commit gate to read its plaintext here; run remove on a machine that receives %s", ErrRefused, e, e)
	}
	who, err := machineID(m, args[0])
	if err != nil {
		return result{}, usagef("%v", err)
	}
	var head crypt.LogEntry
	var newRing *crypt.Keyring
	build := func(ctx context.Context) (crypt.LogEntry, *apply.Capture, error) {
		ring, h, err := ringFor(m, e)
		if err != nil {
			return crypt.LogEntry{}, nil, err
		}
		entry, nr, err := ring.Remove(h, who, m.id, m.pendingPins())
		if err != nil {
			return crypt.LogEntry{}, nil, err
		}
		// Reseal under the new epoch with a snapshot that holds the new keyring.
		rings := map[model.EnclaveName]*crypt.Keyring{}
		for k, v := range m.snap.Readable().Rings {
			rings[k] = v
		}
		rings[e] = nr
		snap := *m.snap
		snap.Keys = &crypt.Set{Rings: rings}
		snap.Crypto = apply.SetCrypto(snap.Keys)
		c, err := m.eng.Reseal(ctx, &snap, e)
		if err != nil {
			return crypt.LogEntry{}, nil, err
		}
		head, newRing = h, nr
		return entry, &c, nil
	}
	_, first, err := build(ctx)
	if err != nil {
		return result{}, err
	}
	d, entry, c, err := m.writeEntry(ctx, a.version, e, fmt.Sprintf("enclave %s: remove %s", e, who), build)
	if c == nil {
		c = first
	}
	d.Resealed = c.Paths
	if d.Commit == "" {
		// Nothing landed: no entry, no pin, no epoch change.
		return result{data: d, next: heldNext(d.Holds)}, removeHeld(e, who, c.Paths, d.Holds, err)
	}
	if err == nil {
		err = m.resealLanded(ctx, d.Commit, *c)
	}
	retired := false
	if err == nil {
		// The reseal landed: retire the old epochs now, so a forgery pushed
		// under an old key is never opened for delivery again.
		var re crypt.LogEntry
		if re, err = newRing.Retire(entry, m.id, m.pendingPins()); err == nil {
			var rd entryData
			rd, _, _, err = m.writeEntry(ctx, a.version, e, fmt.Sprintf("enclave %s: retire epochs below %d", e, re.MinEpoch), retireBuild(m, e))
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

// removeHeld is the error of a remove whose atomic commit did not land: the
// gate or a conflict held part of the reseal, so neither the entry nor the
// reseal was committed.
func removeHeld(e model.EnclaveName, who model.MachineID, resealed []model.Target, holds []model.Hold, cause error) error {
	var held []string
	for _, h := range holds {
		if slices.Contains(resealed, h.Target) && !slices.Contains(held, string(h.Target)) {
			held = append(held, string(h.Target))
		}
	}
	sort.Strings(held)
	if len(held) == 0 {
		return fmt.Errorf("remove %s from %s did not commit; the key log, pins and epoch are unchanged: %v", who, e, cause)
	}
	return fmt.Errorf("remove %s from %s did not commit: the commit gate held the reseal of %s; the key log, pins and epoch are unchanged; settle the holds, then run remove again", who, e, strings.Join(held, ", "))
}

// heldNext collects the suggested commands of holds, without repeats.
func heldNext(holds []model.Hold) []string {
	var out []string
	for _, h := range holds {
		for _, n := range h.Next {
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	return out
}

// resealLanded checks that commit holds every resealed source as the
// reseal wrote it. The atomic commit makes a partial reseal unlikely; a
// conflict resolved against a fetched source is the one way left, and then
// the old epochs must stay open until a member reseals again.
func (m *machineEnv) resealLanded(ctx context.Context, commit model.CommitID, c apply.Capture) error {
	var missing []string
	for i, ch := range c.Changes {
		b, err := m.repo.ReadPath(ctx, commit, ch.Path)
		if err != nil || !bytes.Equal(b, ch.Blob) {
			missing = append(missing, string(c.Paths[i]))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("the remove entry committed, but the reseal of %s did not land as written; old epochs are not retired: a member reseals them, then runs yadm enclave retire", strings.Join(missing, ", "))
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
	build := retireBuild(m, e)
	entry, _, err := build(ctx)
	if err != nil {
		return result{}, err
	}
	d, _, _, err := m.writeEntry(ctx, a.version, e, fmt.Sprintf("enclave %s: retire epochs below %d", e, entry.MinEpoch), build)
	return result{data: d}, err
}

// retireBuild retires the epochs below the head's of e.
func retireBuild(m *machineEnv, e model.EnclaveName) entryBuild {
	return func(context.Context) (crypt.LogEntry, *apply.Capture, error) {
		ring, head, err := ringFor(m, e)
		if err != nil {
			return crypt.LogEntry{}, nil, err
		}
		entry, err := ring.Retire(head, m.id, m.pendingPins())
		return entry, nil, err
	}
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
	to, saved, err := recoveryMember(cmd, m.recoveryGuard())
	if err != nil {
		return result{}, err
	}
	enc := model.EnclaveName(e)
	build := func(context.Context) (crypt.LogEntry, *apply.Capture, error) {
		l, ok := m.snap.Enclaves[enc]
		if !ok || l.Err != nil {
			return crypt.LogEntry{}, nil, fmt.Errorf("enclave %s: key log not readable: %v", e, l.Err)
		}
		entry, err := crypt.SetRecovery(l.Head, cur, to, m.pendingPins())
		return entry, nil, err
	}
	if _, _, err := build(ctx); err != nil {
		return result{}, err
	}
	d, _, _, err := m.writeEntry(ctx, a.version, enc, fmt.Sprintf("enclave %s: set recovery", e), build)
	d.Recovery = saved
	return result{data: d}, err
}

func (a *app) cmdEnclaveJoin(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	expect, _ := cmd.Flags().GetString("expect")
	code, _ := cmd.Flags().GetString("code")
	switch {
	case expect == "" && code == "":
		return result{next: []string{"yadm enclave join " + model.ShellQuote(args[0]) + " --code <code>"}},
			usagef("--code is required: the join code printed by `yadm enclave add` on a member, received out of band (or --expect <fingerprint>)")
	case expect != "" && code != "":
		return result{}, usagef("give --code or --expect, not both")
	case code != "":
		if _, err := crypt.ParseJoinCode(code); err != nil {
			return result{}, usagef("%v", err)
		}
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
	var head crypt.LogEntry
	if code != "" {
		head, err = crypt.JoinWithCode(logs[e], code, m.local.Machine, crypt.FilePins(m.paths.State))
	} else {
		head, err = crypt.Join(logs[e], expect, crypt.FilePins(m.paths.State))
	}
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
