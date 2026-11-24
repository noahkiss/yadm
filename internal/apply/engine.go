package apply

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/render"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// Load reads fleet.toml, manifest.toml and every key log at rev, verifies
// the key logs, builds this machine's Context (with observed facts from
// local state) and resolves the plan.
func (e *Engine) Load(ctx context.Context, rev model.CommitID) (*Snapshot, error) {
	if e.Store == nil {
		return nil, errors.New("apply: no store")
	}
	resolved, err := e.Store.ResolveRef(ctx, string(rev))
	if err != nil {
		return nil, err
	}
	rev = resolved
	entries, err := e.Store.ListTree(ctx, rev)
	if err != nil {
		return nil, err
	}
	tree := make(map[model.SourcePath]store.TreeEntry, len(entries))
	paths := make([]model.SourcePath, 0, len(entries))
	for _, te := range entries {
		tree[te.Path] = te
		paths = append(paths, te.Path)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })

	fb, err := e.Store.ReadPath(ctx, rev, fleet.FileName)
	if err != nil {
		return nil, err
	}
	fl, err := fleet.Parse(fb)
	if err != nil {
		return nil, err
	}
	m, ok := fl.Machines[e.Self]
	if !ok {
		return nil, fmt.Errorf("machine %s is not in %s", e.Self, fleet.FileName)
	}
	m.ID = e.Self
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	mctx := model.Context{Machine: m, Home: e.Home, User: e.User, Observed: st.Observed}

	mb, err := e.Store.ReadPath(ctx, rev, manifest.FileName)
	if err != nil {
		return nil, err
	}
	man, err := manifest.Parse(mb)
	if err != nil {
		return nil, err
	}
	if err := man.LoadIncludes(func(p model.SourcePath) ([]byte, error) { return e.Store.ReadPath(ctx, rev, p) }); err != nil {
		return nil, err
	}

	logs := map[model.EnclaveName][]crypt.LogEntry{}
	for _, enc := range fl.Enclaves() {
		prefix := string(crypt.LogDir(enc)) + "/"
		for _, p := range paths {
			if !strings.HasPrefix(string(p), prefix) || !strings.HasSuffix(string(p), ".toml") {
				continue
			}
			b, err := e.Store.ReadBlob(ctx, tree[p].Blob)
			if err != nil {
				return nil, err
			}
			le, err := crypt.ParseLogEntry(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			logs[enc] = append(logs[enc], le)
		}
	}
	all, loads, err := crypt.LoadSet(logs, e.Pins, e.Identity)
	if err != nil {
		return nil, err
	}
	// Filter after LoadSet: pins still advance and a bad log is still
	// refused for an on-demand enclave; only delivery loses its keys.
	onDemand := map[model.EnclaveName]bool{}
	for _, x := range e.OnDemand {
		onDemand[x] = true
	}
	keys := all.Only(func(x model.EnclaveName) bool { return !onDemand[x] })
	// The vocabulary carries the manifest's named conditions, so
	// templates may say {% if cond:NAME %} as well.
	voc, err := man.Vocabulary(fl.Vocabulary())
	if err != nil {
		return nil, err
	}
	plan, err := man.Resolve(mctx, paths, voc)
	if err != nil {
		return nil, err
	}
	ExpandRoots(man, plan, paths, func(r manifest.Root) bool { return e.rootAccepted(st, r) })
	return &Snapshot{
		Commit:   rev,
		Fleet:    fl,
		Manifest: man,
		Plan:     plan,
		Context:  mctx,
		Keys:     keys,
		ReadKeys: all,
		OnDemand: onDemand,
		Enclaves: loads,
		Render:   render.New(voc),
		Crypto:   SetCrypto(keys),
		Tree:     tree,
	}, nil
}

func (e *Engine) snapshot(ctx context.Context, rev model.CommitID) (*Snapshot, error) {
	if e.LoadSnapshot != nil {
		return e.LoadSnapshot(ctx, rev)
	}
	return e.Load(ctx, rev)
}

// noSealer opens nothing: what a machine with no keys sees.
type noSealer struct{}

func (noSealer) CanOpen(model.EnclaveName) bool { return false }
func (noSealer) SealValue(model.EnclaveName, string, []byte) (string, error) {
	return "", crypt.ErrNotMember
}
func (noSealer) OpenValue(model.EnclaveName, string, string) ([]byte, error) {
	return nil, crypt.ErrNotMember
}
func (noSealer) SealRegion(model.EnclaveName, string, []byte) (string, error) {
	return "", crypt.ErrNotMember
}
func (noSealer) OpenRegion(model.EnclaveName, string, string) ([]byte, error) {
	return nil, crypt.ErrNotMember
}

// cr returns the snapshot's Crypto, falling back to Keys. It may be nil.
func (s *Snapshot) cr() Crypto {
	if s.Crypto != nil {
		return s.Crypto
	}
	if s.Keys != nil {
		return SetCrypto(s.Keys)
	}
	return nil
}

// sealer returns the Sealer for intra-file rules. Refused enclaves never open.
func (s *Snapshot) sealer() rules.Sealer {
	c := s.cr()
	if c == nil {
		return noSealer{}
	}
	return refusing{c, s.Enclaves}
}

// Readable returns every key this machine holds, on-demand enclaves
// included. Use it only for bytes that go to stdout or into ciphertext,
// never for bytes written to $HOME, backups or the state.
func (s *Snapshot) Readable() *crypt.Set {
	if s.ReadKeys != nil {
		return s.ReadKeys
	}
	return s.Keys
}

// IsOnDemand reports whether this machine reads enclave enc on demand only.
func (s *Snapshot) IsOnDemand(enc model.EnclaveName) bool { return s.OnDemand[enc] }

// CanRead reports whether this machine may open enc to print it: it holds
// the key, on demand or not, and the enclave's key log was not refused.
func (s *Snapshot) CanRead(enc model.EnclaveName) bool {
	if l, ok := s.Enclaves[enc]; ok && l.Err != nil {
		return false
	}
	return s.Readable().CanOpen(enc)
}

// onDemandError is the refusal for an enclave this machine reads on demand
// only. The machine is a key-log member, so the text says so; it still
// matches crypt.ErrNotMember, since it never seals or captures here.
type onDemandError struct{ enc model.EnclaveName }

func (e onDemandError) Error() string {
	return fmt.Sprintf("%s: this machine is a member on demand only and never seals or captures it; run this on a member that receives %s", e.enc, e.enc)
}

func (e onDemandError) Unwrap() error { return crypt.ErrNotMember }

// notOpen is the error for an enclave this snapshot cannot open:
// crypt.ErrNotMember with the enclave's name, or onDemandError for an
// enclave this machine holds the keys of but reads on demand only.
func (s *Snapshot) notOpen(enc model.EnclaveName) error {
	if s != nil && s.IsOnDemand(enc) && s.CanRead(enc) {
		return onDemandError{enc}
	}
	return fmt.Errorf("%w: %s", crypt.ErrNotMember, enc)
}

// notMemberDetail is the hold detail for a file this machine cannot seal.
func (s *Snapshot) notMemberDetail(enc model.EnclaveName) string {
	if s != nil && s.IsOnDemand(enc) && s.CanRead(enc) {
		return "member of " + string(enc) + " on demand only; never sealed here"
	}
	return "not a member of " + string(enc) + "; cannot seal"
}

// canOpen reports whether this machine may open an enclave in this snapshot.
func (s *Snapshot) canOpen(enc model.EnclaveName) bool {
	if l, ok := s.Enclaves[enc]; ok && l.Err != nil {
		return false
	}
	c := s.cr()
	return c != nil && c.CanOpen(enc)
}

// refusing wraps a Crypto so an enclave whose key log was refused never opens.
type refusing struct {
	Crypto
	loads map[model.EnclaveName]crypt.EnclaveLoad
}

func (r refusing) CanOpen(e model.EnclaveName) bool {
	if l, ok := r.loads[e]; ok && l.Err != nil {
		return false
	}
	return r.Crypto.CanOpen(e)
}

// desired is what one target should hold on this machine.
type desired struct {
	res        manifest.Resolved
	scope      model.Scope
	bytes      []byte
	mode       fs.FileMode
	blob       string
	sealed     bool   // not delivered here: non-member or refused enclave
	reason     string // why sealed
	renderHash string
	key        string // applyKey of the entry at the snapshot
}

// readSource returns the raw source bytes of a resolved target at the snapshot.
func (e *Engine) readSource(ctx context.Context, snap *Snapshot, p model.SourcePath) ([]byte, string, error) {
	if te, ok := snap.Tree[p]; ok && te.Blob != "" {
		b, err := e.Store.ReadBlob(ctx, te.Blob)
		return b, te.Blob, err
	}
	b, err := e.Store.ReadPath(ctx, snap.Commit, p)
	return b, "", err
}

// modeOf is an entry's target mode. An explicit `mode` wins. Otherwise the
// mode follows the source, sealed or not: 0755 for an executable source,
// else 0644. Under a private directory (.ssh, .gnupg) group and other
// access is removed: 0700 or 0600.
func modeOf(snap *Snapshot, r manifest.Resolved) fs.FileMode {
	if r.Entry.Mode != 0 {
		return r.Entry.Mode.Perm()
	}
	return sourceDefaultMode(snap, r)
}

// ModeAccepted reports whether a target's live mode is not drift against
// the mode its entry wants: it grants no bit outside want (a stricter mode,
// such as 0640 from a tool writing under umask 027 where 0644 is wanted),
// and keeps the owner's execute bit when want has it, since a script that
// loses it stops working. One wider bit is noise, not drift: group write on
// a file whose group may already read it (0664 from a tool writing under
// umask 002 where 0644 is wanted). Git does not record it, so no capture
// could settle it. An owner-only want (0600, 0700), a want the owner may not
// write (0444), a target under .ssh or .gnupg (ssh refuses a group-writable
// file there, whatever mode the manifest asks for) and other write stay
// strict.
func ModeAccepted(t model.Target, live, want fs.FileMode) bool {
	live, want = live.Perm(), want.Perm()
	extra := live &^ want
	if want&0o240 == 0o240 && !privateTarget(t) {
		extra &^= 0o020
	}
	if extra != 0 {
		return false
	}
	return want&0o100 == 0 || live&0o100 != 0
}

// want is the mode the entry asked for when the target was last recorded.
func (ts TargetState) want() fs.FileMode {
	if ts.Want != 0 {
		return fs.FileMode(ts.Want).Perm()
	}
	return fs.FileMode(ts.Mode).Perm()
}

// TargetMode is the mode apply writes r's target with in snap: an explicit
// `mode`, else the source's (0755 or 0644), owner-only under .ssh and .gnupg.
func TargetMode(snap *Snapshot, r manifest.Resolved) fs.FileMode { return modeOf(snap, r) }

// sourceDefaultMode is the mode a target gets from its source alone.
func sourceDefaultMode(snap *Snapshot, r manifest.Resolved) fs.FileMode {
	plain := r
	plain.Entry.Enclave = "" // enclave files follow the source too
	plain.Entry.Mode = 0     // the default, not the explicit mode
	m := plain.FileMode(snap.Tree[r.Source].Mode&0o111 != 0).Perm()
	if privateTarget(r.Target) {
		m &^= 0o077
	}
	return m
}

// widenedMode reports an explicit manifest mode that grants a file with
// enclave plaintext (a whole sealed file, sealed values or regions) a
// permission bit its source mode does not. Any pusher can edit the
// manifest, so it may not widen who can read a member's plaintext.
func widenedMode(snap *Snapshot, r manifest.Resolved) (string, bool) {
	en := r.Entry
	if en.Mode == 0 || (en.Enclave == "" && len(en.Seal) == 0 && !en.Regions) {
		return "", false
	}
	want, def := en.Mode.Perm(), sourceDefaultMode(snap, r)
	if want&^def == 0 {
		return "", false
	}
	return fmt.Sprintf("the manifest sets mode %#o, wider than %#o, on a file with enclave plaintext; a manifest may not widen such a file's mode", want, def), true
}

// hasPlaintext reports whether an entry's target holds enclave plaintext.
func hasPlaintext(en manifest.Entry) bool {
	return en.Enclave != "" || len(en.Seal) > 0 || en.Regions
}

// modeWidenedSince reports, for a target with enclave plaintext whose last
// apply used an explicit `mode`, a mode that grants a permission bit that
// explicit mode lacks: a pusher who drops an owner's `mode = 0o600`, or sets
// a wider one. It holds until allowed here (`yadm protection allow`). A
// mode that followed the source still follows it.
func (e *Engine) modeWidenedSince(snap *Snapshot, r manifest.Resolved, ts TargetState, have bool) (string, bool) {
	if !have || ts.ExplicitMode == 0 || !hasPlaintext(r.Entry) {
		return "", false
	}
	want, was := modeOf(snap, r), fs.FileMode(ts.ExplicitMode).Perm()
	if want&^was == 0 || e.allowed(KindMode, string(r.Target), modeHash(r.Target, want)) {
		return "", false
	}
	return fmt.Sprintf("the manifest widens this file's mode from %#o to %#o; the file has enclave plaintext, so it is neither applied nor captured until allowed on this machine", was, want), true
}

// modeHash is the allow hash for writing target t with mode m.
func modeHash(t model.Target, m fs.FileMode) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("mode\x00%s\x00%o", t, m.Perm())))
	return hex.EncodeToString(h[:])
}

// privateDirs are top-level directories whose files and subdirectories are
// kept owner-only when the manifest sets no mode.
var privateDirs = map[string]bool{".ssh": true, ".gnupg": true}

// privateTarget reports whether a target lies under a private directory.
func privateTarget(t model.Target) bool {
	first, _, nested := strings.Cut(string(t), "/")
	return nested && privateDirs[first]
}

// sourceMode is the git mode a change to an existing source path keeps: the
// executable bit follows the path's current tree entry, sealed or not.
func sourceMode(snap *Snapshot, p model.SourcePath) uint32 {
	if te, ok := snap.Tree[p]; ok && te.Mode == gitModeExec {
		return gitModeExec
	}
	return gitModeFile
}

// produce computes the target bytes for one resolved entry. lv is the live
// target, which keep rules merge into. known is the source blob this
// machine last applied or captured for the target ("" for none): a source
// blob that differs from it is new here, and its sealed parts open only
// under the enclave's current epoch (crypt.Set.Strict). A removed member
// still holds the old keys, so new content under an old epoch is held until
// a member reseals it.
func (e *Engine) produce(ctx context.Context, snap *Snapshot, r manifest.Resolved, lv []byte, known string) (desired, error) {
	d := desired{res: r, scope: r.Entry.Scope(), mode: modeOf(snap, r), key: applyKey(snap, r)}
	if enc := r.Entry.Enclave; enc != "" {
		if l, ok := snap.Enclaves[enc]; ok && l.Err != nil {
			d.sealed, d.reason = true, "enclave refused: "+l.Err.Error()
			return d, nil
		}
		if snap.IsOnDemand(enc) {
			d.sealed, d.reason = true, string(enc)+" is on demand on this machine"
			return d, nil
		}
		if !snap.canOpen(enc) {
			d.sealed, d.reason = true, "not a member of "+string(enc)
			return d, nil
		}
	}
	raw, blob, err := e.readSource(ctx, snap, r.Source)
	if err != nil {
		return d, fmt.Errorf("%s: %w", r.Source, err)
	}
	d.blob = blob
	if blob == "" || blob != known {
		snap = snap.strict()
	}
	out, rh, err := e.produceFrom(snap, r, raw, lv)
	if err != nil {
		return d, err
	}
	d.bytes, d.renderHash = out, rh
	return d, nil
}

// ErrNotPlanned is returned by Render for a target the snapshot's plan
// does not produce on this machine.
var ErrNotPlanned = errors.New("not managed on this machine")

// CanOpen reports whether this machine may open enc in this snapshot: it
// holds the key and the enclave's key log was not refused.
func (s *Snapshot) CanOpen(enc model.EnclaveName) bool { return s.canOpen(enc) }

// Render returns the bytes apply would write to target t at snap, with the
// live target lv for keep and drop rules to merge into: open the sealed
// file, render the template, apply intra-file rules. It is the one render
// pipeline; diff and hook summaries use it. It writes nothing. A sealed
// entry this machine cannot open fails with crypt.ErrNotMember.
func (e *Engine) Render(ctx context.Context, snap *Snapshot, t model.Target, lv []byte) ([]byte, error) {
	r, raw, err := e.planned(ctx, snap, t)
	if err != nil {
		return nil, err
	}
	out, _, err := e.produceFrom(snap, r, raw, lv)
	return out, err
}

// OpenSource returns the source of target t at snap as its entry stores
// it, before any render or rule: a whole sealed file opened, a template
// unrendered, sealed values and regions left as their tokens. It refuses
// what Render refuses and writes nothing.
func (e *Engine) OpenSource(ctx context.Context, snap *Snapshot, t model.Target) ([]byte, error) {
	r, raw, err := e.planned(ctx, snap, t)
	if err != nil {
		return nil, err
	}
	return openRaw(snap, r, raw)
}

// planned reads the raw source of a target that snap's plan produces,
// after the checks Render and OpenSource share.
func (e *Engine) planned(ctx context.Context, snap *Snapshot, t model.Target) (manifest.Resolved, []byte, error) {
	if snap == nil || snap.Plan == nil {
		return manifest.Resolved{}, nil, errors.New("render: no snapshot")
	}
	r, ok := snap.Plan.Targets[t]
	if !ok {
		return r, nil, fmt.Errorf("%s: %w", t, ErrNotPlanned)
	}
	if enc := r.Entry.Enclave; enc != "" && snap.IsOnDemand(enc) {
		return r, nil, fmt.Errorf("%s is on demand on this machine and never delivered; yadm show %s prints it: %w", enc, model.ShellQuote(string(t)), crypt.ErrNotMember)
	}
	if enc := r.Entry.Enclave; enc != "" && !snap.canOpen(enc) {
		return r, nil, fmt.Errorf("sealed for %s; this machine cannot open it: %w", enc, crypt.ErrNotMember)
	}
	raw, _, err := e.readSource(ctx, snap, r.Source)
	if err != nil {
		return r, nil, fmt.Errorf("%s: %w", r.Source, err)
	}
	return r, raw, nil
}

// openRaw opens a whole sealed file in memory; other sources pass through.
func openRaw(snap *Snapshot, r manifest.Resolved, raw []byte) ([]byte, error) {
	if enc := r.Entry.Enclave; enc != "" {
		if !snap.canOpen(enc) {
			return nil, fmt.Errorf("%s: %w", r.Target, crypt.ErrNotMember)
		}
		p, err := snap.cr().OpenFile(enc, r.Source, raw)
		if err != nil {
			return nil, fmt.Errorf("%s: open: %w", r.Source, err)
		}
		return p, nil
	}
	if crypt.IsSealedFile(raw) {
		return nil, fmt.Errorf("%s: sealed container in an entry without enclave", r.Source)
	}
	return raw, nil
}

// produceFrom runs the apply pipeline on raw source bytes: open the sealed
// container, render the template, apply intra-file rules. It returns the
// target bytes and, for templates, the hash of the render.
func (e *Engine) produceFrom(snap *Snapshot, r manifest.Resolved, raw, lv []byte) ([]byte, string, error) {
	plain, err := openRaw(snap, r, raw)
	if err != nil {
		return nil, "", err
	}
	var rh string
	if r.Entry.Template {
		if snap.Render == nil {
			return nil, "", errors.New("apply: no render engine")
		}
		out, err := snap.Render.Render(string(r.Source), plain, snap.Context)
		if err != nil {
			return nil, "", err
		}
		plain, rh = out, hashOf(out)
	}
	spec := rules.SpecFor(r)
	if !spec.Empty() {
		out, err := e.Rules.ToTarget(plain, lv, spec, snap.sealer())
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", r.Target, err)
		}
		plain = out
	}
	return plain, rh, nil
}

// step is one planned action with what it needs to execute.
type step struct {
	Action
	d      desired
	live   live
	abs    string
	hold   *model.Hold
	chmod  bool   // bytes already equal; fix the mode only
	forget bool   // drop the target from state
	keep   bool   // unchanged since the last apply: state stays as it is
	merged []byte // union of source and target: written instead of d.bytes
	// taken marks a target that enters state for the first time with its
	// bytes already in place: nothing is written, yet adopt and a first
	// apply fire its path tasks as if it had changed.
	taken bool
}

func inFilter(paths []model.Target, t model.Target) bool {
	if len(paths) == 0 {
		return true
	}
	for _, p := range paths {
		if p == t || strings.HasPrefix(string(t), strings.TrimSuffix(string(p), "/")+"/") {
			return true
		}
	}
	return false
}

// planSteps decides what to do with every target. adopt treats a differing
// target that is not in state as held, and an identical one as adopted.
func (e *Engine) planSteps(ctx context.Context, snap *Snapshot, st *State, paths []model.Target, adopt bool) ([]step, error) {
	now := e.Now()
	if snap.Plan == nil {
		return nil, errors.New("apply: snapshot has no plan")
	}
	targets := make([]model.Target, 0, len(snap.Plan.Targets))
	for t := range snap.Plan.Targets {
		if inFilter(paths, t) {
			targets = append(targets, t)
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })

	var steps []step
	for _, t := range targets {
		r := snap.Plan.Targets[t]
		s, err := e.planOne(ctx, snap, st, r, adopt, now)
		if err != nil {
			return nil, err
		}
		steps = append(steps, s)
	}

	// Targets that left the plan.
	var gone []model.Target
	for t := range st.Targets {
		if _, ok := snap.Plan.Targets[t]; !ok && inFilter(paths, t) {
			gone = append(gone, t)
		}
	}
	sort.Slice(gone, func(i, j int) bool { return gone[i] < gone[j] })
	for _, t := range gone {
		s, err := e.leavePlan(ctx, st, t, st.Targets[t], now, "left the plan")
		if err != nil {
			return nil, err
		}
		steps = append(steps, s)
	}
	return steps, nil
}

// leavePlan is the step for a recorded target apply no longer delivers:
// delete it when it still holds what apply wrote, hold it otherwise. why
// says why it is no longer delivered.
func (e *Engine) leavePlan(ctx context.Context, st *State, t model.Target, ts TargetState, now time.Time, why string) (step, error) {
	abs, err := e.abs(t)
	if err != nil {
		return step{}, err
	}
	s := step{Action: Action{Target: t, Source: ts.Source, Scope: ts.Scope}, abs: abs}
	lv, err := e.readTarget(ctx, abs)
	switch {
	case err != nil:
		s.Kind, s.Reason = ActHold, why+"; target unreadable: "+err.Error()
	case !lv.exists:
		s.Kind, s.Reason, s.forget = ActSkip, why+"; already absent", true
	case !lv.info.Mode().IsRegular():
		h := fileHold(st, now, t, ts.Scope, model.HoldDrifted, ts.ChangedAt, why+"; target is no longer a regular file")
		s.Kind, s.Reason, s.hold = ActHold, "drifted", &h
	case hashOf(lv.bytes) == ts.Written:
		s.Kind, s.Reason, s.live = ActDelete, why, lv
	default:
		h := fileHold(st, now, t, ts.Scope, model.HoldDrifted, ts.ChangedAt, why+" but was modified since last written; not deleted")
		s.Kind, s.Reason, s.hold = ActHold, "drifted", &h
	}
	return s, nil
}

func (e *Engine) planOne(ctx context.Context, snap *Snapshot, st *State, r manifest.Resolved, adopt bool, now time.Time) (step, error) {
	t := r.Target
	abs, err := e.abs(t)
	if err != nil {
		return step{}, err
	}
	s := step{Action: Action{Target: t, Source: r.Source, Scope: r.Entry.Scope(), Unit: r.Unit}, abs: abs}
	ts, have := st.Targets[t]
	hold := func(detail string) (step, error) {
		h := fileHold(st, now, t, s.Scope, model.HoldDrifted, ts.ChangedAt, detail)
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldDrifted), &h
		return s, nil
	}

	if model.HasControl(string(t)) {
		// A glob or a root can expand to a tree path with a newline or
		// other control character; such a name is never written.
		h := badNameHold(st, now, t, s.Scope, ts.ChangedAt)
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldUncapturable), &h
		return s, nil
	}
	// Decide delivery before touching the target, so a non-member never
	// computes or reads anything for a sealed file.
	if enc := r.Entry.Enclave; enc != "" && !snap.canOpen(enc) {
		if have && snap.IsOnDemand(enc) {
			// Delivered before the enclave went on demand here: take it
			// back out of $HOME as if it had left the plan.
			return e.leavePlan(ctx, st, t, ts, now, string(enc)+" is on demand on this machine")
		}
		d, _ := e.produce(ctx, snap, r, nil, "")
		s.Kind, s.Reason, s.d = ActSealed, d.reason, d
		return s, nil
	}
	guard := func(detail string) (step, error) {
		h := fileHold(st, now, t, s.Scope, model.HoldSealGuard, ts.ChangedAt, detail)
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldSealGuard), &h
		return s, nil
	}
	if detail, weak := e.weakened(ts, have, r); weak {
		h := weakHold(st, now, t, s.Scope, ts.ChangedAt, detail)
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldSealGuard), &h
		return s, nil
	}
	if detail, wide := widenedMode(snap, r); wide {
		return guard(detail)
	}
	if detail, wide := e.modeWidenedSince(snap, r, ts, have); wide {
		h := weakHold(st, now, t, s.Scope, ts.ChangedAt, detail)
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldSealGuard), &h
		return s, nil
	}
	if !adopt && have && e.unchangedSince(ctx, snap, st, r, ts, abs) {
		s.Kind, s.keep = ActSkip, true
		s.d = desired{res: r, scope: s.Scope, mode: modeOf(snap, r), blob: ts.SourceBlob, key: ts.ApplyKey}
		return s, nil
	}

	lv, err := e.readTarget(ctx, abs)
	if errors.Is(err, ErrOutsideHome) {
		h := fileHold(st, now, t, s.Scope, model.HoldUncapturable, ts.ChangedAt, "the target's real path leaves $HOME ("+err.Error()+"); it is never read or written")
		h.Next = []string{"yadm hold show " + h.ID}
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldUncapturable), &h
		return s, nil
	}
	if err != nil {
		s.Kind, s.Reason = ActHold, "target unreadable: "+err.Error()
		return s, nil
	}
	s.live = lv
	if lv.exists && !lv.info.Mode().IsRegular() {
		// A stock symlink yadm never recorded: adopt, and apply too (a
		// member that adopted before it joined an enclave could not open
		// the render then), materialize it when its content equals the
		// render. A new keep, drop or volatile entry still needs a decision,
		// unless the link is the stock layout: it resolves inside $HOME to a
		// file whose bytes equal the source's own.
		if !have && lv.info.Mode()&fs.ModeSymlink != 0 {
			if !adopt && hasLocalKeys(r.Entry) && !e.stockLink(ctx, snap, r, ts, abs) {
				h := fileHold(st, now, t, s.Scope, model.HoldNeedsDecision, ts.ChangedAt,
					"a new entry with keep, drop or volatile covers a symlink yadm never wrote; not taken over until resolved")
				s.Kind, s.Reason, s.hold = ActHold, string(model.HoldNeedsDecision), &h
				return s, nil
			}
			return e.materializeLink(ctx, snap, r, s, ts, hold)
		}
		return hold("target is not a regular file (symlink or directory); not replaced")
	}
	if lv.exists && !have && !adopt && hasLocalKeys(r.Entry) && !e.equalsSource(ctx, snap, r, ts, lv.bytes) {
		// The render merges the live file, so it may equal it. Recording
		// the file as managed would let a later manifest change share keys
		// that were never yadm's. The user decides. A file byte-identical
		// to the source itself owes nothing to the merge and is taken over.
		h := fileHold(st, now, t, s.Scope, model.HoldNeedsDecision, ts.ChangedAt,
			"a new entry with keep, drop or volatile covers a file yadm never wrote; not taken over until resolved")
		s.Kind, s.Reason, s.hold = ActHold, string(model.HoldNeedsDecision), &h
		return s, nil
	}
	var lb []byte
	if lv.exists {
		lb = lv.bytes
	}
	d, err := e.produce(ctx, snap, r, lb, ts.SourceBlob)
	if detail, ok := sealedOpenFailure(err); ok {
		return guard(detail)
	}
	if err != nil {
		return step{}, err
	}
	s.d = d

	if !lv.exists {
		if have && !adopt {
			return hold("deleted since last written; not recreated")
		}
		s.Kind = ActWrite
		return s, nil
	}
	liveHash := hashOf(lv.bytes)
	liveMode := lv.info.Mode().Perm()
	if liveHash == hashOf(d.bytes) {
		switch {
		case liveMode == d.mode:
			s.Kind = ActSkip
			if !have && adopt {
				s.Kind = ActAdopt
			}
		case have && ts.want() == d.mode && ModeAccepted(r.Target, liveMode, d.mode):
			// Stricter than wanted, by the file's own tool or user: not
			// drift, and apply never widens it.
			s.Kind = ActSkip
		case have && uint32(liveMode) == ts.Mode:
			// The entry's mode changed and the file is as last recorded.
			s.Kind, s.chmod, s.Reason = ActWrite, true, "mode"
		case have && ModeAccepted(r.Target, liveMode, d.mode):
			s.Kind = ActSkip
		case !have && liveMode&0o222 == 0:
			// A read-only render another tool left (0444): adopt, and apply
			// for a target adopt could not open yet, take it over at the
			// source's mode.
			s.Kind, s.chmod, s.Reason = ActWrite, true, "mode"
		case !have && ModeAccepted(r.Target, liveMode, d.mode):
			s.Kind = ActSkip
			if adopt {
				s.Kind = ActAdopt
			}
		default:
			return hold(fmt.Sprintf("bytes match but mode is %#o, want %#o", liveMode, d.mode))
		}
		s.taken = !have
		return s, nil
	}
	switch {
	case adopt && !have:
		return hold("exists and differs from the source; not overwritten")
	case have && liveHash == ts.Written:
		s.Kind = ActWrite
		return s, nil
	case !have:
		return hold("exists, differs and was never written by yadm; not overwritten")
	case r.Entry.Merge == manifest.MergeUnion && hashOf(d.bytes) != ts.Written:
		// Both sides changed a line-set file: write the union. The state
		// keeps the source as written, so the next capture commits it.
		merged, why := e.unionMerge(ctx, snap, r, ts, d.bytes, lv.bytes)
		if why != "" {
			return hold("modified since last written; not overwritten: " + why)
		}
		s.Kind, s.merged, s.Reason = ActWrite, merged, "union"
		return s, nil
	case r.Entry.Template:
		return hold("rendered output edited by hand since last written; not re-rendered")
	default:
		return hold("modified since last written; not overwritten")
	}
}

// unionMerge computes the line union of a `merge = "union"` target that
// changed here while its source changed too: base is the source as last
// written (opened, for a sealed file), ours the new source, theirs the
// target. The source's lines come first, then lines only the target has; a
// line either side removed stays removed. why is set when the union cannot
// be computed: rules or a template between source and target, a base that
// is gone or does not open, or binary content.
func (e *Engine) unionMerge(ctx context.Context, snap *Snapshot, r manifest.Resolved, ts TargetState, source, target []byte) (merged []byte, why string) {
	if r.Entry.Template || !rules.SpecFor(r).Empty() {
		return nil, "a union merge needs a plain file without template or rules"
	}
	base, err := e.prevSource(ctx, snap, ts, r.Source)
	if err != nil {
		return nil, "cannot read the source last written"
	}
	if enc := r.Entry.Enclave; enc != "" {
		// The base is only compared against, never delivered.
		if base, err = snap.history().cr().OpenFile(enc, r.Source, base); err != nil {
			return nil, "cannot open the source last written"
		}
	}
	if hashOf(base) != ts.Written {
		return nil, "the source last written is not what the target was written from"
	}
	if textmerge.IsBinary(base) || textmerge.IsBinary(source) || textmerge.IsBinary(target) {
		return nil, "binary content"
	}
	return textmerge.Union(base, source, target), ""
}

// unchangedSince reports whether target r is exactly as the last apply or
// capture left it, so apply can skip it without reading its source or the
// file: the source blob, the entry and (for a template) the render inputs
// are unchanged, the file's stat tuple matches the state, and nothing about
// it is held or pending. A target with intra-file rules is always
// recomputed, since its output merges the live file. The strict epoch
// check is untouched: it applies only to a blob new to this machine, and a
// skipped target's blob is the one it already knows.
func (e *Engine) unchangedSince(ctx context.Context, snap *Snapshot, st *State, r manifest.Resolved, ts TargetState, abs string) bool {
	te, ok := snap.Tree[r.Source]
	switch {
	case !ok || te.Blob == "" || te.Blob != ts.SourceBlob:
		return false
	case ts.Written == "" || ts.ApplyKey == "" || !ts.ChangedAt.IsZero():
		return false
	case ts.Source != r.Source || ts.Scope != r.Entry.Scope():
		return false
	case !rules.SpecFor(r).Empty():
		return false
	case !sameProt(ts.prot(), protOf(r.Entry)):
		return false
	case modeOf(snap, r) != ts.want():
		return false
	case ts.ApplyKey != applyKey(snap, r):
		return false
	}
	t := r.Target
	for _, h := range st.Holds {
		if h.Target == t {
			return false
		}
	}
	if _, ok := st.Seen[t]; ok {
		return false
	}
	if _, ok := st.Baseline[t]; ok {
		return false
	}
	if _, ok := st.Ignored[t]; ok {
		return false
	}
	info, err := bounded(ctx, e.StatTimeout, func() (fs.FileInfo, error) { return e.fs.Lstat(abs) })
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return info.Size() == ts.Size && info.ModTime().Equal(ts.ModTime) && uint32(info.Mode().Perm()) == ts.Mode
}

// applyKey fingerprints what apply computes r's target from at snap,
// besides the source blob: the resolved entry and, for a template, the
// manifest and fleet blobs (named conditions, types) and the parts of the
// Context a render reads. Observed facts count by their items and error,
// not their collection time.
func applyKey(snap *Snapshot, r manifest.Resolved) string {
	type fact struct {
		Items []string `json:"items,omitempty"`
		Error string   `json:"error,omitempty"`
	}
	k := struct {
		Target   model.Target     `json:"target"`
		Source   model.SourcePath `json:"source"`
		Entry    manifest.Entry   `json:"entry"`
		Manifest string           `json:"manifest,omitempty"`
		Fleet    string           `json:"fleet,omitempty"`
		Machine  *model.Machine   `json:"machine,omitempty"`
		Home     string           `json:"home,omitempty"`
		User     string           `json:"user,omitempty"`
		Observed map[string]fact  `json:"observed,omitempty"`
	}{Target: r.Target, Source: r.Source, Entry: r.Entry}
	if r.Entry.Template {
		k.Manifest = snap.Tree[manifest.FileName].Blob
		k.Fleet = snap.Tree[fleet.FileName].Blob
		m := snap.Context.Machine
		k.Machine, k.Home, k.User = &m, snap.Context.Home, snap.Context.User
		k.Observed = map[string]fact{}
		for c, f := range snap.Context.Observed {
			k.Observed[c] = fact{Items: f.Items, Error: f.Error}
		}
	}
	b, err := json.Marshal(k)
	if err != nil {
		return ""
	}
	return hashOf(b)
}

// sameProt reports whether two protections are equal.
func sameProt(a, b protection) bool {
	if a.Enclave != b.Enclave || a.Regions != b.Regions || len(a.Seal) != len(b.Seal) {
		return false
	}
	if !slices.Equal(a.Keep, b.Keep) || !slices.Equal(a.Drop, b.Drop) || !slices.Equal(a.Volatile, b.Volatile) {
		return false
	}
	for k, v := range a.Seal {
		if w, ok := b.Seal[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// Plan computes the actions apply would take for rev.
func (e *Engine) Plan(ctx context.Context, rev model.CommitID) ([]Action, error) {
	res, err := e.Apply(ctx, rev, ApplyOptions{DryRun: true})
	return res.Actions, err
}

// Apply renders rev for this machine and writes changed targets, then runs
// triggered tasks (including unit reloads and, once, first-apply tasks).
func (e *Engine) Apply(ctx context.Context, rev model.CommitID, opts ApplyOptions) (Result, error) {
	return e.run(ctx, rev, opts.Paths, opts.DryRun, false)
}

// Adopt takes over an existing $HOME: identical targets are recorded without
// writing, missing ones are written, differing ones are held. Every target
// it takes over fires its path tasks once, as if it had changed.
func (e *Engine) Adopt(ctx context.Context, rev model.CommitID, opts AdoptOptions) (Result, error) {
	if !opts.DryRun && opts.AllowTasks {
		snap, err := e.snapshot(ctx, rev)
		if err != nil {
			return Result{}, err
		}
		if err := e.allowAll(snap); err != nil {
			return Result{}, err
		}
	}
	snap, err := e.snapshot(ctx, rev)
	if err != nil {
		return Result{}, err
	}
	links, copied, err := e.materializeDirLinks(snap, opts.DryRun)
	if berr := e.baselineCopies(snap, copied); err == nil {
		err = berr
	}
	if err != nil {
		return Result{}, err
	}
	res, err := e.run(ctx, rev, nil, opts.DryRun, true)
	var acts []Action
	for _, p := range links {
		acts = append(acts, Action{Target: p, Kind: ActWrite, Scope: model.ScopeShared, Reason: "materialize directory symlink"})
	}
	res.Actions = append(acts, res.Actions...)
	return res, err
}

// allowAll records every task definition of the plan and every collector
// definition of the fleet in the allow list.
func (e *Engine) allowAll(snap *Snapshot) error {
	if snap.Plan == nil {
		return nil
	}
	if a := e.allowList(); a != nil {
		for _, r := range snap.Plan.Roots {
			if err := a.Allow(KindRoot, string(r.Path), rootHash(r)); err != nil {
				return fmt.Errorf("allow root %s: %w", r.Path, err)
			}
		}
	}
	if e.Tasks == nil || e.Tasks.Allow == nil {
		return nil
	}
	for name, def := range snap.Plan.Tasks {
		h, err := tasks.DefinitionHash(def)
		if err != nil {
			return fmt.Errorf("allow task %s: %w", name, err)
		}
		if err := e.Tasks.Allow.Allow(extexec.KindTask, name, h); err != nil {
			return fmt.Errorf("allow task %s: %w", name, err)
		}
	}
	if snap.Fleet != nil {
		for name, def := range snap.Fleet.Collectors {
			h, err := tasks.DefinitionHash(def)
			if err != nil {
				return fmt.Errorf("allow collector %s: %w", name, err)
			}
			if err := e.Tasks.Allow.Allow(extexec.KindCollector, name, h); err != nil {
				return fmt.Errorf("allow collector %s: %w", name, err)
			}
		}
	}
	return nil
}

func (e *Engine) run(ctx context.Context, rev model.CommitID, paths []model.Target, dry, adopt bool) (Result, error) {
	snap, err := e.snapshot(ctx, rev)
	if err != nil {
		return Result{}, err
	}
	st, err := e.loadState()
	if err != nil {
		return Result{}, err
	}
	steps, err := e.planSteps(ctx, snap, st, paths, adopt)
	if err != nil {
		return Result{}, err
	}
	res := Result{Commit: snap.Commit}
	for _, s := range steps {
		res.Actions = append(res.Actions, s.Action)
		if s.hold != nil {
			res.Holds = append(res.Holds, *s.hold)
		}
	}
	if dry {
		return res, nil
	}

	now := e.Now()
	var changed, removed, taken []model.Target
	var units []manifest.Unit
	var execErr error
	for i, s := range steps {
		if execErr = e.execute(st, s, now); errors.Is(execErr, errRaced) {
			// The target changed between plan and write: hold, do not clobber.
			ts := st.Targets[s.Target]
			h := fileHold(st, now, s.Target, s.Scope, model.HoldDrifted, ts.ChangedAt, "changed while apply ran; not overwritten")
			putHold(st, h)
			res.Actions[i].Kind, res.Actions[i].Reason = ActHold, string(model.HoldDrifted)
			res.Holds = append(res.Holds, h)
			execErr = nil
			continue
		}
		if execErr != nil {
			execErr = fmt.Errorf("%s: %w", s.Target, execErr)
			break
		}
		switch {
		case s.Kind == ActWrite && !s.chmod:
			changed = append(changed, s.Target)
			if s.Unit != nil {
				units = append(units, *s.Unit)
			}
		case s.Kind == ActDelete:
			removed = append(removed, s.Target)
		}
		if s.taken {
			taken = append(taken, s.Target)
		}
	}
	if execErr == nil && len(paths) == 0 {
		st.Applied = snap.Commit
		c := snap.Context
		st.RenderContext = &c
		if snap.Manifest != nil {
			st.Outputs = snap.Manifest.Outputs()
		}
		res.Holds = append(res.Holds, e.acceptRoots(ctx, snap, st, now)...)
		pruneStaleHolds(st, snap)
	}
	// Prune first: a failed step must not leave an on-demand enclave's
	// backup behind until the next clean apply.
	e.pruneBackups(now, snap.Enclaves, snap.OnDemand)
	if err := e.State.Save(st); err != nil {
		return res, err
	}
	if execErr != nil {
		return res, execErr
	}
	ev := tasks.Event{Commit: snap.Commit, Changed: changed, Removed: removed, Units: units, FirstApply: !st.FirstApplyDone && len(paths) == 0}
	if adopt || !st.FirstApplyDone {
		// A target taken over with its bytes already in place fires its
		// path tasks once, as if it had changed: the machine never ran
		// them for those bytes. Later applies find it in state.
		ev.Changed = append(ev.Changed, taken...)
	}
	if adopt {
		// Adopt runs path tasks only: no unit reload, removal or input
		// trigger, and no first-apply task. First-apply tasks run on the
		// first apply after it (FirstApplyDone stays false).
		ev.Removed, ev.Units, ev.FirstApply = nil, nil, false
	} else if len(paths) == 0 && watchesInputs(snap) {
		ev.Inputs, ev.LastInputs = taskInputs(snap), st.TaskInputs
	}
	results, holds := e.runTasks(ctx, snap, st, ev)
	recordTaskInputs(st, snap, ev, results)
	if adopt && watchesInputs(snap) {
		// A task adopt ran saw today's inputs: record them, so the first
		// apply does not run it again for on_fact or on_render.
		rec := ev
		rec.Inputs = taskInputs(snap)
		recordTaskInputs(st, snap, rec, results)
	}
	res.Tasks = append(res.Tasks, results...)
	if len(results) > 0 || len(holds) > 0 || ev.FirstApply {
		if st.Tasks == nil {
			st.Tasks = map[string]model.TaskResult{}
		}
		for _, r := range results {
			st.Tasks[r.Task] = r
			clearTaskHolds(st, r.Task)
		}
		for _, h := range holds {
			// Keep the first sighting, so a task held on every apply keeps one id.
			h = model.KeepSince(st.Holds, h, now)
			putHold(st, h)
			res.Holds = append(res.Holds, h)
		}
		if len(paths) == 0 {
			e.pruneTaskHolds(st, snap)
		}
		if ev.FirstApply && !firstApplyHeld(st, snap) {
			st.FirstApplyDone = true
		}
		if err := e.State.Save(st); err != nil {
			return res, err
		}
	} else if len(paths) == 0 {
		// No task fired: still drop holds a `task allow` or a manifest
		// change has settled since the last apply.
		before := len(st.Holds)
		if e.pruneTaskHolds(st, snap); len(st.Holds) != before {
			if err := e.State.Save(st); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// execute performs one step and records it in st.
func (e *Engine) execute(st *State, s step, now time.Time) error {
	t := s.Target
	switch s.Kind {
	case ActHold:
		if s.hold != nil {
			putHold(st, *s.hold)
		}
		return nil
	case ActSealed:
		return nil
	case ActSkip:
		if s.keep {
			return nil
		}
		if s.forget {
			forget(st, t, now)
			clearFileHolds(st, t)
			return nil
		}
		return e.record(st, s, now)
	case ActAdopt:
		return e.record(st, s, now)
	case ActWrite:
		if s.chmod {
			if err := os.Chmod(s.abs, s.d.mode); err != nil {
				return err
			}
			return e.record(st, s, now)
		}
		out := s.d.bytes
		if s.merged != nil {
			out = s.merged
		}
		if s.live.exists && !bytes.Equal(s.live.bytes, out) {
			written := st.Targets[t].Written
			if s.merged != nil {
				written = hashOf(s.live.bytes) // the union keeps every live line
			}
			if err := e.backup(now, t, union(protOf(s.d.res.Entry), st.Targets[t].prot()), s.live.bytes, written); err != nil {
				return err
			}
		}
		if err := e.writeAtomic(s.abs, out, s.d.mode, func() error { return unchanged(s) }); err != nil {
			return err
		}
		if err := e.record(st, s, now); err != nil {
			return err
		}
		if s.merged != nil && !bytes.Equal(out, s.d.bytes) {
			// Recorded as the source wrote it, with no stat to match, so
			// the next scan hashes the union and capture commits it.
			ts := st.Targets[t]
			ts.ModTime = time.Time{}
			st.Targets[t] = ts
		}
		return nil
	case ActDelete:
		if err := unchanged(s); err != nil {
			return err
		}
		if err := e.backup(now, t, st.Targets[t].prot(), s.live.bytes, st.Targets[t].Written); err != nil {
			return err
		}
		if err := os.Remove(s.abs); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		forget(st, t, now)
		clearFileHolds(st, t)
		return nil
	}
	return fmt.Errorf("unknown action %q", s.Kind)
}

// errRaced reports a target that changed between plan and write.
var errRaced = errors.New("target changed while apply ran")

// unchanged re-stats a target just before apply replaces or removes it and
// returns errRaced if it no longer looks the way the plan saw it.
func unchanged(s step) error {
	info, err := os.Lstat(s.abs)
	if !s.live.exists {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return errRaced
	}
	if err != nil || info.Size() != s.live.info.Size() || !info.ModTime().Equal(s.live.info.ModTime()) || info.Mode() != s.live.info.Mode() {
		return errRaced
	}
	return nil
}

// record stores what is now on disk for a target that matches its source.
func (e *Engine) record(st *State, s step, now time.Time) error {
	info, err := os.Lstat(s.abs)
	if err != nil {
		return err
	}
	ts := TargetState{
		Source:     s.d.res.Source,
		SourceBlob: s.d.blob,
		Scope:      s.d.scope,
		Written:    hashOf(s.d.bytes),
		Size:       info.Size(),
		ModTime:    info.ModTime(),
		Mode:       uint32(info.Mode().Perm()),
		Want:       uint32(s.d.mode.Perm()),
		RenderHash: s.d.renderHash,
		ApplyKey:   s.d.key,
	}
	prot := protOf(s.d.res.Entry)
	if old, had := st.Targets[s.Target]; had {
		// Belt and braces: never record a weaker protection that was not
		// allowed. Every caller checks first; the record keeps the stronger.
		if _, weak := e.weakened(old, true, s.d.res); weak {
			prot = old.prot()
		}
	}
	ts.Enclave, ts.Seal, ts.Regions = prot.Enclave, prot.Seal, prot.Regions
	ts.Keep, ts.Drop, ts.Volatile = prot.Keep, prot.Drop, prot.Volatile
	ts.ExplicitMode = uint32(s.d.res.Entry.Mode.Perm())
	for k := range prot.Seal {
		ts.SealSet = append(ts.SealSet, k)
	}
	sort.Strings(ts.SealSet)
	if prot.Regions {
		ts.SealSet = append(ts.SealSet, "regions")
	}
	st.Targets[s.Target] = ts
	delete(st.Seen, s.Target)
	delete(st.Baseline, s.Target)
	delete(st.Ignored, s.Target)
	clearFileHolds(st, s.Target)
	return nil
}

// sealedOpenFailure reports an error from opening sealed content: a blob or
// token that fails authentication, names an unknown epoch, or is sealed
// under an epoch this open does not accept. Apply holds such a target
// instead of failing the whole run, so one bad blob a pusher planted does
// not stop every other file.
func sealedOpenFailure(err error) (string, bool) {
	switch {
	case err == nil:
		return "", false
	case errors.Is(err, crypt.ErrRetiredEpoch):
		return "sealed content new to this machine is sealed under an old epoch, which a removed member may hold; a member must reseal it: " + err.Error(), true
	case errors.Is(err, crypt.ErrAuthFailed), errors.Is(err, crypt.ErrNotSealed), errors.Is(err, crypt.ErrUnknownEpoch):
		return "sealed content does not open here (moved, damaged or forged): " + err.Error(), true
	}
	return "", false
}

// strict returns a copy of the snapshot whose Crypto opens only each
// enclave's current epoch.
func (s *Snapshot) strict() *Snapshot {
	v, ok := s.cr().(cryptoViews)
	if !ok {
		return s
	}
	c := *s
	c.Crypto = v.Strict()
	return &c
}

// history returns a copy of the snapshot whose Crypto opens every epoch it
// holds, for bytes that are never delivered to $HOME.
func (s *Snapshot) history() *Snapshot {
	v, ok := s.cr().(cryptoViews)
	if !ok {
		return s
	}
	c := *s
	c.Crypto = v.History()
	return &c
}

// runTasks selects and runs the tasks an apply triggered.
//
// A first-apply task whose last recorded run was a successful first-apply
// run does not run again while the first apply stays open for another held
// task; it still runs for its path triggers.
func (e *Engine) runTasks(ctx context.Context, snap *Snapshot, st *State, ev tasks.Event) ([]model.TaskResult, []model.Hold) {
	if e.Tasks == nil || snap.Plan == nil {
		return nil, nil
	}
	if len(ev.Changed) == 0 && len(ev.Removed) == 0 && len(ev.Units) == 0 && !ev.FirstApply && ev.Inputs == nil {
		return nil, nil
	}
	if len(snap.Plan.Tasks) == 0 && len(ev.Units) == 0 {
		return nil, nil
	}
	sel, err := tasks.Select(snap.Plan.Tasks, ev)
	if err != nil {
		return []model.TaskResult{{Task: "select", Commit: ev.Commit, Started: e.Now(), ExitCode: -1, Error: err.Error()}}, nil
	}
	sel = skipDoneFirstApply(sel, st, ev)
	if len(sel) == 0 && len(ev.Units) == 0 {
		return nil, nil
	}
	req := extexec.Request{
		Schema:  extexec.Schema,
		Kind:    extexec.KindTask,
		Machine: snap.Context.Machine,
		Home:    e.Home,
		Source:  e.Store.Dir(),
		Commit:  ev.Commit,
		Changed: ev.Changed,
		Removed: ev.Removed,
	}
	return e.Tasks.Run(ctx, ev, sel, req)
}

// skipDoneFirstApply drops the first-apply trigger of tasks that already
// ran successfully for it, or already ran at this commit for another
// trigger (adopt's path run). A task that also matched written or removed
// targets keeps running for those.
func skipDoneFirstApply(sel []tasks.Selected, st *State, ev tasks.Event) []tasks.Selected {
	changed := map[model.Target]bool{}
	for _, t := range ev.Changed {
		changed[t] = true
	}
	out := sel[:0]
	for _, s := range sel {
		prev, ok := st.Tasks[s.Name]
		doneFirst := prev.Trigger == tasks.TriggerFirstApply && prev.ExitCode == 0 && prev.Error == ""
		ranHere := prev.Trigger != tasks.TriggerFirstApply && prev.Commit == ev.Commit
		if s.Trigger != tasks.TriggerFirstApply || !ok || (!doneFirst && !ranHere) {
			out = append(out, s)
			continue
		}
		if len(s.Matched) == 0 {
			continue
		}
		s.Trigger = tasks.TriggerRemove
		for _, t := range s.Matched {
			if changed[t] {
				s.Trigger = tasks.TriggerPaths
				break
			}
		}
		out = append(out, s)
	}
	return out
}

// firstApplyHeld reports whether a first-apply task of the plan is still
// held, so the first apply is not marked done and that task runs on the
// next apply once it is allowed. Holds of other tasks do not count.
func firstApplyHeld(st *State, snap *Snapshot) bool {
	for _, h := range st.Holds {
		if h.Task == "" || h.Target != "" {
			continue
		}
		if snap.Plan == nil {
			return true
		}
		if def, ok := snap.Plan.Tasks[h.Task]; ok && def.FirstApply {
			return true
		}
	}
	return false
}

// pruneTaskHolds drops task_untrusted holds that have nothing left to allow:
// the plan no longer has the task, or its current definition is allowed now
// (it runs on its next trigger).
func (e *Engine) pruneTaskHolds(st *State, snap *Snapshot) {
	if snap.Plan == nil {
		return
	}
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target == "" && h.Reason == model.HoldTaskUntrusted {
			def, ok := snap.Plan.Tasks[h.Task]
			if !ok {
				continue
			}
			if e.Tasks != nil && e.Tasks.Allow != nil {
				if hash, err := tasks.DefinitionHash(def); err == nil && e.Tasks.Allow.Allowed(extexec.KindTask, h.Task, hash) {
					continue
				}
			}
		}
		out = append(out, h)
	}
	st.Holds = out
}

// watchesInputs reports whether a task of the plan has on_fact or on_render.
func watchesInputs(snap *Snapshot) bool {
	if snap.Plan == nil {
		return false
	}
	for _, d := range snap.Plan.Tasks {
		if len(tasks.InputKeys(d)) > 0 {
			return true
		}
	}
	return false
}

// fingerprint is the hex SHA-256 of v, so state holds no fact values.
func fingerprint(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// taskInputs fingerprints every input a task may watch: each declared fact
// ("fact:KEY"), each collector's observed items, and the render context
// (tasks.RenderInput): this machine's types, declared and observed facts,
// and the fleet file.
func taskInputs(snap *Snapshot) map[string]string {
	out := map[string]string{}
	m := snap.Context.Machine
	for k, v := range m.Facts {
		out["fact:"+k] = fingerprint(v)
	}
	items := map[string][]string{}
	for c, f := range snap.Context.Observed {
		out[c] = fingerprint(f.Items)
		items[c] = f.Items
	}
	types := slices.Clone(m.Types)
	slices.Sort(types)
	out[tasks.RenderInput] = fingerprint(struct {
		Types    []model.TypeName    `json:"types"`
		Facts    map[string]string   `json:"facts"`
		Observed map[string][]string `json:"observed"`
		Fleet    any                 `json:"fleet"`
	}{types, m.Facts, items, snap.Fleet})
	return out
}

// recordTaskInputs stores, for each task that ran, the fingerprints of the
// inputs it watches. A held task records nothing, so the change still fires
// once the task is allowed. A failed run records too, as a failed path task
// is not retried either.
func recordTaskInputs(st *State, snap *Snapshot, ev tasks.Event, results []model.TaskResult) {
	if ev.Inputs == nil || snap.Plan == nil {
		return
	}
	for _, r := range results {
		def, ok := snap.Plan.Tasks[r.Task]
		if !ok {
			continue
		}
		keys := tasks.InputKeys(def)
		if len(keys) == 0 {
			continue
		}
		rec := make(map[string]string, len(keys))
		for _, k := range keys {
			rec[k] = ev.Inputs[k]
		}
		if st.TaskInputs == nil {
			st.TaskInputs = map[string]map[string]string{}
		}
		st.TaskInputs[r.Task] = rec
	}
}
