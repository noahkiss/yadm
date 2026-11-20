package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
)

// Load reads fleet.toml, manifest.toml and every key log at rev, verifies
// the key logs, builds this machine's Context (with observed facts from
// local state) and resolves the plan.
func (e *Engine) Load(ctx context.Context, rev model.CommitID) (*Snapshot, error) {
	if e.Store == nil {
		return nil, errors.New("apply: no store")
	}
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
	keys, loads, err := crypt.LoadSet(logs, e.Pins, e.Identity)
	if err != nil {
		return nil, err
	}
	voc := fl.Vocabulary()
	plan, err := man.Resolve(mctx, paths, voc)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Commit:   rev,
		Fleet:    fl,
		Manifest: man,
		Plan:     plan,
		Context:  mctx,
		Keys:     keys,
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

// modeOf is an entry's target mode: explicit, else 0600 for an enclave file,
// else 0755 for an executable source, else 0644.
func modeOf(snap *Snapshot, r manifest.Resolved) fs.FileMode {
	switch {
	case r.Entry.Mode != 0:
		return r.Entry.Mode.Perm()
	case r.Entry.Enclave != "":
		return 0o600
	case snap.Tree[r.Source].Mode&0o111 != 0:
		return 0o755
	}
	return 0o644
}

// produce computes the target bytes for one resolved entry. lv is the live
// target, which keep rules merge into.
func (e *Engine) produce(ctx context.Context, snap *Snapshot, r manifest.Resolved, lv []byte) (desired, error) {
	d := desired{res: r, scope: r.Entry.Scope(), mode: modeOf(snap, r)}
	if enc := r.Entry.Enclave; enc != "" {
		if l, ok := snap.Enclaves[enc]; ok && l.Err != nil {
			d.sealed, d.reason = true, "enclave refused: "+l.Err.Error()
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
	out, rh, err := e.produceFrom(snap, r, raw, lv)
	if err != nil {
		return d, err
	}
	d.bytes, d.renderHash = out, rh
	return d, nil
}

// produceFrom runs the apply pipeline on raw source bytes: open the sealed
// container, render the template, apply intra-file rules. It returns the
// target bytes and, for templates, the hash of the render.
func (e *Engine) produceFrom(snap *Snapshot, r manifest.Resolved, raw, lv []byte) ([]byte, string, error) {
	plain := raw
	if enc := r.Entry.Enclave; enc != "" {
		if !snap.canOpen(enc) {
			return nil, "", fmt.Errorf("%s: %w", r.Target, crypt.ErrNotMember)
		}
		p, err := snap.cr().OpenFile(enc, raw)
		if err != nil {
			return nil, "", fmt.Errorf("%s: open: %w", r.Source, err)
		}
		plain = p
	} else if crypt.IsSealedFile(raw) {
		return nil, "", fmt.Errorf("%s: sealed container in an entry without enclave", r.Source)
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
	spec := rules.SpecOf(r.Entry)
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
	chmod  bool // bytes already equal; fix the mode only
	forget bool // drop the target from state
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
		ts := st.Targets[t]
		abs, err := e.abs(t)
		if err != nil {
			return nil, err
		}
		s := step{Action: Action{Target: t, Source: ts.Source, Scope: ts.Scope}, abs: abs}
		lv, err := e.readTarget(ctx, abs)
		switch {
		case err != nil:
			s.Kind, s.Reason = ActHold, "left the plan; target unreadable: "+err.Error()
		case !lv.exists:
			s.Kind, s.Reason, s.forget = ActSkip, "left the plan; already absent", true
		case !lv.info.Mode().IsRegular():
			h := fileHold(st, now, t, ts.Scope, model.HoldDrifted, ts.ChangedAt, "left the plan; target is no longer a regular file")
			s.Kind, s.Reason, s.hold = ActHold, "drifted", &h
		case hashOf(lv.bytes) == ts.Written:
			s.Kind, s.Reason, s.live = ActDelete, "left the plan", lv
		default:
			h := fileHold(st, now, t, ts.Scope, model.HoldDrifted, ts.ChangedAt, "left the plan but was modified since last written; not deleted")
			s.Kind, s.Reason, s.hold = ActHold, "drifted", &h
		}
		steps = append(steps, s)
	}
	return steps, nil
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

	// Decide delivery before touching the target, so a non-member never
	// computes or reads anything for a sealed file.
	if enc := r.Entry.Enclave; enc != "" && !snap.canOpen(enc) {
		d, _ := e.produce(ctx, snap, r, nil)
		s.Kind, s.Reason, s.d = ActSealed, d.reason, d
		return s, nil
	}

	lv, err := e.readTarget(ctx, abs)
	if err != nil {
		s.Kind, s.Reason = ActHold, "target unreadable: "+err.Error()
		return s, nil
	}
	s.live = lv
	if lv.exists && !lv.info.Mode().IsRegular() {
		return hold("target is not a regular file (symlink or directory); not replaced")
	}
	var lb []byte
	if lv.exists {
		lb = lv.bytes
	}
	d, err := e.produce(ctx, snap, r, lb)
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
		case have && uint32(liveMode) == ts.Mode:
			s.Kind, s.chmod, s.Reason = ActWrite, true, "mode"
		default:
			return hold(fmt.Sprintf("bytes match but mode is %#o, want %#o", liveMode, d.mode))
		}
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
	case r.Entry.Template:
		return hold("rendered output edited by hand since last written; not re-rendered")
	default:
		return hold("modified since last written; not overwritten")
	}
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
// writing, missing ones are written, differing ones are held.
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
	return e.run(ctx, rev, nil, opts.DryRun, true)
}

// allowAll records every task definition of the plan in the allow list.
func (e *Engine) allowAll(snap *Snapshot) error {
	if e.Tasks == nil || e.Tasks.Allow == nil || snap.Plan == nil {
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
	var changed, removed []model.Target
	var units []manifest.Unit
	var execErr error
	for _, s := range steps {
		if execErr = e.execute(st, s, now); execErr != nil {
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
	}
	if execErr == nil && len(paths) == 0 {
		st.Applied = snap.Commit
		c := snap.Context
		st.RenderContext = &c
		st.Roots = snap.Plan.Roots
	}
	if err := e.State.Save(st); err != nil {
		return res, err
	}
	if execErr != nil {
		return res, execErr
	}
	e.pruneBackups(now)

	ev := tasks.Event{Commit: snap.Commit, Changed: changed, Removed: removed, Units: units, FirstApply: !st.FirstApplyDone && len(paths) == 0}
	results, holds := e.runTasks(ctx, snap, ev)
	res.Tasks = append(res.Tasks, results...)
	res.Holds = append(res.Holds, holds...)
	if len(results) > 0 || len(holds) > 0 || ev.FirstApply {
		if st.Tasks == nil {
			st.Tasks = map[string]model.TaskResult{}
		}
		for _, r := range results {
			st.Tasks[r.Task] = r
		}
		for _, h := range holds {
			putHold(st, h)
		}
		if ev.FirstApply {
			st.FirstApplyDone = true
		}
		if err := e.State.Save(st); err != nil {
			return res, err
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
		if s.forget {
			delete(st.Targets, t)
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
		if s.live.exists && !bytes.Equal(s.live.bytes, s.d.bytes) {
			if err := e.backup(now, t, s.live.bytes); err != nil {
				return err
			}
		}
		if err := e.writeAtomic(s.abs, s.d.bytes, s.d.mode); err != nil {
			return err
		}
		return e.record(st, s, now)
	case ActDelete:
		if err := e.backup(now, t, s.live.bytes); err != nil {
			return err
		}
		if err := os.Remove(s.abs); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		delete(st.Targets, t)
		clearFileHolds(st, t)
		return nil
	}
	return fmt.Errorf("unknown action %q", s.Kind)
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
		RenderHash: s.d.renderHash,
	}
	for k := range s.d.res.Entry.Seal {
		ts.SealSet = append(ts.SealSet, k)
	}
	sort.Strings(ts.SealSet)
	if s.d.res.Entry.Regions {
		ts.SealSet = append(ts.SealSet, "regions")
	}
	st.Targets[s.Target] = ts
	delete(st.Seen, s.Target)
	clearFileHolds(st, s.Target)
	return nil
}

// runTasks selects and runs the tasks an apply triggered.
func (e *Engine) runTasks(ctx context.Context, snap *Snapshot, ev tasks.Event) ([]model.TaskResult, []model.Hold) {
	if e.Tasks == nil || snap.Plan == nil {
		return nil, nil
	}
	if len(ev.Changed) == 0 && len(ev.Removed) == 0 && len(ev.Units) == 0 && !ev.FirstApply {
		return nil, nil
	}
	if len(snap.Plan.Tasks) == 0 && len(ev.Units) == 0 {
		return nil, nil
	}
	sel, err := tasks.Select(snap.Plan.Tasks, ev)
	if err != nil {
		return []model.TaskResult{{Task: "select", Commit: ev.Commit, Started: e.Now(), ExitCode: -1, Error: err.Error()}}, nil
	}
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
