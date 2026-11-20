package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// Git modes of captured blobs.
const (
	gitModeFile = 0o100644
	gitModeExec = 0o100755
)

// Capture turns drift into source changes, applying the round-trip check and
// the seal guard. It never commits. A captured change that leaves the source
// as it is marks the target clean in state; any other change stays drift
// until it is committed and applied.
func (e *Engine) Capture(ctx context.Context, drift []Drift) (Capture, error) {
	out := Capture{Scopes: map[model.Target]model.Scope{}}
	if len(drift) == 0 {
		return out, nil
	}
	st, err := e.loadState()
	if err != nil {
		return out, err
	}
	snap, err := e.snapshot(ctx, st.Applied)
	if err != nil {
		return out, err
	}
	sort.Slice(drift, func(i, j int) bool { return drift[i].Target < drift[j].Target })
	for _, d := range drift {
		var ch *store.Change
		var h *model.Hold
		var err error
		if snap.Manifest != nil && snap.Manifest.Generated(d.Target) {
			// A task output: generated here, never captured.
			continue
		}
		switch d.Kind {
		case DriftUnreadable:
			continue
		case DriftNew:
			ch, h, err = e.captureNew(ctx, snap, st, d)
		default:
			ch, h, err = e.captureManaged(ctx, snap, st, d)
		}
		if err != nil {
			return out, fmt.Errorf("capture %s: %w", d.Target, err)
		}
		if h != nil {
			putHold(st, *h)
			out.Holds = append(out.Holds, *h)
			continue
		}
		if ch == nil {
			continue
		}
		clearFileHolds(st, d.Target)
		out.Changes = append(out.Changes, *ch)
		out.Paths = append(out.Paths, d.Target)
		out.Scopes[d.Target] = d.Scope
	}
	if err := e.State.Save(st); err != nil {
		return out, err
	}
	return out, nil
}

// captureManaged captures one managed target. It returns a change, a hold,
// or neither (nothing to commit; state updated).
func (e *Engine) captureManaged(ctx context.Context, snap *Snapshot, st *State, d Drift) (*store.Change, *model.Hold, error) {
	now := e.Now()
	t := d.Target
	ts, have := st.Targets[t]
	r, inPlan := snap.Plan.Targets[t]
	if !inPlan {
		return nil, nil, nil // left the plan: apply deletes or holds it
	}
	scope := r.Entry.Scope()
	if !have {
		// Never written here (an adopt or apply hold): capture against the
		// source at the snapshot.
		ts = TargetState{Source: r.Source, Scope: scope, SourceBlob: snap.Tree[r.Source].Blob}
	}
	hold := func(reason model.HoldReason, detail string) (*store.Change, *model.Hold, error) {
		h := fileHold(st, now, t, scope, reason, ts.ChangedAt, detail)
		return nil, &h, nil
	}
	if have && r.Source != ts.Source {
		return hold(model.HoldUncapturable, fmt.Sprintf("source moved from %s to %s since last apply", ts.Source, r.Source))
	}
	if detail, weak := e.weakened(ts, have, r); weak {
		h := weakHold(st, now, t, scope, ts.ChangedAt, detail)
		return nil, &h, nil
	}
	if enc := r.Entry.Enclave; enc != "" && !snap.canOpen(enc) {
		return hold(model.HoldSealGuard, "not a member of "+string(enc)+"; cannot seal")
	}
	switch d.Kind {
	case DriftDeleted:
		return &store.Change{Path: r.Source, Delete: true}, nil, nil
	case DriftMode:
		return hold(model.HoldUncapturable, "mode changed; set mode in the manifest entry")
	}

	abs, err := e.abs(t)
	if err != nil {
		return nil, nil, err
	}
	lv, err := e.readTarget(ctx, abs)
	if err != nil {
		return hold(model.HoldUncapturable, "target unreadable: "+err.Error())
	}
	if !lv.exists {
		return &store.Change{Path: r.Source, Delete: true}, nil, nil
	}
	if !lv.info.Mode().IsRegular() {
		return hold(model.HoldUncapturable, "target is not a regular file")
	}
	target := lv.bytes

	prevRaw, err := e.prevSource(ctx, snap, ts, r.Source)
	if err != nil {
		return nil, nil, err
	}
	enc := r.Entry.Enclave
	prevPlain := prevRaw
	if enc != "" {
		// The previous source is only compared against, never delivered.
		if prevPlain, err = snap.history().cr().OpenFile(enc, r.Source, prevRaw); err != nil {
			return hold(model.HoldUncapturable, "cannot open the stored source: "+err.Error())
		}
	}

	spec := rules.SpecFor(r)
	var newPlain []byte
	failReason := model.HoldUncapturable
	switch {
	case r.Entry.Template:
		failReason = model.HoldRenderedEdit
		if len(spec.Seal) > 0 || spec.Regions {
			return hold(model.HoldUncapturable, "template with sealed values or regions; edit the template")
		}
		if st.RenderContext == nil || snap.Render == nil {
			return hold(model.HoldRenderedEdit, "no stored render context to recompute the last render")
		}
		last, err := snap.Render.Render(string(r.Source), prevPlain, *st.RenderContext)
		if err != nil || hashOf(last) != ts.RenderHash {
			return hold(model.HoldRenderedEdit, "cannot recompute the last render")
		}
		// With keep or drop, the template renders only the owned part of
		// the file. Map the target through the rules onto the last render
		// first: an edit to app-owned keys leaves it unchanged (nothing to
		// commit), and an edit to a kept key patches the template as a
		// plain hand edit of that render would.
		want := target
		if !spec.Empty() {
			owned, viol, err := e.Rules.ToSource(target, last, spec, snap.sealer())
			if err != nil || len(viol) > 0 {
				detail := "keep/drop on a template: the target does not map onto the template's keys"
				if err != nil {
					detail += ": " + err.Error()
				}
				return hold(model.HoldRenderedEdit, detail+"; edit the template")
			}
			if bytes.Equal(owned, last) {
				newPlain = prevPlain
				break
			}
			want = owned
		}
		p, err := e.Text.PatchTemplate(prevPlain, last, want)
		if err != nil {
			detail := "hand edit touches rendered expressions or conditional blocks; it does not patch into the template: " + err.Error()
			cand, ok := []byte(nil), false
			if enc == "" {
				cand, ok = e.literalCandidate(snap, r, prevPlain, last, want, target)
			}
			if ok {
				detail += "; the proposed template patch replaces the edited expressions with literal text, which renders the same on every machine: review it before committing"
			}
			_, h, herr := hold(model.HoldRenderedEdit, detail)
			if h != nil {
				if ok {
					*h = proposePatch(*h, r, enc, model.PatchOfTemplate, prevPlain, cand)
				} else {
					*h = proposePatch(*h, r, enc, model.PatchOfRender, last, want)
				}
			}
			return nil, h, herr
		}
		newPlain = p
	case !spec.Empty():
		p, viol, err := e.Rules.ToSource(target, prevPlain, spec, snap.sealer())
		if len(viol) > 0 {
			var parts []string
			for _, v := range viol {
				parts = append(parts, string(v.Kind)+" "+v.Path)
			}
			return hold(model.HoldSealGuard, "seal guard: "+strings.Join(parts, ", "))
		}
		if err != nil {
			return hold(model.HoldUncapturable, "rules: "+err.Error())
		}
		newPlain = p
	default:
		newPlain = target
	}

	newRaw := newPlain
	if enc != "" {
		if newRaw, err = snap.cr().SealFile(enc, r.Source, newPlain); err != nil {
			return nil, nil, err
		}
	}
	// Round trip: the new source must reproduce the target byte for byte.
	got, rh, err := e.produceFrom(snap, r, newRaw, target)
	if err != nil || !bytes.Equal(got, target) {
		detail := "round trip failed: the new source does not reproduce the target"
		if err != nil {
			detail += ": " + err.Error()
		}
		_, h, herr := hold(failReason, detail)
		if h != nil && failReason == model.HoldRenderedEdit {
			*h = proposePatch(*h, r, enc, model.PatchOfTemplate, prevPlain, newPlain)
		}
		return nil, h, herr
	}
	if bytes.Equal(newRaw, prevRaw) {
		// Nothing to commit: the drift is only in parts the source does not own.
		ts.Written = hashOf(target)
		ts.Size, ts.ModTime, ts.Mode = lv.info.Size(), lv.info.ModTime(), uint32(lv.info.Mode().Perm())
		ts.RenderHash = rh
		ts.ChangedAt = time.Time{}
		st.Targets[t] = ts
		clearFileHolds(st, t)
		return nil, nil, nil
	}
	return &store.Change{Path: r.Source, Blob: newRaw, Mode: sourceMode(snap, r.Source)}, nil, nil
}

// literalCandidate builds a template that renders to want (the target, or
// its owned part under keep or drop) on this
// machine: a three-way merge of the template and the target over the last
// render, with each conflict resolved to the target's lines. Literal edits
// land beside the template's expressions; an edit on an expression or a
// conditional block replaces it with literal text. It returns false when
// the candidate does not render back to the target byte for byte.
func (e *Engine) literalCandidate(snap *Snapshot, r manifest.Resolved, tmpl, last, want, target []byte) ([]byte, bool) {
	merged, regions, err := e.Text.Merge3(last, tmpl, want)
	if err != nil {
		return nil, false
	}
	cand, ok := takeTheirs(merged, len(regions))
	if !ok {
		return nil, false
	}
	got, _, err := e.produceFrom(snap, r, cand, target)
	if err != nil || !bytes.Equal(got, target) {
		return nil, false
	}
	return cand, true
}

// takeTheirs resolves every conflict block of a textmerge.Merge3 result to
// its theirs side. want is the number of conflicts Merge3 reported; a
// different count of marker blocks means a marker line was ambiguous.
func takeTheirs(merged []byte, want int) ([]byte, bool) {
	var out bytes.Buffer
	state, n := 0, 0 // 0 outside, 1 ours side, 2 theirs side
	for _, line := range bytes.SplitAfter(merged, []byte("\n")) {
		bare := strings.TrimRight(string(line), "\r\n")
		switch {
		case state == 0 && bare == textmerge.MarkerOurs:
			state = 1
		case state == 1 && bare == textmerge.MarkerSep:
			state = 2
		case state == 2 && bare == textmerge.MarkerTheirs:
			state, n = 0, n+1
		case state == 1:
		default:
			out.Write(line)
		}
	}
	if state != 0 || n != want {
		return nil, false
	}
	return out.Bytes(), true
}

// proposePatch attaches a proposed source patch to a rendered_edit hold, so
// an agent can finish the capture in one step: edit Source, then commit.
// An enclave template gets no patch: holds live in the state file, which
// never holds plaintext.
func proposePatch(h model.Hold, r manifest.Resolved, enc model.EnclaveName, of string, from, to []byte) model.Hold {
	h.Source = r.Source
	if enc != "" {
		h.Next = append(h.Next, "yadm diff "+string(r.Target))
		return h
	}
	a, b := "a/"+string(r.Source), "b/"+string(r.Source)
	if of == model.PatchOfRender {
		a, b = "last-render/"+string(r.Target), "target/"+string(r.Target)
	}
	d, err := textmerge.Diff(a, b, from, to)
	if err != nil || d == "" {
		return h
	}
	h.Patch, h.PatchOf = d, of
	h.Next = append(h.Next, "edit "+string(r.Source)+" and run yadm commit "+string(r.Target))
	return h
}

// prevSource reads the source bytes the target was last applied from.
func (e *Engine) prevSource(ctx context.Context, snap *Snapshot, ts TargetState, p model.SourcePath) ([]byte, error) {
	if ts.SourceBlob != "" {
		return e.Store.ReadBlob(ctx, ts.SourceBlob)
	}
	b, _, err := e.readSource(ctx, snap, p)
	return b, err
}

// captureNew captures a new file inside an owned root into files/<target>,
// or sealed/<enclave>/<target> for an enclave root. Only roots this machine
// accepted (st.Roots) count, never the manifest's own list: a pusher who
// adds a root or strips its enclave changes nothing here until the user
// allows it. A file that predates its root (st.Baseline) is captured only
// when the caller named it (Drift.Named).
func (e *Engine) captureNew(ctx context.Context, snap *Snapshot, st *State, d Drift) (*store.Change, *model.Hold, error) {
	now := e.Now()
	if inBaseline(st, d.Target) && !d.Named {
		return nil, nil, nil
	}
	root, ok := rootOf(&manifest.Plan{Roots: st.Roots}, d.Target)
	if !ok {
		return nil, nil, nil
	}
	abs, err := e.abs(d.Target)
	if err != nil {
		return nil, nil, err
	}
	lv, err := e.readTarget(ctx, abs)
	if err != nil || !lv.exists || !lv.info.Mode().IsRegular() {
		return nil, nil, nil
	}
	mode := uint32(gitModeFile)
	if lv.info.Mode().Perm()&0o111 != 0 {
		mode = gitModeExec
	}
	if root.Enclave == "" {
		return &store.Change{Path: model.SourcePath("files/" + string(d.Target)), Blob: lv.bytes, Mode: mode}, nil, nil
	}
	scope := model.Scope(root.Enclave)
	if !snap.canOpen(root.Enclave) {
		h := fileHold(st, now, d.Target, scope, model.HoldSealGuard, d.Since, "new file in an enclave root, and this machine is not a member")
		return nil, &h, nil
	}
	p := model.SourcePath("sealed/" + string(root.Enclave) + "/" + string(d.Target))
	blob, err := snap.cr().SealFile(root.Enclave, p, lv.bytes)
	if err != nil {
		return nil, nil, err
	}
	return &store.Change{Path: p, Blob: blob, Mode: mode}, nil, nil
}

func rootOf(p *manifest.Plan, t model.Target) (manifest.Root, bool) {
	var best manifest.Root
	found := false
	if p == nil {
		return best, false
	}
	for _, r := range p.Roots {
		prefix := strings.TrimSuffix(string(r.Path), "/") + "/"
		if strings.HasPrefix(string(t), prefix) && (!found || len(r.Path) > len(best.Path)) {
			best, found = r, true
		}
	}
	return best, found
}

// ResolveHold resolves one hold by id. Taking the target captures it (through
// the seal guard); taking the source rewrites the target; a file path is
// written to the target and then captured. A capture comes back in
// Result.Capture for the caller to commit through the gate.
func (e *Engine) ResolveHold(ctx context.Context, id string, opts ResolveOptions) (Result, error) {
	st, err := e.loadState()
	if err != nil {
		return Result{}, err
	}
	var h *model.Hold
	for i := range st.Holds {
		if st.Holds[i].ID == id {
			h = &st.Holds[i]
			break
		}
	}
	if h == nil {
		return Result{}, fmt.Errorf("no hold %s", id)
	}
	if !fileHoldReasons[h.Reason] || h.Target == "" {
		return Result{}, fmt.Errorf("hold %s (%s) is resolved by sync or task allow, not here", id, h.Reason)
	}
	t := h.Target
	snap, err := e.snapshot(ctx, st.Applied)
	if err != nil {
		return Result{}, err
	}
	now := e.Now()
	abs, err := e.abs(t)
	if err != nil {
		return Result{}, err
	}

	switch opts.Take {
	case "source":
		r, inPlan := snap.Plan.Targets[t]
		lv, err := e.readTarget(ctx, abs)
		if err != nil {
			return Result{}, err
		}
		if !inPlan {
			// Left the plan: taking the source means removing the target.
			if lv.exists && lv.info.Mode().IsRegular() {
				if err := e.backup(now, t, st.Targets[t].prot(), lv.bytes); err != nil {
					return Result{}, err
				}
				if err := os.Remove(abs); err != nil {
					return Result{}, err
				}
			}
			forget(st, t, now)
			clearFileHolds(st, t)
			return Result{Commit: snap.Commit, Actions: []Action{{Target: t, Kind: ActDelete, Scope: h.Scope, Reason: "hold resolved: take source"}}}, e.State.Save(st)
		}
		if enc := r.Entry.Enclave; enc != "" && !snap.canOpen(enc) {
			return Result{}, fmt.Errorf("%s: not a member of %s", t, enc)
		}
		if lv.exists && !lv.info.Mode().IsRegular() {
			return Result{}, fmt.Errorf("%s: not a regular file; remove it first", t)
		}
		ts, have := st.Targets[t]
		if detail, weak := e.weakened(ts, have, r); weak {
			return Result{}, fmt.Errorf("%s: %s", t, detail)
		}
		if detail, wide := widenedMode(snap, r); wide {
			return Result{}, fmt.Errorf("%s: %s", t, detail)
		}
		if detail, wide := e.modeWidenedSince(snap, r, ts, have); wide {
			return Result{}, fmt.Errorf("%s: %s", t, detail)
		}
		var lb []byte
		if lv.exists {
			lb = lv.bytes
		}
		d, err := e.produce(ctx, snap, r, lb, ts.SourceBlob)
		if err != nil {
			return Result{}, err
		}
		s := step{Action: Action{Target: t, Kind: ActWrite, Source: r.Source, Scope: d.scope, Reason: "hold resolved: take source", Unit: r.Unit}, d: d, live: lv, abs: abs}
		if err := e.execute(st, s, now); err != nil {
			return Result{}, err
		}
		return Result{Commit: snap.Commit, Actions: []Action{s.Action}}, e.State.Save(st)

	case "target", "":
		if opts.Take == "" {
			return Result{}, errors.New("resolve: --take source, target or a file path is required")
		}
	default:
		b, err := os.ReadFile(opts.Take)
		if err != nil {
			return Result{}, err
		}
		mode := os.FileMode(0o644)
		if lv, err := e.readTarget(ctx, abs); err == nil && lv.exists {
			if !lv.info.Mode().IsRegular() {
				return Result{}, fmt.Errorf("%s: not a regular file; remove it first", t)
			}
			mode = lv.info.Mode().Perm()
			if err := e.backup(now, t, e.backupProt(snap, st, t), lv.bytes); err != nil {
				return Result{}, err
			}
		} else if r, ok := snap.Plan.Targets[t]; ok {
			mode = modeOf(snap, r)
		}
		if err := e.writeAtomic(abs, b, mode, nil); err != nil {
			return Result{}, err
		}
	}

	// Take the target: capture it as it is now.
	ts := st.Targets[t]
	if _, inPlan := snap.Plan.Targets[t]; !inPlan {
		// A modified orphan: keep the file as it is and stop managing it.
		// It goes into the baseline, so an owned root over it never
		// captures it automatically.
		delete(st.Targets, t)
		st.Baseline[t] = now
		clearFileHolds(st, t)
		return Result{Commit: snap.Commit, Actions: []Action{{Target: t, Kind: ActSkip, Scope: h.Scope, Reason: "hold resolved: take target; no longer managed"}}}, e.State.Save(st)
	}
	kind := DriftModified
	if lv, err := e.readTarget(ctx, abs); err == nil && !lv.exists {
		kind = DriftDeleted
	}
	c, err := e.Capture(ctx, []Drift{{Target: t, Kind: kind, Scope: h.Scope, Since: ts.ChangedAt}})
	if err != nil {
		return Result{}, err
	}
	res := Result{Commit: snap.Commit, Holds: c.Holds}
	if len(c.Holds) > 0 {
		return res, nil
	}
	if len(c.Changes) == 0 {
		// A no-op capture must have marked the target clean in state.
		after, err := e.loadState()
		if err != nil {
			return res, err
		}
		lv, err := e.readTarget(ctx, abs)
		if err != nil || !lv.exists || after.Targets[t].Written != hashOf(lv.bytes) {
			return res, fmt.Errorf("resolve %s: capture produced no change and the target is still drifted", id)
		}
		res.Actions = []Action{{Target: t, Kind: ActSkip, Scope: h.Scope, Reason: "hold resolved: target already matches the source"}}
		return res, nil
	}
	res.Capture = &c
	res.Actions = []Action{{Target: t, Kind: ActHold, Scope: h.Scope, Reason: "hold resolved: take target; commit the capture"}}
	return res, nil
}
