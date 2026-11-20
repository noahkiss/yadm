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
	if !have || !inPlan {
		return nil, nil, nil // left the plan: apply deletes or holds it
	}
	scope := r.Entry.Scope()
	hold := func(reason model.HoldReason, detail string) (*store.Change, *model.Hold, error) {
		h := fileHold(st, now, t, scope, reason, ts.ChangedAt, detail)
		return nil, &h, nil
	}
	if r.Source != ts.Source {
		return hold(model.HoldUncapturable, fmt.Sprintf("source moved from %s to %s since last apply", ts.Source, r.Source))
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
		if prevPlain, err = snap.cr().OpenFile(enc, prevRaw); err != nil {
			return hold(model.HoldUncapturable, "cannot open the stored source: "+err.Error())
		}
	}

	spec := rules.SpecOf(r.Entry)
	var newPlain []byte
	failReason := model.HoldUncapturable
	switch {
	case r.Entry.Template:
		failReason = model.HoldRenderedEdit
		if !spec.Empty() {
			return hold(model.HoldUncapturable, "template with intra-file rules; edit the template")
		}
		if st.RenderContext == nil || snap.Render == nil {
			return hold(model.HoldRenderedEdit, "no stored render context to recompute the last render")
		}
		last, err := snap.Render.Render(string(r.Source), prevPlain, *st.RenderContext)
		if err != nil || hashOf(last) != ts.RenderHash {
			return hold(model.HoldRenderedEdit, "cannot recompute the last render")
		}
		p, err := e.Text.PatchTemplate(prevPlain, last, target)
		if err != nil {
			return hold(model.HoldRenderedEdit, "hand edit does not patch into the template: "+err.Error())
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
		if newRaw, err = snap.cr().SealFile(enc, newPlain); err != nil {
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
		return hold(failReason, detail)
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
	mode := uint32(gitModeFile)
	if te, ok := snap.Tree[r.Source]; ok && te.Mode == gitModeExec && enc == "" {
		mode = gitModeExec
	}
	return &store.Change{Path: r.Source, Blob: newRaw, Mode: mode}, nil, nil
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
// or sealed/<enclave>/<target> for an enclave root.
func (e *Engine) captureNew(ctx context.Context, snap *Snapshot, st *State, d Drift) (*store.Change, *model.Hold, error) {
	now := e.Now()
	root, ok := rootOf(snap.Plan, d.Target)
	if !ok {
		root, ok = rootOf(&manifest.Plan{Roots: st.Roots}, d.Target)
	}
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
	blob, err := snap.cr().SealFile(root.Enclave, lv.bytes)
	if err != nil {
		return nil, nil, err
	}
	return &store.Change{Path: model.SourcePath("sealed/" + string(root.Enclave) + "/" + string(d.Target)), Blob: blob, Mode: gitModeFile}, nil, nil
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
				if err := e.backup(now, t, lv.bytes); err != nil {
					return Result{}, err
				}
				if err := os.Remove(abs); err != nil {
					return Result{}, err
				}
			}
			delete(st.Targets, t)
			clearFileHolds(st, t)
			return Result{Commit: snap.Commit, Actions: []Action{{Target: t, Kind: ActDelete, Scope: h.Scope, Reason: "hold resolved: take source"}}}, e.State.Save(st)
		}
		if enc := r.Entry.Enclave; enc != "" && !snap.canOpen(enc) {
			return Result{}, fmt.Errorf("%s: not a member of %s", t, enc)
		}
		if lv.exists && !lv.info.Mode().IsRegular() {
			return Result{}, fmt.Errorf("%s: not a regular file; remove it first", t)
		}
		var lb []byte
		if lv.exists {
			lb = lv.bytes
		}
		d, err := e.produce(ctx, snap, r, lb)
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
			if err := e.backup(now, t, lv.bytes); err != nil {
				return Result{}, err
			}
		} else if r, ok := snap.Plan.Targets[t]; ok {
			mode = modeOf(snap, r)
		}
		if err := e.writeAtomic(abs, b, mode); err != nil {
			return Result{}, err
		}
	}

	// Take the target: capture it as it is now.
	ts := st.Targets[t]
	kind := DriftModified
	if lv, err := e.readTarget(ctx, abs); err == nil && !lv.exists {
		kind = DriftDeleted
	}
	c, err := e.Capture(ctx, []Drift{{Target: t, Kind: kind, Scope: h.Scope, Since: ts.ChangedAt}})
	if err != nil {
		return Result{}, err
	}
	res := Result{Commit: snap.Commit, Holds: c.Holds}
	if len(c.Holds) == 0 {
		res.Capture = &c
		res.Actions = []Action{{Target: t, Kind: ActHold, Scope: h.Scope, Reason: "hold resolved: take target; commit the capture"}}
	}
	return res, nil
}
