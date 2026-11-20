package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
)

// commitOut is what one commit step made.
type commitOut struct {
	ids         []model.CommitID
	committed   map[model.Target]bool
	resolutions []Resolution
	dirty       bool
}

// gateFor returns the commit gate: Deps.Gate, or one built from the plan's
// checks, this machine's allow list and the exec runner. The built gate
// fails closed when the allow list or runner is missing.
func (s *Syncer) gateFor(snap *apply.Snapshot) tasks.Gate {
	if s.Gate != nil {
		return PerTarget(s.Gate)
	}
	if snap == nil || snap.Plan == nil || len(snap.Plan.Checks) == 0 {
		return nil
	}
	var allow tasks.AllowList
	if s.Apply.Tasks != nil {
		allow = s.Apply.Tasks.Allow
	}
	return PerTarget(tasks.NewGateIn(snap.Plan.Checks, s.Exec, allow, s.Apply.StateDir))
}

// MaxGateSplit bounds how many failing targets PerTarget re-checks one by
// one; beyond it the batch verdict stands (fail closed).
const MaxGateSplit = 50

// PerTarget makes a gate give per-file verdicts. A check runs once on every
// file it matches; when it fails and so holds more than one file, each of
// those files is checked again on its own, and only the files that fail on
// their own stay held. One bad file never holds every file a broad check
// matched. Holds for an untrusted check are not split: they hold every
// match until the check is allowed.
func PerTarget(g tasks.Gate) tasks.Gate {
	if g == nil {
		return nil
	}
	if _, ok := g.(perTarget); ok {
		return g
	}
	return perTarget{g}
}

type perTarget struct{ inner tasks.Gate }

func (p perTarget) Check(ctx context.Context, staged []tasks.Staged, req extexec.Request) ([]model.Target, []model.Hold, []tasks.Verdict) {
	pass, holds, verdicts := p.inner.Check(ctx, staged, req)
	var split []model.Target
	for _, h := range holds {
		if h.Reason == model.HoldCheckFailed {
			split = append(split, h.Target)
		}
	}
	if len(staged) < 2 || len(split) < 2 || len(split) > MaxGateSplit {
		return pass, holds, verdicts
	}
	byTarget := map[model.Target][]tasks.Staged{}
	for _, s := range staged {
		byTarget[s.Target] = append(byTarget[s.Target], s)
	}
	redo := map[model.Target]bool{}
	for _, t := range split {
		redo[t] = true
	}
	outHolds := holds[:0:0]
	for _, h := range holds {
		if !redo[h.Target] {
			outHolds = append(outHolds, h)
		}
	}
	outVerdicts := make([]tasks.Verdict, 0, len(verdicts))
	for _, v := range verdicts {
		if !redo[v.Target] {
			outVerdicts = append(outVerdicts, v)
		}
	}
	for _, t := range split {
		if err := ctx.Err(); err != nil {
			// Out of time: keep the batch verdict for the rest.
			for _, h := range holds {
				if h.Target == t {
					outHolds = append(outHolds, h)
				}
			}
			continue
		}
		p1, h1, v1 := p.inner.Check(ctx, byTarget[t], req)
		pass = append(pass, p1...)
		outHolds = append(outHolds, h1...)
		outVerdicts = append(outVerdicts, v1...)
	}
	return pass, outHolds, outVerdicts
}

// commit gates and commits planned changes onto local main, one commit per
// scope, each through store.CommitPaths (a fresh private index). A change
// captured against a source blob that main has since moved past is merged
// up the resolution ladder first, so a commit never silently reverts a
// change it did not see. Then main moves by compare-and-swap, the worktree
// follows, and apply records the committed targets.
//
// resolve names targets whose conflict the caller settled: they commit over
// the current source blob instead of going up the ladder again. A change in
// direct is not a target (a key-log entry, a manifest edit): it skips the
// gate, whose paths name targets, and commits against the current source.
//
// With partial set, the caller applies everything later in this run (the
// exchange, or settle): the commit's own apply then covers only the targets
// it touched, unless it changed a source that is not a target (a manifest
// or key-log edit), which can change any target.
func (s *Syncer) commit(ctx context.Context, rep *Report, snap *apply.Snapshot, planned []PlannedCommit, drift []apply.Drift, resolve map[model.Target]bool, partial bool) (commitOut, error) {
	out := commitOut{committed: map[model.Target]bool{}}
	if len(planned) == 0 {
		return out, nil
	}
	now := s.now()
	st, err := s.Apply.State.Load()
	if err != nil {
		return out, err
	}
	head, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return out, err
	}
	headTree, err := s.treeMap(ctx, head)
	if err != nil {
		return out, err
	}
	appliedTree := headTree
	if st.Applied != head {
		if appliedTree, err = s.treeMap(ctx, st.Applied); err != nil {
			return out, err
		}
	}

	// The commit gate sees the target plaintext of every staged, non-deleted file.
	var staged []tasks.Staged
	unreadable := map[model.Target]bool{}
	direct := map[model.Target]bool{}
	for _, pc := range planned {
		for i, t := range pc.Targets {
			if pc.Changes[i].Delete {
				continue
			}
			if pc.isDirect(i) {
				// Not a target: a key-log entry or a manifest edit is tool
				// output (signed or structural) that holds no plaintext.
				// The gate's paths name targets, so it does not see these.
				direct[t] = true
				continue
			}
			b, err := os.ReadFile(filepath.Join(s.Apply.Home, filepath.FromSlash(string(t))))
			if err != nil {
				unreadable[t] = true
				putHold(st, targetHold(st, now, t, pc.Scope, model.HoldCheckFailed, now, "unreadable for the commit gate: "+err.Error()))
				continue
			}
			staged = append(staged, tasks.Staged{Target: t, Scope: pc.Scope, Plaintext: b})
		}
	}
	pass := map[model.Target]bool{}
	for t := range direct {
		pass[t] = true
	}
	if g := s.gateFor(snap); g == nil {
		for _, x := range staged {
			pass[x.Target] = true
		}
	} else if len(staged) > 0 {
		ok, holds, _ := g.Check(ctx, staged, s.request(snap, head))
		for _, t := range ok {
			pass[t] = true
		}
		for _, h := range holds {
			putHold(st, targetHold(st, now, h.Target, h.Scope, h.Reason, now, h.Detail, h.Next...))
		}
	}
	for i := range staged {
		staged[i].Plaintext = nil
	}

	hashes := map[model.Target]string{}
	for _, d := range drift {
		hashes[d.Target] = d.Hash
	}
	r := &resolver{s: s, snap: snap, st: st}
	tip := head
	written := map[model.Target]string{}
	var touched []model.Target // targets whose source the commits change
	whole := false             // a commit changes a source that is not a target
	for _, pc := range planned {
		var changes []store.Change
		var landed []model.Target
		var trailers []store.Trailer
		merged := 0
		var mergeNote string
		for i, ch := range pc.Changes {
			t := pc.Targets[i]
			if !ch.Delete && !pass[t] {
				continue // held by the gate, or unreadable
			}
			base := baseBlob(st, appliedTree, t, ch.Path)
			cur := headTree[ch.Path].Blob
			if pc.isDirect(i) || resolve[t] {
				base = cur
			}
			if base == cur && !ch.Delete && cur != "" {
				// Already in the source (a root file no entry manages yet): no commit.
				id, err := s.blobID(ctx, ch.Blob)
				if err != nil {
					return out, err
				}
				if id == cur {
					out.committed[t] = true
					continue
				}
			}
			if base == cur {
				changes = append(changes, ch)
				landed = append(landed, t)
				continue
			}
			if ch.Delete {
				if cur == "" {
					out.committed[t] = true // already deleted upstream
					continue
				}
				h := conflictHold(st, now, t, pc.Scope, store.Conflict{Path: ch.Path, Base: base, Theirs: cur}, "deleted here, changed in the source since the last apply")
				putHold(st, h)
				continue
			}
			ours, err := s.blobID(ctx, ch.Blob)
			if err != nil {
				return out, err
			}
			if ours == cur {
				out.committed[t] = true // the source already holds these bytes
				continue
			}
			rc, h, rung, err := r.resolve(ctx, conflict{Conflict: store.Conflict{Path: ch.Path, Base: base, Ours: ours, Theirs: cur}, Mode: ch.Mode})
			if err != nil {
				return out, err
			}
			out.resolutions = append(out.resolutions, Resolution{Path: ch.Path, Target: t, Rung: rung})
			if h != nil {
				putHold(st, *h)
				continue
			}
			changes = append(changes, *rc)
			landed = append(landed, t)
			written[t] = hashes[t]
			trailers = append(trailers, store.Trailer{Key: TrailerResolved, Value: rung + " " + string(ch.Path)})
			merged++
			mergeNote = "merge " + string(t) + " (" + rung + ")"
		}
		if len(changes) == 0 {
			continue
		}
		var msg store.Message
		if pc.Info.Trigger != "" || pc.Info.Subject != "" {
			info := pc.Info
			if merged == len(landed) {
				info.Trigger = TriggerMerge
				if merged == 1 && info.Subject == "" {
					info.Subject = mergeNote
				}
			}
			msg = commitMessage(info, s.self(), pc.Scope, itemsOf(st, landed, changes), trailers...)
		} else {
			msg = pc.Message
			msg.Trailers = append(append([]store.Trailer(nil), msg.Trailers...), trailers...)
		}
		id, err := s.Store.CommitPaths(ctx, tip, changes, msg)
		if err != nil {
			return out, fmt.Errorf("commit %s: %w", pc.Scope, err)
		}
		tip = id
		out.ids = append(out.ids, id)
		for _, t := range landed {
			out.committed[t] = true
		}
		for i, ch := range pc.Changes {
			for _, c := range changes {
				if c.Path != ch.Path {
					continue
				}
				if pc.isDirect(i) {
					whole = true
				} else {
					touched = append(touched, pc.Targets[i])
				}
			}
		}
	}
	// A merged change lets apply replace the target only while it still holds
	// the bytes that were captured.
	for t, h := range written {
		if ts, ok := st.Targets[t]; ok && h != "" {
			ts.Written = h
			st.Targets[t] = ts
		}
	}
	if err := s.Apply.State.Save(st); err != nil {
		return out, err
	}
	if tip == head {
		return out, nil
	}
	if out.dirty, err = s.setMain(ctx, tip, head); err != nil || out.dirty {
		return out, err
	}
	if partial && !whole && len(touched) > 0 {
		out.dirty, err = s.moveAndApplyPaths(ctx, rep, tip, touched)
		return out, err
	}
	dirty, err := s.moveAndApply(ctx, rep, tip, false)
	out.dirty = dirty
	return out, err
}

// baseBlob is the source blob a capture of t was made against.
func baseBlob(st *apply.State, applied map[model.SourcePath]store.TreeEntry, t model.Target, p model.SourcePath) string {
	if ts, ok := st.Targets[t]; ok && ts.Source == p && ts.SourceBlob != "" {
		return ts.SourceBlob
	}
	return applied[p].Blob
}

// Commit makes a manual commit: capture, gate, one commit per scope through a
// fresh private index. It bypasses the quiet period and leases but never the
// gate or the seal guard. Protected paths need to be named in Paths, unless
// the commit is Unattended. With Push it then fetches, replays, applies,
// publishes and pushes under the same lock, so the commit reaches the remote
// in this call; without it the next sync pushes.
func (s *Syncer) Commit(ctx context.Context, opts CommitOptions) (Report, error) {
	var rep Report
	if err := s.check(); err != nil {
		return rep, err
	}
	release, err := s.Lock.Acquire(ctx)
	if err != nil {
		return rep, err
	}
	defer release()
	defer s.begin()()

	head, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return rep, err
	}
	if opts.Resolve && opts.Capture == nil {
		if err := s.rebaseOnto(ctx, head, opts.Paths); err != nil {
			return rep, err
		}
	}
	var cp apply.Capture
	var drift []apply.Drift
	if opts.Capture != nil {
		cp = *opts.Capture
	} else if len(opts.Changes) == 0 || len(opts.Paths) > 0 {
		// Scan everything (owned roots included), then keep the named paths.
		// Resolving hashes every file: a target captured before its conflict
		// was raised has an unchanged stat tuple but no longer matches.
		all, err := s.Apply.Scan(ctx, apply.ScanOptions{FullHash: opts.Resolve})
		if err != nil {
			return rep, fmt.Errorf("scan: %w", err)
		}
		// A named path is scanned by name too, so a file that predates its
		// owned root (a baseline file) is captured when asked for.
		byName := map[model.Target]apply.Drift{}
		if len(opts.Paths) > 0 {
			nd, err := s.Apply.Scan(ctx, apply.ScanOptions{FullHash: opts.Resolve, Paths: opts.Paths})
			if err != nil {
				return rep, fmt.Errorf("scan: %w", err)
			}
			for _, d := range nd {
				byName[d.Target] = d
			}
		}
		for _, d := range all {
			if len(opts.Paths) == 0 || named(opts.Paths, d.Target) {
				if n, ok := byName[d.Target]; ok {
					d = n
					delete(byName, d.Target)
				}
				drift = append(drift, d)
			}
		}
		for _, d := range byName {
			drift = append(drift, d)
		}
		sort.Slice(drift, func(i, j int) bool { return drift[i].Target < drift[j].Target })
		if cp, err = s.Apply.Capture(ctx, drift); err != nil {
			return rep, fmt.Errorf("capture: %w", err)
		}
	}
	if len(cp.Changes) != len(cp.Paths) {
		return rep, fmt.Errorf("commit: %d changes for %d paths", len(cp.Changes), len(cp.Paths))
	}
	rep.Captured = cp.Paths
	st, err := s.Apply.State.Load()
	if err != nil {
		return rep, err
	}
	snap, err := s.snapshotAt(ctx, st.Applied, head)
	if err != nil {
		return rep, err
	}
	pol := s.policyFor(snap)
	now := s.now()
	info := MessageInfo{Trigger: opts.Trigger, Subject: opts.Message, Session: opts.Session, Tool: opts.Tool}
	if info.Trigger == "" {
		info.Trigger = TriggerManual
	}

	resolve := map[model.Target]bool{}
	byScope := map[model.Scope]*PlannedCommit{}
	plan := func(scope model.Scope) *PlannedCommit {
		pc := byScope[scope]
		if pc == nil {
			pc = &PlannedCommit{Scope: scope, Info: info}
			byScope[scope] = pc
		}
		return pc
	}
	for i, t := range cp.Paths {
		ch := cp.Changes[i]
		scope := scopeOf(cp, t)
		isNamed := opts.Capture != nil || (len(opts.Paths) > 0 && named(opts.Paths, t))
		switch {
		case opts.Resolve && isNamed:
			// The caller settled the conflict: commit this side over the
			// current source and drop the hold.
			dropHolds(st, t, model.HoldConflict)
			resolve[t] = true
		case hasHold(st, t, model.HoldConflict):
			continue
		}
		dropSyncHolds(st, func(x model.Target) bool { return x == t })
		approved := isNamed && !opts.Unattended
		switch {
		case !approved && (ch.Delete || protected(pol, t, ch.Path)):
			putHold(st, targetHold(st, now, t, scope, model.HoldProtected, sinceOf(st, t, now), "protected; commit it by name", "yadm commit "+string(t)))
			continue
		case opts.Unattended && isNew(st, t):
			// A new file in an owned root: which machines get it is a decision.
			putHold(st, targetHold(st, now, t, scope, model.HoldProtected, sinceOf(st, t, now),
				"new file; commit it by name to share it, or retag it first", "yadm commit "+string(t), "yadm retag "+string(t)+" <type>[,<type>...]"))
			continue
		}
		pc := plan(scope)
		pc.Changes = append(pc.Changes, ch)
		pc.Targets = append(pc.Targets, t)
		pc.direct = append(pc.direct, false)
	}
	for _, ch := range opts.Changes {
		scope := opts.ChangesScope
		if scope == "" {
			scope = model.ScopeShared
		}
		pc := plan(scope)
		pc.Changes = append(pc.Changes, ch)
		pc.Targets = append(pc.Targets, model.Target(ch.Path))
		pc.direct = append(pc.direct, true)
	}
	scopes := make([]model.Scope, 0, len(byScope))
	for sc := range byScope {
		scopes = append(scopes, sc)
	}
	sort.Slice(scopes, func(i, j int) bool { return scopeLess(scopes[i], scopes[j]) })
	var planned []PlannedCommit
	for _, sc := range scopes {
		pc := byScope[sc]
		pc.Message = commitMessage(info, s.self(), sc, itemsOf(st, pc.Targets, pc.Changes))
		planned = append(planned, *pc)
	}
	if opts.DryRun {
		committed := map[model.Target]bool{}
		for _, pc := range planned {
			for _, t := range pc.Targets {
				committed[t] = true
			}
		}
		rep.Pending = pending(cp.Paths, committed, st)
		rep.Holds = reportHolds(st, rep.Pending)
		return rep, nil
	}
	if err := s.Apply.State.Save(st); err != nil {
		return rep, err
	}
	out, err := s.commit(ctx, &rep, snap, planned, drift, resolve, opts.Push)
	if err != nil {
		return s.settle(ctx, rep, cp.Paths, out.committed, err)
	}
	rep.Committed = out.ids
	rep.Resolutions = out.resolutions
	if a, err := s.Store.ResolveRef(ctx, store.RefMain); err == nil && len(out.ids) > 0 && !out.dirty {
		rep.Applied = a
	}
	if opts.Push && !out.dirty {
		r, err := s.exchange(ctx, rep, head, cp.Paths, out.committed, Options{Push: true, MaxRetries: opts.MaxRetries})
		r, err = s.settle(ctx, r, cp.Paths, out.committed, err)
		if err != nil {
			return r, &ExchangeError{Err: err}
		}
		return r, nil
	}
	return s.finish(ctx, rep, cp.Paths, out.committed)
}

// rebaseOnto settles the conflicts of the named targets in favour of the
// live files: each target's capture base becomes its source blob at head,
// its conflict hold goes, and its last-written hash is cleared so the scan
// sees it. The capture that follows is then the live file against the
// current source, and it commits without going up the ladder again.
func (s *Syncer) rebaseOnto(ctx context.Context, head model.CommitID, paths []model.Target) error {
	tree, err := s.treeMap(ctx, head)
	if err != nil {
		return err
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	for t, ts := range st.Targets {
		if !named(paths, t) {
			continue
		}
		if e, ok := tree[ts.Source]; ok {
			ts.SourceBlob = e.Blob
		}
		ts.Written = ""
		st.Targets[t] = ts
		dropHolds(st, t, model.HoldConflict)
	}
	return s.Apply.State.Save(st)
}

// baselineDetail marks the protected holds holdBaseline owns.
const baselineDetail = "existed before its owned root was accepted here; commit it by name if it belongs in the repository"

// holdBaseline holds each file of a complete scan that predates its owned
// root (apply reports it with Drift.Baseline and does not capture it), so
// the user sees it, and drops such holds for files that are gone or
// managed now.
func (s *Syncer) holdBaseline(drift []apply.Drift, cp apply.Capture) error {
	captured := map[model.Target]bool{}
	for _, t := range cp.Paths {
		captured[t] = true
	}
	base := map[model.Target]apply.Drift{}
	for _, d := range drift {
		if d.Baseline && !captured[d.Target] {
			base[d.Target] = d
		}
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	changed := false
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Reason == model.HoldProtected && h.Detail == baselineDetail {
			if _, ok := base[h.Target]; !ok {
				changed = true
				continue
			}
		}
		out = append(out, h)
	}
	st.Holds = out
	now := s.now()
	for t, d := range base {
		if hasHold(st, t, model.HoldProtected) {
			continue
		}
		putHold(st, targetHold(st, now, t, d.Scope, model.HoldProtected, sinceOf(st, t, now), baselineDetail, "yadm commit "+string(t)))
		changed = true
	}
	if !changed {
		return nil
	}
	return s.Apply.State.Save(st)
}

// ExchangeError wraps a failure after Commit's own commit step: fetch,
// replay, apply or push. The commits in the report stand; the next sync
// pushes them.
type ExchangeError struct{ Err error }

func (e *ExchangeError) Error() string { return "after the commit: " + e.Err.Error() }
func (e *ExchangeError) Unwrap() error { return e.Err }

// dropHolds removes t's holds with one of reasons.
func dropHolds(st *apply.State, t model.Target, reasons ...model.HoldReason) {
	out := st.Holds[:0]
	for _, h := range st.Holds {
		drop := false
		if h.Target == t {
			for _, r := range reasons {
				drop = drop || h.Reason == r
			}
		}
		if !drop {
			out = append(out, h)
		}
	}
	st.Holds = out
}

// named reports whether t is one of paths or below one of them.
func named(paths []model.Target, t model.Target) bool {
	for _, p := range paths {
		if p == t || strings.HasPrefix(string(t), strings.TrimSuffix(string(p), "/")+"/") {
			return true
		}
	}
	return false
}

// collect runs the allowed collectors and stores their facts in local state.
// A failed collector records its error and never fails the sync.
func (s *Syncer) collect(ctx context.Context, head model.CommitID) error {
	if s.Exec == nil || head == "" {
		return nil
	}
	snap, err := s.load(ctx, head)
	if err != nil {
		return nil // nothing to resolve collectors against; apply reports the error
	}
	fl := snap.Fleet
	if fl == nil {
		fl = s.Fleet
	}
	if fl == nil || len(fl.Collectors) == 0 {
		return nil
	}
	var allow tasks.AllowList
	if s.Apply.Tasks != nil {
		allow = s.Apply.Tasks.Allow
	}
	allowed := func(name string, def any) bool {
		if allow == nil {
			return false
		}
		h, err := tasks.DefinitionHash(def)
		return err == nil && allow.Allowed(extexec.KindCollector, name, h)
	}
	base := s.request(snap, head)
	facts, _, err := collectWith(ctx, fl, snap.Context, s.Exec, allowed, base)
	if err != nil {
		return err
	}
	if len(facts) == 0 {
		return nil
	}
	st, err := s.Apply.State.Load()
	if err != nil {
		return err
	}
	if st.Observed == nil {
		st.Observed = map[string]model.ObservedFact{}
	}
	for k, v := range facts {
		st.Observed[k] = v
	}
	// New facts can change renders and task inputs: the next apply of
	// even the same commit must run in full.
	s.applied = ""
	return s.Apply.State.Save(st)
}

// isDirect reports whether Changes[i] is not a target.
func (pc PlannedCommit) isDirect(i int) bool { return i < len(pc.direct) && pc.direct[i] }
