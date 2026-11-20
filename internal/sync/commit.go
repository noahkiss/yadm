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
		return s.Gate
	}
	if snap == nil || snap.Plan == nil || len(snap.Plan.Checks) == 0 {
		return nil
	}
	var allow tasks.AllowList
	if s.Apply.Tasks != nil {
		allow = s.Apply.Tasks.Allow
	}
	return tasks.NewGateIn(snap.Plan.Checks, s.Exec, allow, s.Apply.StateDir)
}

// commit gates and commits planned changes onto local main, one commit per
// scope, each through store.CommitPaths (a fresh private index). A change
// captured against a source blob that main has since moved past is merged
// up the resolution ladder first, so a commit never silently reverts a
// change it did not see. Then main moves by compare-and-swap, the worktree
// follows, and apply records the committed targets.
func (s *Syncer) commit(ctx context.Context, rep *Report, snap *apply.Snapshot, planned []PlannedCommit, drift []apply.Drift) (commitOut, error) {
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
	for _, pc := range planned {
		for i, t := range pc.Targets {
			if pc.Changes[i].Delete {
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
	for _, pc := range planned {
		var changes []store.Change
		var landed []model.Target
		var trailers []store.Trailer
		for i, ch := range pc.Changes {
			t := pc.Targets[i]
			if !ch.Delete && !pass[t] {
				continue // held by the gate, or unreadable
			}
			base := baseBlob(st, appliedTree, t, ch.Path)
			cur := headTree[ch.Path].Blob
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
		}
		if len(changes) == 0 {
			continue
		}
		msg := pc.Message
		if len(landed) != len(pc.Targets) {
			kind, _, _ := strings.Cut(msg.Subject, "(")
			auto := trailer(msg, store.TrailerAuto) == "1"
			subj := msg.Subject
			msg = commitMessage(kind, hostOf(msg.Subject), s.self(), pc.Scope, landed, auto)
			if !strings.HasPrefix(subj, kind+"(") || !strings.Contains(subj, " file") {
				msg.Subject = subj // a custom subject stays
			}
		}
		msg.Trailers = append(append([]store.Trailer(nil), msg.Trailers...), trailers...)
		id, err := s.Store.CommitPaths(ctx, tip, changes, msg)
		if err != nil {
			return out, fmt.Errorf("commit %s: %w", pc.Scope, err)
		}
		tip = id
		out.ids = append(out.ids, id)
		for _, t := range landed {
			out.committed[t] = true
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
	if err := s.Store.UpdateRef(ctx, store.RefMain, tip, head); err != nil {
		return out, err
	}
	dirty, err := s.moveAndApply(ctx, rep, tip)
	out.dirty = dirty
	return out, err
}

// hostOf extracts the host from "kind(host): ...".
func hostOf(subject string) string {
	_, rest, ok := strings.Cut(subject, "(")
	if !ok {
		return ""
	}
	h, _, _ := strings.Cut(rest, ")")
	return h
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
// gate or the seal guard. Protected paths need to be named in Paths. It does
// not fetch or push; the next sync does.
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
	s.snaps = nil
	defer func() { s.snaps = nil }()

	head, err := s.Store.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return rep, err
	}
	var cp apply.Capture
	var drift []apply.Drift
	if opts.Capture != nil {
		cp = *opts.Capture
	} else {
		if drift, err = s.Apply.Scan(ctx, apply.ScanOptions{Paths: opts.Paths}); err != nil {
			return rep, fmt.Errorf("scan: %w", err)
		}
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

	byScope := map[model.Scope]*PlannedCommit{}
	for i, t := range cp.Paths {
		ch := cp.Changes[i]
		scope := scopeOf(cp, t)
		named := opts.Capture != nil || (len(opts.Paths) > 0 && named(opts.Paths, t))
		if hasHold(st, t, model.HoldConflict) {
			continue
		}
		dropSyncHolds(st, func(x model.Target) bool { return x == t })
		if !named && (ch.Delete || protected(pol, t, ch.Path)) {
			putHold(st, targetHold(st, now, t, scope, model.HoldProtected, sinceOf(st, t, now), "protected; commit it by name", "yadm commit "+string(t)))
			continue
		}
		pc := byScope[scope]
		if pc == nil {
			pc = &PlannedCommit{Scope: scope}
			byScope[scope] = pc
		}
		pc.Changes = append(pc.Changes, ch)
		pc.Targets = append(pc.Targets, t)
	}
	scopes := make([]model.Scope, 0, len(byScope))
	for sc := range byScope {
		scopes = append(scopes, sc)
	}
	sort.Slice(scopes, func(i, j int) bool { return scopeLess(scopes[i], scopes[j]) })
	var planned []PlannedCommit
	for _, sc := range scopes {
		pc := byScope[sc]
		pc.Message = commitMessage("commit", pol.Host, s.self(), sc, pc.Targets, false)
		if m := strings.TrimSpace(opts.Message); m != "" {
			pc.Message.Subject = m
		}
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
	out, err := s.commit(ctx, &rep, snap, planned, drift)
	if err != nil {
		return rep, err
	}
	rep.Committed = out.ids
	rep.Resolutions = out.resolutions
	if a, err := s.Store.ResolveRef(ctx, store.RefMain); err == nil && len(out.ids) > 0 && !out.dirty {
		rep.Applied = a
	}
	return s.finish(ctx, rep, cp.Paths, out.committed)
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
	return s.Apply.State.Save(st)
}
