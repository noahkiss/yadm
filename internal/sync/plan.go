package sync

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// syncHoldReasons are the hold reasons sync owns on targets. A run that
// re-evaluates a target replaces them.
var syncHoldReasons = map[model.HoldReason]bool{
	model.HoldProtected:     true,
	model.HoldCheckFailed:   true,
	model.HoldTaskUntrusted: true, // only holds with a Target: the gate's
}

// PlanCommits splits captured changes into per-scope commits and holds.
//
// A captured path is planned when its quiet period has passed since its last
// change, no lease names it, it holds no open conflict and it is not
// protected. Protected paths (built-in and Policy globs, Policy.Protect,
// deletions, and every path of a scope with more than Policy.MassChange
// changes) come back as model.HoldProtected. Quiet and leased paths are
// neither planned nor held: they stay pending drift.
func PlanCommits(c apply.Capture, st *apply.State, p Policy, leases []Lease, self model.MachineID, now time.Time) ([]PlannedCommit, []model.Hold, error) {
	if len(c.Changes) != len(c.Paths) {
		return nil, nil, fmt.Errorf("plan commits: %d changes for %d paths", len(c.Changes), len(c.Paths))
	}
	if st == nil {
		st = &apply.State{}
	}
	mass := p.MassChange
	if mass <= 0 {
		mass = DefaultMassChange
	}
	var holds []model.Hold
	hold := func(t model.Target, scope model.Scope, detail string) {
		holds = append(holds, targetHold(st, now, t, scope, model.HoldProtected, sinceOf(st, t, now), detail,
			"yadm commit "+string(t)))
	}

	perScope := map[model.Scope]int{}
	for _, t := range c.Paths {
		perScope[scopeOf(c, t)]++
	}

	byScope := map[model.Scope][]store.Change{}
	targets := map[model.Scope][]model.Target{}
	for i, t := range c.Paths {
		ch := c.Changes[i]
		scope := scopeOf(c, t)
		switch {
		case hasHold(st, t, model.HoldConflict):
			continue // resolve the conflict first
		case ch.Delete:
			hold(t, scope, "deletion; commit it by name")
			continue
		case protected(p, t, ch.Path):
			hold(t, scope, "protected; commit it by name")
			continue
		case perScope[scope] > mass:
			hold(t, scope, fmt.Sprintf("%d changed files in scope %s exceed the limit of %d; commit them by name", perScope[scope], scope, mass))
			continue
		case leased(leases, t, now):
			continue
		}
		q := p.Quiet
		if p.QuietFor != nil {
			if d, ok := p.QuietFor(t); ok {
				q = d
			}
		}
		last := lastChange(st, p, t)
		if !last.IsZero() && now.Sub(last) < q {
			continue
		}
		byScope[scope] = append(byScope[scope], ch)
		targets[scope] = append(targets[scope], t)
	}

	scopes := make([]model.Scope, 0, len(byScope))
	for sc := range byScope {
		scopes = append(scopes, sc)
	}
	sort.Slice(scopes, func(i, j int) bool { return scopeLess(scopes[i], scopes[j]) })
	var out []PlannedCommit
	for _, sc := range scopes {
		out = append(out, PlannedCommit{
			Scope:   sc,
			Changes: byScope[sc],
			Targets: targets[sc],
			Message: commitMessage("auto", p.Host, self, sc, targets[sc], true),
		})
	}
	return out, holds, nil
}

// scopeLess orders shared first, then enclaves by name.
func scopeLess(a, b model.Scope) bool {
	if a == model.ScopeShared || b == model.ScopeShared {
		return a == model.ScopeShared && b != model.ScopeShared
	}
	return a < b
}

func scopeOf(c apply.Capture, t model.Target) model.Scope {
	if s := c.Scopes[t]; s != "" {
		return s
	}
	return model.ScopeShared
}

func protected(p Policy, t model.Target, src model.SourcePath) bool {
	if p.Protect != nil && p.Protect(t) {
		return true
	}
	for _, g := range append(append([]string(nil), manifest.BuiltinProtected...), p.Protected...) {
		if manifest.Match(g, string(t)) || manifest.Match(g, string(src)) {
			return true
		}
	}
	return false
}

// lastChange is the time of a target's last change: Policy.LastChange (the
// file's mtime) when known, else when its drift was first seen.
func lastChange(st *apply.State, p Policy, t model.Target) time.Time {
	if p.LastChange != nil {
		if at := p.LastChange(t); !at.IsZero() {
			return at
		}
	}
	if ts, ok := st.Targets[t]; ok && !ts.ChangedAt.IsZero() {
		return ts.ChangedAt
	}
	return st.Seen[t]
}

func sinceOf(st *apply.State, t model.Target, now time.Time) time.Time {
	if ts, ok := st.Targets[t]; ok && !ts.ChangedAt.IsZero() {
		return ts.ChangedAt
	}
	if at, ok := st.Seen[t]; ok {
		return at
	}
	return now
}

func hasHold(st *apply.State, t model.Target, reasons ...model.HoldReason) bool {
	for _, h := range st.Holds {
		if h.Target != t {
			continue
		}
		for _, r := range reasons {
			if h.Reason == r {
				return true
			}
		}
	}
	return false
}

// targetHold builds a sync-owned hold on a target. Since is kept from an
// existing hold of the same target and reason, so the id stays stable.
func targetHold(st *apply.State, now time.Time, t model.Target, scope model.Scope, reason model.HoldReason, since time.Time, detail string, next ...string) model.Hold {
	if st != nil {
		for _, h := range st.Holds {
			if h.Target == t && h.Reason == reason {
				since = h.Since
				break
			}
		}
	}
	if since.IsZero() {
		since = now
	}
	if scope == "" {
		scope = model.ScopeShared
	}
	h := model.Hold{Target: t, Scope: scope, Reason: reason, Since: since, Detail: detail}
	h.ID = apply.HoldID(h)
	h.Next = append([]string{"yadm hold show " + h.ID}, next...)
	return h
}

// putHold inserts or replaces the hold with the same target, task and reason.
func putHold(st *apply.State, h model.Hold) {
	for i, x := range st.Holds {
		if x.Target == h.Target && x.Task == h.Task && x.Reason == h.Reason {
			st.Holds[i] = h
			return
		}
	}
	st.Holds = append(st.Holds, h)
}

// dropSyncHolds removes sync-owned holds on targets for which keep is false.
func dropSyncHolds(st *apply.State, drop func(model.Target) bool) {
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target != "" && syncHoldReasons[h.Reason] && drop(h.Target) {
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
}

// commitMessage builds an auto or manual commit message.
func commitMessage(kind, host string, self model.MachineID, scope model.Scope, targets []model.Target, auto bool) store.Message {
	if host == "" {
		host = string(self)
	}
	n := len(targets)
	unit := "files"
	if n == 1 {
		unit = "file"
	}
	lines := make([]string, len(targets))
	for i, t := range targets {
		lines[i] = string(t)
	}
	sort.Strings(lines)
	m := store.Message{
		Subject: fmt.Sprintf("%s(%s): %d %s [%s]", kind, host, n, unit, scope),
		Body:    strings.Join(lines, "\n"),
		Trailers: []store.Trailer{
			{Key: store.TrailerMachine, Value: string(self)},
		},
	}
	if auto {
		m.Trailers = append(m.Trailers, store.Trailer{Key: store.TrailerAuto, Value: "1"})
	}
	m.Trailers = append(m.Trailers, store.Trailer{Key: store.TrailerScope, Value: string(scope)})
	return m
}
