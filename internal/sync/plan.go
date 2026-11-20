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
			"yadm commit "+model.ShellQuote(string(t))))
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
		case p.MergeFor != nil && (p.MergeFor(t) == MergeGenerated || p.MergeFor(t) == MergeRegenerate):
			continue // generated files are never auto-committed
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
			Message: commitMessage(MessageInfo{Trigger: TriggerScan}, self, sc, itemsOf(st, targets[sc], byScope[sc])),
			Info:    MessageInfo{Trigger: TriggerScan},
		})
	}
	return out, holds, nil
}

// isNew reports whether t is not managed yet (a new file in an owned root).
func isNew(st *apply.State, t model.Target) bool {
	_, ok := st.Targets[t]
	return !ok
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

// targetHold builds a sync-owned hold on a target. model.KeepSince keeps
// Since from an existing hold of the same target and reason, so the id stays
// stable across runs.
func targetHold(st *apply.State, now time.Time, t model.Target, scope model.Scope, reason model.HoldReason, since time.Time, detail string, next ...string) model.Hold {
	if scope == "" {
		scope = model.ScopeShared
	}
	h := model.Hold{Target: t, Scope: scope, Reason: reason, Since: since, Detail: detail}
	var prev []model.Hold
	if st != nil {
		prev = st.Holds
	}
	h = model.KeepSince(prev, h, now)
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

// Commit triggers, the value of the Yadm-Auto trailer.
const (
	TriggerHook   = "hook"   // an agent harness hook captured an edit
	TriggerStop   = "stop"   // an agent harness flushed a session at its end
	TriggerScan   = "scan"   // the timer's scan found the change
	TriggerManual = "manual" // `yadm commit`
	TriggerMerge  = "merge"  // a commit whose only change was merged up the ladder
)

// Trailer keys sync writes besides store.TrailerMachine, TrailerAuto and TrailerScope.
const (
	TrailerSession = "Yadm-Session" // the harness session id, when known
	TrailerTool    = "Yadm-Tool"    // the tool that made the edit (Edit, Write, Bash, an app), when known
)

// MessageInfo is what a commit message is built from besides its targets.
type MessageInfo struct {
	Trigger string // TriggerHook, TriggerStop, TriggerScan, TriggerManual or TriggerMerge
	Subject string // a caller's subject (`-m`, `--why`); empty builds one from the paths
	Session string
	Tool    string
}

// MessageItem is one target of a commit and what happened to it.
type MessageItem struct {
	Target model.Target
	Verb   string // "add", "update" or "remove"
}

// commitMessage builds the message of a tool commit. The subject reads like a
// human one: `<verb> <path>`, `<verb> N files in <dir>` or `<verb> N files`;
// a caller's subject wins. The body lists every target. Messages name paths
// only, never content, so no enclave plaintext reaches a message or trailer.
func commitMessage(info MessageInfo, self model.MachineID, scope model.Scope, items []MessageItem, extra ...store.Trailer) store.Message {
	lines := make([]string, len(items))
	verbs := map[string]bool{}
	for i, it := range items {
		lines[i] = string(it.Target)
		verbs[it.Verb] = true
	}
	sort.Strings(lines)
	subject := strings.TrimSpace(info.Subject)
	if i := strings.IndexByte(subject, '\n'); i >= 0 {
		subject = strings.TrimSpace(subject[:i])
	}
	if subject == "" {
		subject = mechanicalSubject(verbs, lines)
	}
	trigger := info.Trigger
	if trigger == "" {
		trigger = TriggerManual
	}
	m := store.Message{
		Subject: subject,
		Body:    strings.Join(lines, "\n"),
		Trailers: []store.Trailer{
			{Key: store.TrailerMachine, Value: string(self)},
			{Key: store.TrailerAuto, Value: trigger},
			{Key: store.TrailerScope, Value: string(scope)},
		},
	}
	if v := oneLine(info.Session); v != "" {
		m.Trailers = append(m.Trailers, store.Trailer{Key: TrailerSession, Value: v})
	}
	if v := oneLine(info.Tool); v != "" {
		m.Trailers = append(m.Trailers, store.Trailer{Key: TrailerTool, Value: v})
	}
	m.Trailers = append(m.Trailers, extra...)
	return m
}

// mechanicalSubject is `<verb> <path>` for one target, `<verb> N files in
// <dir>` when they share a directory, else `<verb> N files`.
func mechanicalSubject(verbs map[string]bool, paths []string) string {
	verb := "update"
	if len(verbs) == 1 {
		for v := range verbs {
			if v != "" {
				verb = v
			}
		}
	}
	switch len(paths) {
	case 0:
		return verb + " nothing"
	case 1:
		return verb + " " + paths[0]
	}
	dir := commonDir(paths)
	if dir == "" {
		return fmt.Sprintf("%s %d files", verb, len(paths))
	}
	return fmt.Sprintf("%s %d files in %s", verb, len(paths), dir)
}

// commonDir is the deepest directory every path is under, or "".
func commonDir(paths []string) string {
	dir := paths[0]
	i := strings.LastIndexByte(dir, '/')
	if i < 0 {
		return ""
	}
	dir = dir[:i]
	for _, p := range paths[1:] {
		for dir != "" && !strings.HasPrefix(p, dir+"/") {
			if i := strings.LastIndexByte(dir, '/'); i >= 0 {
				dir = dir[:i]
			} else {
				dir = ""
			}
		}
	}
	return dir
}

// oneLine keeps a trailer value on one line and bounded.
func oneLine(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// verbOf names what a change does to a target: a deletion removes it, a
// target this machine has never written is added, anything else updates.
func verbOf(st *apply.State, t model.Target, ch store.Change) string {
	switch {
	case ch.Delete:
		return "remove"
	case st != nil && isNew(st, t):
		return "add"
	}
	return "update"
}

// itemsOf pairs targets with their verbs.
func itemsOf(st *apply.State, targets []model.Target, changes []store.Change) []MessageItem {
	out := make([]MessageItem, len(targets))
	for i, t := range targets {
		var ch store.Change
		if i < len(changes) {
			ch = changes[i]
		}
		out[i] = MessageItem{Target: t, Verb: verbOf(st, t, ch)}
	}
	return out
}
