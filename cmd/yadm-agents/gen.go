package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// GenOptions control one gen run.
type GenOptions struct {
	Home      string          // where the harness files live
	As        string          // render for another fleet machine; implies DryRun
	DryRun    bool            // never write
	Only      map[string]bool // harnesses to consider; empty means all
	Prune     bool            // drop live handlers no unit produces
	AllowDrop bool            // drop a required unit's live handlers
	State     string          // state file; "" is <Home>/.local/state/yadm-agents/state.json
}

// Status of one harness after gen.
const (
	StatusUnchanged = "unchanged"
	StatusChange    = "would change"
	StatusWritten   = "written"
	StatusSkipped   = "skipped"
	StatusRefused   = "refused"
)

// HarnessResult reports one harness.
type HarnessResult struct {
	Harness  string              `json:"harness"`
	Target   string              `json:"target,omitempty"`
	Status   string              `json:"status"`
	Reason   string              `json:"reason,omitempty"`
	Units    []string            `json:"units"`
	Added    []string            `json:"added,omitempty"`
	Removed  []string            `json:"removed,omitempty"`
	Foreign  []string            `json:"foreign,omitempty"`
	Lacks    map[string][]string `json:"lacks,omitempty"` // unit -> actions this harness has no tool for
	Warnings []string            `json:"warnings,omitempty"`
	Rendered []byte              `json:"-"`

	next      *HarnessState // the state to record; nil keeps the old record
	dropState bool          // the harness has no file here: forget its record
}

// truster is an adapter that owns per-project trust entries.
type truster interface {
	TrustKey(abs string) string
}

// Gen plans, checks and (unless dry) writes each harness's wiring.
func Gen(f *File, ev Evaluator, o GenOptions) ([]HarnessResult, error) {
	if o.As != "" {
		o.DryRun = true
	}
	if o.State == "" {
		o.State = statePath(o.Home)
	}
	st := loadState(o.State)
	var out []HarnessResult
	for _, h := range f.Harnesses() {
		if len(o.Only) > 0 && !o.Only[h] {
			continue
		}
		a, ok := adapterFor(h)
		if !ok {
			out = append(out, HarnessResult{Harness: h, Status: StatusSkipped, Reason: "no adapter for this harness"})
			continue
		}
		out = append(out, genOne(f, ev, a, o, st.Harness[h]))
	}
	if o.DryRun {
		return out, nil
	}
	// Record state after the harness files: a crash in between leaves an
	// entry gen wrote unowned (never removed), never a foreign one owned.
	for _, r := range out {
		switch {
		case r.next != nil:
			st.Harness[r.Harness] = *r.next
		case r.dropState:
			delete(st.Harness, r.Harness)
		}
	}
	st.Failed = ""
	if err := writeState(o.State, st); err != nil {
		return out, fmt.Errorf("state %s: %w", o.State, err)
	}
	return out, nil
}

// trustPaths expands trusted_projects against home. Each must name a
// directory strictly inside home.
func trustPaths(list []string, home string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, p := range list {
		var abs string
		switch {
		case strings.HasPrefix(p, "~/"):
			abs = filepath.Join(home, p[2:])
		case strings.HasPrefix(p, "$HOME/"):
			abs = filepath.Join(home, p[6:])
		case filepath.IsAbs(p):
			abs = filepath.Clean(p)
		default:
			return nil, fmt.Errorf("trusted_projects: %q is relative", p)
		}
		rel, err := filepath.Rel(home, abs)
		if err != nil || rel == "." || !filepath.IsLocal(rel) {
			return nil, fmt.Errorf("trusted_projects: %q is not inside home", p)
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out, nil
}

// planTrust sets the trust entries gen owns. A listed path with no entry
// gets one, and gen owns it. A listed path already trusted keeps its owner.
// A path with any other level was set by hand (Codex writes "untrusted"
// when the owner declines), so gen leaves it and stops owning it; kept
// lists those. A path gen owned that left the list loses its entry, but
// only while it still says "trusted".
func planTrust(tr truster, cur Wiring, vals map[string]string, want, prevOwned []string) (_ map[string]string, owned, kept []string) {
	if vals == nil {
		vals = map[string]string{}
	}
	listed, prev := setOf(want...), setOf(prevOwned...)
	for _, p := range want {
		k := tr.TrustKey(p)
		switch cur.Values[k] {
		case "":
			owned = append(owned, p)
			vals[k] = trustedLevel
		case trustedLevel:
			if prev[p] {
				owned = append(owned, p)
			}
			vals[k] = trustedLevel
		default:
			kept = append(kept, p)
		}
	}
	for _, p := range prevOwned {
		if k := tr.TrustKey(p); !listed[p] && cur.Values[k] == trustedLevel {
			vals[k] = "" // gen wrote it; take it back
		}
	}
	return vals, owned, kept
}

// resolveFor lists every unit with a cell for harness h, resolved, with
// Enabled set for the machine (machine "" is this one).
func resolveFor(f *File, ev Evaluator, h, machine string) ([]Resolved, error) {
	var out []Resolved
	for _, u := range f.Units {
		on, has, err := cellOn(f, ev, u.Name, h, machine)
		if err != nil {
			return nil, err
		}
		if !has {
			continue
		}
		r := u.Resolve(h)
		r.Enabled = on
		out = append(out, r)
	}
	return out, nil
}

func genOne(f *File, ev Evaluator, a Adapter, o GenOptions, prev HarnessState) HarnessResult {
	h := a.Name()
	res := HarnessResult{Harness: h, Units: []string{}}
	// planned is the record once gen knows the plan. A refusal records the
	// plan (or, before there is one, the previous record) with the reason,
	// so the tripwire reports it; it keeps the trust gen owned before.
	var planned *HarnessState
	refuse := func(format string, args ...any) HarnessResult {
		res.Status = StatusRefused
		res.Reason = fmt.Sprintf(format, args...)
		if o.As == "" {
			p := prev
			if planned != nil {
				p = *planned
				p.Trusted = prev.Trusted
			}
			p.Refused = res.Reason
			res.next = &p
		}
		return res
	}
	units, err := resolveFor(f, ev, h, o.As)
	if err != nil {
		return refuse("%v", err)
	}
	// gen runs as a task after apply, so a script apply has not written
	// here is not on this machine yet: wiring it would land the handler
	// first. A required unit refuses; any other unit waits for a later gen.
	ready := func(script string) (string, error) {
		if o.As == "" {
			return scriptProblem(filepath.Join(o.Home, homeRel(script))), nil
		}
		d, ok := ev.(deliverer)
		if !ok {
			return "", nil
		}
		s, err := d.Delivered(o.As)
		if err != nil {
			return "", err
		}
		if !s[filepath.ToSlash(homeRel(script))] {
			return "is not delivered to " + o.As, nil
		}
		return "", nil
	}
	for i, u := range units {
		if !u.Enabled || u.Via != "" || !a.Wires(u.Kind) || u.Kind == "mod" || u.Run != "" || u.Script == "" {
			continue
		}
		why, err := ready(u.Script)
		if err != nil {
			return refuse("%v", err)
		}
		switch {
		case why == "":
		case u.Required:
			return refuse("required unit %q: script %s %s", u.Unit, u.Script, why)
		default:
			units[i].Enabled = false
			res.Warnings = append(res.Warnings, fmt.Sprintf("unit %q not wired: script %s %s", u.Unit, u.Script, why))
		}
	}
	for _, u := range wiredUnits(a, units) {
		res.Units = append(res.Units, u.Unit)
		if err := checkWired(a, u); err != nil {
			return refuse("%v", err)
		}
		if l := a.Unmapped(u.Actions); len(l) > 0 {
			if res.Lacks == nil {
				res.Lacks = map[string][]string{}
			}
			res.Lacks[u.Unit] = l
		}
	}
	rendered, err := a.Render(units)
	if err != nil {
		return refuse("%v", err)
	}
	for _, u := range wiredUnits(a, units) {
		if u.Required && u.Kind != "mod" && !hasUnit(rendered, u.Unit) {
			return refuse("required unit %q renders no handler on %s: no event or tool it names exists there", u.Unit, h)
		}
	}

	var want []string
	tr, trusts := a.(truster)
	switch {
	case trusts:
		if want, err = trustPaths(f.Harness[h].Trust, o.Home); err != nil {
			return refuse("[harness.%s] %v", h, err)
		}
	case len(f.Harness[h].Trust) > 0:
		return refuse("[harness.%s] trusted_projects: %s has no project trust", h, h)
	}

	rel := a.DefaultConfig()
	if c := f.Harness[h].Config; c != "" {
		rel = homeRel(c)
	}
	if rel == "" {
		res.Status = StatusSkipped
		res.Reason = fmt.Sprintf("no target: set [harness.%s] config in the units file", h)
		return res
	}
	if !filepath.IsLocal(rel) {
		return refuse("config %q: the file must be inside home", rel)
	}
	path := filepath.Join(o.Home, rel)
	res.Target = path
	planned = &HarnessState{Target: filepath.ToSlash(rel), Required: expected(units, rendered)}
	live, err := os.ReadFile(path)
	missing := errors.Is(err, fs.ErrNotExist)
	if o.As != "" && !missing {
		// This machine's file stands in for the other machine's only when
		// the manifest gives that machine the file too.
		if d, ok := ev.(deliverer); ok {
			s, derr := d.Delivered(o.As)
			if derr != nil {
				return refuse("%v", derr)
			}
			if !s[filepath.ToSlash(rel)] {
				live, err, missing = nil, fs.ErrNotExist, true
				res.Reason = fmt.Sprintf("the manifest does not give %s this file", o.As)
			}
		}
	}
	switch {
	case err != nil && !missing:
		return refuse("read %s: %v", path, err)
	case missing && !a.Create():
		res.dropState = o.As == ""
		res.Status = StatusSkipped
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("%s does not exist; gen never creates it", path)
		}
		return res
	case missing && len(rendered.Entries) == 0:
		res.dropState = o.As == ""
		res.Status = StatusSkipped
		res.Reason = "nothing to wire"
		return res
	}
	var cur Wiring
	if !missing {
		if cur, err = a.Load(live); err != nil {
			return refuse("parse %s: %v", path, err)
		}
	}
	if or, ok := a.(orderer); ok {
		rendered = or.Order(cur, rendered)
	}
	var owned []string
	if trusts {
		var kept []string
		rendered.Values, owned, kept = planTrust(tr, cur, rendered.Values, want, prev.Trusted)
		if len(kept) > 0 {
			res.Reason = fmt.Sprintf("trusted_projects: kept the trust level set by hand for %s", strings.Join(kept, ", "))
		}
	}
	// A live owned value the units file does not render (a mod list with
	// no mod unit for this harness) stays as it is.
	for k, v := range cur.Values {
		if _, ok := rendered.Values[k]; !ok {
			if rendered.Values == nil {
				rendered.Values = map[string]string{}
			}
			rendered.Values[k] = v
		}
	}
	res.Added, res.Removed = diffRows(a.Rows(cur), a.Rows(rendered))

	// Safety: never empty, never drop what no unit owns, never drop a
	// required unit's handlers without being told to.
	if len(rendered.Entries) == 0 && len(cur.Entries) > 0 {
		return refuse("the result would hold no handler; %s keeps its %d", path, len(cur.Entries))
	}
	known, required, err := commandsOf(f, a, h)
	if err != nil {
		return refuse("%v", err)
	}
	// A required unit's live handler counts per event, tool and command,
	// so a guard that keeps its command but loses a tool or an event is a
	// drop too.
	covered := map[string]bool{}
	for _, e := range rendered.Entries {
		for _, k := range coverKeys(e) {
			covered[k] = true
		}
	}
	foreign := map[string]bool{}
	var dropped []string
	for _, e := range cur.Entries {
		c := canonCommand(e.Command)
		switch {
		case required[c] != "":
			if !coveredBy(covered, e) {
				dropped = append(dropped, required[c])
			}
		case !known[c]:
			foreign[e.Command] = true
		}
	}
	res.Foreign = sortedKeys(foreign)
	if len(res.Foreign) > 0 && !o.Prune {
		return refuse("%d live handler(s) match no unit; add units for them or pass --prune", len(res.Foreign))
	}
	if len(dropped) > 0 && !o.AllowDrop {
		sort.Strings(dropped)
		return refuse("this would remove required unit(s) %s; pass --allow-drop if that is intended", strings.Join(uniq(dropped), ", "))
	}

	record := &HarnessState{Target: planned.Target, Required: planned.Required, Trusted: owned}
	if len(res.Added) == 0 && len(res.Removed) == 0 {
		res.Status = StatusUnchanged
		res.next = record
		return res
	}
	next, err := a.Apply(live, rendered, cur)
	if err != nil {
		return refuse("render %s: %v", path, err)
	}
	if err := proveEdit(a, live, next, rendered); err != nil {
		return refuse("%s: %v; nothing written", path, err)
	}
	res.Rendered = next
	if o.DryRun {
		res.Status = StatusChange
		return res
	}
	// The harness may rewrite its file while gen runs; never overwrite a
	// change gen did not see.
	if again, err := os.ReadFile(path); (err == nil || !missing) && !bytes.Equal(again, live) {
		return refuse("%s changed while gen ran; run it again", path)
	}
	if err := writeAtomic(path, next); err != nil {
		return refuse("write %s: %v", path, err)
	}
	res.Status = StatusWritten
	res.next = record
	return res
}

func checkWired(a Adapter, u Resolved) error {
	if u.Kind == "mod" {
		return nil
	}
	for _, ev := range u.On {
		if !a.Events()[ev] {
			return fmt.Errorf("unit %q: %s has no %s event", u.Unit, a.Name(), ev)
		}
	}
	if !a.Effects()[u.Effect] {
		return fmt.Errorf("unit %q: %s cannot %s", u.Unit, a.Name(), u.Effect)
	}
	return nil
}

// coverKeys lists what one handler covers: event, tool and command (by
// canonCommand, so the guarded and plain forms match), one key per matcher
// alternative. A server list `mcp__(a|b)__.*` counts per
// server, so adding a server is not a drop.
func coverKeys(e Entry) []string {
	var out []string
	cmd := canonCommand(e.Command)
	for _, t := range matcherTokens(e.Matcher) {
		if m := serverList.FindStringSubmatch(t); m != nil {
			for _, s := range strings.Split(m[1], "|") {
				out = append(out, e.Event+"\t"+"mcp__"+s+"__.*"+"\t"+cmd)
			}
			continue
		}
		out = append(out, e.Event+"\t"+t+"\t"+cmd)
	}
	return out
}

var serverList = regexp.MustCompile(`^mcp__\(([A-Za-z0-9_|-]+)\)__\.\*$`)

// coveredBy reports whether the planned wiring still covers everything the
// live handler e covers. A planned handler for every tool on the event
// covers any tool, and one for every MCP tool covers any one server.
func coveredBy(covered map[string]bool, e Entry) bool {
	pre := e.Event + "\t"
	post := "\t" + canonCommand(e.Command)
	if covered[pre+"*"+post] {
		return true
	}
	allMCP := covered[pre+"mcp__.*"+post] || covered[pre+"mcp__*"+post]
	for _, k := range coverKeys(e) {
		tool := strings.TrimSuffix(strings.TrimPrefix(k, pre), post)
		if !covered[k] && !(allMCP && strings.HasPrefix(tool, "mcp__")) {
			return false
		}
	}
	return true
}

func hasUnit(w Wiring, unit string) bool {
	for _, e := range w.Entries {
		if e.Unit == unit {
			return true
		}
	}
	return false
}

// commandsOf renders every unit with a cell for h as if it were on, so gen
// knows which live commands are its own and which belong to required units.
// Keys are canonCommand names, so a plain live form is the unit's too.
// A required unit with no cell for h still claims its commands: removing
// its cell drops it, which needs --allow-drop, never --prune.
func commandsOf(f *File, a Adapter, h string) (known map[string]bool, required map[string]string, err error) {
	known, required = map[string]bool{}, map[string]string{}
	for _, u := range f.Units {
		_, has := f.Cell(u.Name, h)
		if !has && !u.Required {
			continue
		}
		r := u.Resolve(h)
		r.Enabled = true
		w, err := a.Render([]Resolved{r})
		if err != nil {
			if !has {
				continue // the unit was never meant for this harness
			}
			return nil, nil, err
		}
		for _, e := range w.Entries {
			c := canonCommand(e.Command)
			known[c] = true
			if u.Required {
				required[c] = u.Name
			}
		}
	}
	return known, required, nil
}

// proveEdit re-reads the new bytes: the owned wiring must be exactly what
// was rendered and every other key exactly what it was.
func proveEdit(a Adapter, before, after []byte, want Wiring) error {
	got, err := a.Load(after)
	if err != nil {
		return fmt.Errorf("result does not parse: %v", err)
	}
	if !reflect.DeepEqual(a.Rows(got), a.Rows(want)) {
		add, rm := diffRows(a.Rows(want), a.Rows(got))
		return fmt.Errorf("result wiring differs from the plan (+%d -%d)", len(add), len(rm))
	}
	if before == nil {
		return nil
	}
	x, err := a.Unowned(before)
	if err != nil {
		return err
	}
	y, err := a.Unowned(after)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(x, y) {
		return errors.New("the edit changed keys outside the owned ones")
	}
	return nil
}

// diffRows returns the rows only in b (added) and only in a (removed), as
// multisets.
func diffRows(a, b []string) (added, removed []string) {
	count := map[string]int{}
	for _, r := range a {
		count[r]++
	}
	for _, r := range b {
		if count[r] > 0 {
			count[r]--
		} else {
			added = append(added, r)
		}
	}
	for _, r := range a {
		if count[r] > 0 {
			count[r]--
			removed = append(removed, r)
		}
	}
	return added, removed
}

// writeAtomic replaces path with b through a temp file in the same
// directory, keeping the file's mode. A symlink stays a symlink: gen writes
// the file it points to.
func writeAtomic(path string, b []byte) error {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".yadm-agents-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// scriptProblem says why the guarded form would skip the script at path,
// or "" when it is an executable file.
func scriptProblem(path string) string {
	st, err := os.Stat(path)
	switch {
	case err != nil:
		return "is missing here"
	case !st.Mode().IsRegular():
		return "is not a file"
	case st.Mode().Perm()&0o111 == 0:
		return "is not executable"
	}
	return ""
}

func homeRel(p string) string {
	p = strings.TrimPrefix(p, "~/")
	p = strings.TrimPrefix(p, "$HOME/")
	return p
}

func uniq(xs []string) []string {
	var out []string
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// formatResults prints one block per harness.
func formatResults(rs []HarnessResult, diff bool) string {
	var b bytes.Buffer
	for _, r := range rs {
		fmt.Fprintf(&b, "%s: %s", r.Harness, r.Status)
		if r.Target != "" {
			fmt.Fprintf(&b, " %s", r.Target)
		}
		if len(r.Added)+len(r.Removed) > 0 {
			fmt.Fprintf(&b, " (+%d -%d)", len(r.Added), len(r.Removed))
		}
		b.WriteString("\n")
		if r.Reason != "" {
			fmt.Fprintf(&b, "  %s\n", r.Reason)
		}
		for _, c := range r.Foreign {
			fmt.Fprintf(&b, "  foreign: %s\n", c)
		}
		for _, w := range r.Warnings {
			fmt.Fprintf(&b, "  warning: %s\n", w)
		}
		for _, u := range sortedKeys(r.Lacks) {
			fmt.Fprintf(&b, "  lacks: %s has no tool for %s\n", u, strings.Join(r.Lacks[u], ", "))
		}
		if diff {
			for _, x := range r.Removed {
				fmt.Fprintf(&b, "  - %s\n", x)
			}
			for _, x := range r.Added {
				fmt.Fprintf(&b, "  + %s\n", x)
			}
		}
	}
	return b.String()
}
