package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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
	Rendered []byte              `json:"-"`
}

// Gen plans, checks and (unless dry) writes each harness's wiring.
func Gen(f *File, ev Evaluator, o GenOptions) ([]HarnessResult, error) {
	if o.As != "" {
		o.DryRun = true
	}
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
		out = append(out, genOne(f, ev, a, o))
	}
	return out, nil
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

func genOne(f *File, ev Evaluator, a Adapter, o GenOptions) HarnessResult {
	h := a.Name()
	res := HarnessResult{Harness: h, Units: []string{}}
	refuse := func(format string, args ...any) HarnessResult {
		res.Status = StatusRefused
		res.Reason = fmt.Sprintf(format, args...)
		return res
	}
	units, err := resolveFor(f, ev, h, o.As)
	if err != nil {
		return refuse("%v", err)
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
		if o.As == "" && u.Required && u.Script != "" {
			if _, err := os.Stat(filepath.Join(o.Home, homeRel(u.Script))); err != nil {
				return refuse("required unit %q: script %s is missing here", u.Unit, u.Script)
			}
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

	rel := a.DefaultConfig()
	if c := f.Harness[h].Config; c != "" {
		rel = homeRel(c)
	}
	if rel == "" {
		res.Status = StatusSkipped
		res.Reason = fmt.Sprintf("no target: set [harness.%s] config in the units file", h)
		return res
	}
	path := filepath.Join(o.Home, rel)
	res.Target = path
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
		res.Status = StatusSkipped
		if res.Reason == "" {
			res.Reason = fmt.Sprintf("%s does not exist; gen never creates it", path)
		}
		return res
	case missing && len(rendered.Entries) == 0:
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
	have := map[string]bool{}
	for _, e := range rendered.Entries {
		have[e.Command] = true
	}
	foreign := map[string]bool{}
	var dropped []string
	for _, e := range cur.Entries {
		switch {
		case !known[e.Command]:
			foreign[e.Command] = true
		case required[e.Command] != "" && !have[e.Command]:
			dropped = append(dropped, required[e.Command])
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

	if len(res.Added) == 0 && len(res.Removed) == 0 {
		res.Status = StatusUnchanged
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
func commandsOf(f *File, a Adapter, h string) (known map[string]bool, required map[string]string, err error) {
	known, required = map[string]bool{}, map[string]string{}
	for _, u := range f.Units {
		if _, has := f.Cell(u.Name, h); !has {
			continue
		}
		r := u.Resolve(h)
		r.Enabled = true
		w, err := a.Render([]Resolved{r})
		if err != nil {
			return nil, nil, err
		}
		for _, e := range w.Entries {
			known[e.Command] = true
			if u.Required {
				required[e.Command] = u.Name
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
// directory, keeping the file's mode.
func writeAtomic(path string, b []byte) error {
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
