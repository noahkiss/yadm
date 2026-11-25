package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Finding is one verify result.
type Finding struct {
	Level string `json:"level"` // error | warn
	Msg   string `json:"msg"`
}

// VerifyOptions control verify.
type VerifyOptions struct {
	Home    string
	Offline bool              // skip evaluating cells through yadm
	Staged  map[string]string // check mode: home-relative target -> staged temp file
}

// Verify is the commit check (fail closed): the file parses, every cell
// names a real unit, every wired cell asks only for events and effects its
// harness has, required units have their check script, and every cell
// evaluates. Unknown harnesses and kinds are warnings, never errors.
func Verify(f *File, ev Evaluator, o VerifyOptions) []Finding {
	var out []Finding
	errf := func(format string, a ...any) { out = append(out, Finding{"error", fmt.Sprintf(format, a...)}) }
	warnf := func(format string, a ...any) { out = append(out, Finding{"warn", fmt.Sprintf(format, a...)}) }

	for _, name := range sortedKeys(f.Conditions) {
		u, h, ok := splitCell(name)
		if !ok {
			continue
		}
		_, known := adapterFor(h)
		if f.Unit(u) == nil {
			if known {
				errf("cell %s names unit %q, which the file does not define", name, u)
			}
			continue
		}
		if !known {
			warnf("cell %s: no adapter for harness %q; it shows in the matrix but gen writes nothing", name, h)
		}
	}

	for _, h := range sortedKeys(f.Harness) {
		if len(f.Harness[h].Trust) == 0 {
			continue
		}
		a, ok := adapterFor(h)
		if _, trusts := a.(truster); ok && !trusts {
			errf("[harness.%s] trusted_projects: %s has no project trust", h, h)
		} else if _, err := trustPaths(f.Harness[h].Trust, o.Home); err != nil {
			errf("[harness.%s] %v", h, err)
		}
	}

	for _, u := range f.Units {
		if deref(u.Kind) == "" {
			errf("unit %q: kind is empty", u.Name)
		}
		cells := 0
		for h := range u.Over {
			if _, has := f.Cell(u.Name, h); !has {
				warnf("unit %q: [unit.harness.%s] overrides a harness with no cell", u.Name, h)
			}
		}
		for _, h := range f.Harnesses() {
			if _, has := f.Cell(u.Name, h); !has {
				continue
			}
			cells++
			a, ok := adapterFor(h)
			if !ok {
				continue
			}
			r := u.Resolve(h)
			if r.Via != "" {
				v := f.Unit(r.Via)
				switch {
				case v == nil:
					errf("unit %q on %s: via names unit %q, which the file does not define", u.Name, h, r.Via)
				default:
					if _, has := f.Cell(r.Via, h); !has {
						warnf("unit %q on %s: via unit %q has no %s cell", u.Name, h, r.Via, h)
					}
				}
				continue
			}
			if !a.Wires(r.Kind) {
				if r.File == "" && r.Dir == "" {
					warnf("unit %q on %s: %s does not wire kind %q and the unit names no file or dir", u.Name, h, h, r.Kind)
				}
				continue
			}
			if err := checkWired(a, r); err != nil {
				errf("%v", err)
			}
			if r.Kind == "mod" {
				if r.Dir == "" {
					errf("unit %q: a mod needs dir", u.Name)
				}
				continue
			}
			if r.Command("", true) == "" {
				errf("unit %q on %s: no script or run", u.Name, h)
			}
			if len(r.On) == 0 {
				errf("unit %q on %s: on lists no event", u.Name, h)
			}
			if l := a.Unmapped(r.Actions); len(l) > 0 && r.Note == "" {
				warnf("unit %q on %s: no tool for %s; add a note saying why that is fine", u.Name, h, strings.Join(l, ", "))
			}
			if _, isRoute := a.(routeAdapter); isRoute && r.Script == "" {
				errf("unit %q on %s: a routed guard needs script", u.Name, h)
			} else {
				on := r
				on.Enabled = true
				if _, err := a.Render([]Resolved{on}); err != nil {
					errf("%s: %v", h, err)
				}
			}
		}
		if cells == 0 {
			warnf("unit %q has no cell; it is on nowhere", u.Name)
		}
		if u.Required {
			s := deref(u.Script)
			if s == "" {
				errf("unit %q is required but names no script", u.Name)
			} else if !scriptPresent(o, s) {
				errf("required unit %q: script %s does not exist", u.Name, s)
			}
		}
	}

	for _, h := range f.Harnesses() {
		if a, ok := adapterFor(h); ok {
			for _, m := range firstNotLeading(f, a, h) {
				warnf("%s", m)
			}
		}
	}

	for _, name := range sortedKeys(f.Conditions) {
		x, err := expandLocal(f.Conditions[name], f.Conditions)
		if err != nil {
			errf("condition %s: %v", name, err)
			continue
		}
		if o.Offline || ev == nil {
			continue
		}
		if _, err := ev.Eval(x, ""); err != nil {
			errf("condition %s: %v", name, err)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Level < out[j].Level })
	return out
}

func scriptPresent(o VerifyOptions, s string) bool {
	rel := homeRel(s)
	if _, ok := o.Staged[rel]; ok {
		return true
	}
	_, err := os.Stat(filepath.Join(o.Home, rel))
	return err == nil
}

func hasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Level == "error" {
			return true
		}
	}
	return false
}

// firstNotLeading renders every unit with a cell for an ordered (route)
// harness as if all were on, and reports each list a unit marked first does
// not lead. Only two first units on one list can cause it.
func firstNotLeading(f *File, a Adapter, h string) []string {
	if _, ordered := a.(routeAdapter); !ordered {
		return nil
	}
	var units []Resolved
	for _, u := range f.Units {
		if _, has := f.Cell(u.Name, h); has {
			r := u.Resolve(h)
			r.Enabled = true
			units = append(units, r)
		}
	}
	w, err := a.Render(units)
	if err != nil {
		return nil // the per-unit checks above report it
	}
	lead := map[string]string{}
	var out []string
	for _, e := range w.Entries {
		k := e.Event + " " + e.Matcher
		if _, ok := lead[k]; !ok {
			lead[k] = e.Unit
			continue
		}
		if u := f.Unit(e.Unit); u != nil && u.First {
			out = append(out, fmt.Sprintf("unit %q is marked first but %q leads %s %s; only one first unit can lead a list", e.Unit, lead[k], h, k))
		}
	}
	return out
}
