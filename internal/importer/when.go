package importer

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// checkExclusive checks the generated manifest against the generated fleet:
// every condition names only declared types and facts, and no fleet machine
// gets two entries for one target. The manifest has no precedence, so any
// overlap would be a collision on that machine.
func checkExclusive(man []byte, fl *fleet.File) []Problem {
	m, err := manifest.Parse(man)
	if err != nil {
		return []Problem{{Path: manifest.FileName, Reason: err.Error()}}
	}
	voc := fl.Vocabulary()
	if err := m.Validate(voc); err != nil {
		return []Problem{{Path: manifest.FileName, Reason: err.Error()}}
	}
	var ms []model.Machine
	for _, mc := range fl.Machines {
		ms = append(ms, mc)
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].Name < ms[j].Name })
	var out []Problem
	for _, mc := range ms {
		_, err := m.Resolve(model.Context{Machine: mc}, nil, voc)
		var ce *manifest.CollisionError
		switch {
		case errors.As(err, &ce):
			for _, c := range ce.Collisions {
				out = append(out, Problem{Path: string(c.Target), Reason: fmt.Sprintf("conditions overlap on machine %s", mc.Name)})
			}
		case err != nil:
			out = append(out, Problem{Path: manifest.FileName, Reason: fmt.Sprintf("machine %s: %v", mc.Name, err)})
		}
	}
	return out
}

// atom is one positive condition term in the new condition language:
// type:X, os:X, arch:X or fact:K=V.
type atom struct {
	Kind  string // "type", "os", "arch", or "fact:<key>"
	Value string
}

func (a atom) String() string {
	if k, ok := strings.CutPrefix(a.Kind, "fact:"); ok {
		return "fact:" + k + "=" + a.Value
	}
	return a.Kind + ":" + a.Value
}

// single reports whether a machine holds at most one value of this kind, so
// two atoms of the kind with different values exclude each other. Types are
// multi-valued.
func (a atom) single() bool { return a.Kind != "type" }

// atomFor converts one alternate condition. ok is false for conditions that
// select nothing (default, template, extension).
func atomFor(c AltCond) (atom, bool) {
	switch c.Key {
	case condClass:
		return atom{"type", strings.ToLower(c.Value)}, true
	case condOS:
		return atom{"os", strings.ToLower(c.Value)}, true
	case condArch:
		return atom{"arch", strings.ToLower(c.Value)}, true
	case condHostname:
		return atom{"fact:hostname", c.Value}, true
	case condUser:
		return atom{"fact:user", c.Value}, true
	case condDistro:
		return atom{"fact:distro", c.Value}, true
	case condDistroFamily:
		return atom{"fact:distro_family", c.Value}, true
	}
	return atom{}, false
}

// conj is a conjunction of atoms, kept sorted and unique.
type conj []atom

func newConj(as ...atom) conj {
	m := map[atom]bool{}
	var out conj
	for _, a := range as {
		if !m[a] {
			m[a] = true
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func (c conj) has(a atom) bool {
	for _, x := range c {
		if x == a {
			return true
		}
	}
	return false
}

// excludes reports whether c and d can never hold on one machine.
func (c conj) excludes(d conj) bool {
	for _, a := range c {
		for _, b := range d {
			if a.single() && a.Kind == b.Kind && !strings.EqualFold(a.Value, b.Value) {
				return true
			}
		}
	}
	return false
}

// minus returns the atoms of c that d does not hold.
func (c conj) minus(d conj) conj {
	var out conj
	for _, a := range c {
		if !d.has(a) {
			out = append(out, a)
		}
	}
	return out
}

func (c conj) String() string {
	parts := make([]string, len(c))
	for i, a := range c {
		parts[i] = a.String()
	}
	return strings.Join(parts, " & ")
}

// whenExpr is a variant's condition: its own atoms, and none of the
// higher-ranked variants that could also match.
type whenExpr struct {
	Pos  conj
	Nots []conj // each non-empty
}

func (w whenExpr) String() string {
	var parts []string
	if len(w.Pos) > 0 {
		parts = append(parts, w.Pos.String())
	}
	for _, n := range w.Nots {
		if len(n) == 1 {
			parts = append(parts, "!"+n[0].String())
		} else {
			parts = append(parts, "!("+n.String()+")")
		}
	}
	return strings.Join(parts, " & ")
}

// and joins two condition strings.
func andWhen(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case a == b:
		return a
	}
	return paren(a) + " & " + paren(b)
}

func paren(s string) string {
	if strings.Contains(s, "|") {
		return "(" + s + ")"
	}
	return s
}
