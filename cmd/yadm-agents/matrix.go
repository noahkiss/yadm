package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

// deliverer is an Evaluator that also knows which targets the manifest
// gives each machine, so the matrix can compare a file unit's cell with
// what yadm delivers.
type deliverer interface {
	Delivered(machine string) (map[string]bool, error)
}

// Matrix is the unit × harness × machine view.
type Matrix struct {
	Schema   int          `json:"schema"`
	This     string       `json:"this"`
	Machines []string     `json:"machines"`
	Units    []MatrixUnit `json:"units"`
}

// MatrixUnit is one unit row.
type MatrixUnit struct {
	Name     string                `json:"name"`
	Kind     string                `json:"kind"`
	Required bool                  `json:"required,omitempty"`
	Cells    map[string]MatrixCell `json:"cells"`
}

// MatrixCell is one unit × harness cell.
type MatrixCell struct {
	When      string          `json:"when"`
	Via       string          `json:"via,omitempty"`
	Note      string          `json:"note,omitempty"`
	Tokens    []string        `json:"tokens,omitempty"`
	Lacks     []string        `json:"lacks,omitempty"`
	On        map[string]bool `json:"on"`
	Delivered map[string]bool `json:"delivered,omitempty"` // file units: does the manifest give the machine the file
	Error     string          `json:"error,omitempty"`
}

// BuildMatrix evaluates every cell on every machine.
func BuildMatrix(f *File, ev Evaluator, machines []string) (Matrix, error) {
	this, err := ev.This()
	if err != nil {
		return Matrix{}, err
	}
	if len(machines) == 0 {
		if machines, err = ev.Machines(); err != nil {
			return Matrix{}, err
		}
	}
	m := Matrix{Schema: 1, This: this, Machines: machines}
	del := map[string]map[string]bool{}
	if d, ok := ev.(deliverer); ok {
		for _, mc := range machines {
			if s, err := d.Delivered(mc); err == nil {
				del[mc] = s
			}
		}
	}
	for _, u := range f.Units {
		row := MatrixUnit{Name: u.Name, Kind: deref(u.Kind), Required: u.Required, Cells: map[string]MatrixCell{}}
		for _, h := range f.Harnesses() {
			when, has := f.Cell(u.Name, h)
			if !has {
				continue
			}
			r := u.Resolve(h)
			c := MatrixCell{When: when, Via: r.Via, Note: r.Note, On: map[string]bool{}}
			if a, ok := adapterFor(h); ok && r.Via == "" && a.Wires(r.Kind) && r.Kind != "mod" {
				c.Tokens = tokens(a, r)
				c.Lacks = a.Unmapped(r.Actions)
			}
			target := homeRel(r.File)
			if target == "" {
				target = homeRel(r.Dir)
			}
			for _, mc := range machines {
				who := mc
				if mc == this {
					who = ""
				}
				on, _, err := cellOn(f, ev, u.Name, h, who)
				if err != nil {
					c.Error = err.Error()
					continue
				}
				c.On[mc] = on
				if s, ok := del[mc]; ok && target != "" {
					if c.Delivered == nil {
						c.Delivered = map[string]bool{}
					}
					c.Delivered[mc] = deliveredUnder(s, target)
				}
			}
			row.Cells[h] = c
		}
		m.Units = append(m.Units, row)
	}
	return m, nil
}

func deliveredUnder(s map[string]bool, target string) bool {
	if s[target] {
		return true
	}
	p := strings.TrimSuffix(target, "/") + "/"
	for t := range s {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// tokens names what a wired unit covers, in the vocabulary of a parity
// report: shell, file-read, file-write, web, agent, mcp:<server>, mcp:*,
// and events for a unit on no tool event.
func tokens(a Adapter, r Resolved) []string {
	set := map[string]bool{}
	unmapped := setOf(a.Unmapped(r.Actions)...)
	toolEvent := false
	for _, ev := range r.On {
		if a.ToolEvents()[ev] {
			toolEvent = true
		} else {
			set["events"] = true
		}
	}
	if toolEvent {
		if len(r.Actions) == 0 {
			set["all"] = true
		}
		for _, act := range r.Actions {
			if unmapped[act] {
				continue
			}
			base, server, _ := strings.Cut(act, ":")
			switch base {
			case "shell":
				set["shell"] = true
			case "file_read":
				set["file-read"] = true
			case "file_write", "file_edit":
				set["file-write"] = true
			case "web_fetch", "web_search":
				set["web"] = true
			case "agent_spawn":
				set["agent"] = true
			case "mcp_call":
				if server == "" {
					server = "*"
				}
				set["mcp:"+server] = true
			}
		}
	}
	return sortedKeys(set)
}

// Table renders the matrix for a terminal: one line per unit × harness,
// one column per machine. x = on, . = off, ! = on/off disagrees with the
// files the manifest delivers.
func (m Matrix) Table() string {
	var b bytes.Buffer
	tw := tabwriter.NewWriter(&b, 0, 2, 2, ' ', 0)
	fmt.Fprintf(tw, "UNIT\tHARNESS\tKIND\t%s\tWHEN\n", strings.Join(m.Machines, "\t"))
	for _, u := range m.Units {
		for _, h := range sortedKeys(u.Cells) {
			c := u.Cells[h]
			var cols []string
			for _, mc := range m.Machines {
				mark := "."
				if c.On[mc] {
					mark = "x"
				}
				if d, ok := c.Delivered[mc]; ok && d != c.On[mc] {
					mark = "!"
				}
				cols = append(cols, mark)
			}
			when := c.When
			if c.Via != "" {
				when += " (via " + c.Via + ")"
			}
			if c.Error != "" {
				when += " ERROR: " + c.Error
			}
			name := u.Name
			if u.Required {
				name += "*"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, h, u.Kind, strings.Join(cols, "\t"), when)
		}
	}
	tw.Flush()
	b.WriteString("x on, . off, ! cell and manifest delivery disagree, * required\n")
	return b.String()
}

// Parity renders one line per check script for this machine:
// `<script> <harness>[tokens] ...`, the shape of a parity report.
func (m Matrix) Parity(f *File) string {
	lines := map[string]map[string]map[string]bool{} // script -> harness -> tokens
	for _, u := range f.Units {
		row := m.unit(u.Name)
		for h, c := range row.Cells {
			if !c.On[m.This] {
				continue
			}
			r := u.Resolve(h)
			s := r.ScriptName()
			if s == "" {
				continue
			}
			if lines[s] == nil {
				lines[s] = map[string]map[string]bool{}
			}
			if lines[s][h] == nil {
				lines[s][h] = map[string]bool{}
			}
			toks := c.Tokens
			if c.Via != "" {
				toks = []string{"via"}
			}
			for _, t := range toks {
				lines[s][h][t] = true
			}
		}
	}
	var b strings.Builder
	for _, s := range sortedKeys(lines) {
		b.WriteString(s)
		for _, h := range sortedKeys(lines[s]) {
			fmt.Fprintf(&b, " %s[%s]", h, strings.Join(sortedKeys(lines[s][h]), ","))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m Matrix) unit(name string) MatrixUnit {
	for _, u := range m.Units {
		if u.Name == name {
			return u
		}
	}
	return MatrixUnit{}
}

// JSON renders the matrix.
func (m Matrix) JSON() ([]byte, error) {
	sort.Strings(m.Machines)
	return json.MarshalIndent(m, "", "  ")
}
