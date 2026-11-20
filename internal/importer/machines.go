package importer

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

// machineRow is one line of the machines table.
type machineRow struct {
	Line     int
	Name     string
	Hostname string
	Classes  []string
	OS, Arch string
	Facts    map[string]string
}

// readMachines parses a tab-separated machines table with a header line.
// Columns name and classes are required; hostname, os and arch are optional;
// every other column becomes a declared fact. Blank lines and lines starting
// with # are skipped.
func readMachines(file string) ([]machineRow, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("machines table: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var header []string
	var rows []machineRow
	n := 0
	for sc.Scan() {
		n++
		text := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		cells := strings.Split(text, "\t")
		if header == nil {
			for _, h := range cells {
				header = append(header, strings.ToLower(strings.TrimSpace(h)))
			}
			if index(header, "name") < 0 || index(header, "classes") < 0 {
				return nil, fmt.Errorf("machines table %s: header must name the name and classes columns", file)
			}
			continue
		}
		if len(cells) > len(header) {
			return nil, fmt.Errorf("machines table %s:%d: more cells than header columns", file, n)
		}
		r := machineRow{Line: n, Facts: map[string]string{}}
		for i, h := range header {
			v := ""
			if i < len(cells) {
				v = strings.TrimSpace(cells[i])
			}
			switch h {
			case "name":
				r.Name = v
			case "hostname":
				r.Hostname = v
			case "classes":
				for _, c := range strings.Split(v, ",") {
					if c = strings.TrimSpace(c); c != "" {
						r.Classes = append(r.Classes, strings.ToLower(c))
					}
				}
			case "os":
				r.OS = strings.ToLower(v)
			case "arch":
				r.Arch = strings.ToLower(v)
			default:
				if v != "" {
					r.Facts[h] = v
				}
			}
		}
		if r.Name == "" {
			return nil, fmt.Errorf("machines table %s:%d: empty name", file, n)
		}
		if len(r.Classes) == 0 {
			return nil, fmt.Errorf("machines table %s:%d: machine %s has no classes", file, n, r.Name)
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if header == nil {
		return nil, fmt.Errorf("machines table %s is empty", file)
	}
	return rows, nil
}

func index(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

func newMachineID(used map[model.MachineID]bool) model.MachineID {
	for {
		b := make([]byte, 3)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		id := model.MachineID("m-" + hex.EncodeToString(b))
		if !used[id] {
			used[id] = true
			return id
		}
	}
}

// buildFleet builds the fleet file: a type per class and enclave, and a
// machine per table row, or one machine per class without a table.
func buildFleet(rows []machineRow, p *planner, opts Options) (*fleet.File, error) {
	f := &fleet.File{Schema: fleet.Schema, Types: map[model.TypeName]fleet.TypeDef{}, Machines: map[model.MachineID]model.Machine{}}
	for t := range p.types {
		f.Types[model.TypeName(t)] = fleet.TypeDef{}
	}
	if len(rows) == 0 {
		for t := range p.types {
			rows = append(rows, machineRow{Name: t, Classes: []string{t}, Facts: map[string]string{}})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	}
	used := map[model.MachineID]bool{}
	names := map[string]bool{}
	var errs []string
	for _, r := range rows {
		if names[strings.ToLower(r.Name)] {
			errs = append(errs, fmt.Sprintf("line %d: duplicate machine name %s", r.Line, r.Name))
			continue
		}
		names[strings.ToLower(r.Name)] = true
		m := model.Machine{Name: r.Name, OS: r.OS, Arch: r.Arch, Facts: map[string]string{}}
		seen := map[model.TypeName]bool{}
		addType := func(t model.TypeName) {
			if !seen[t] {
				seen[t] = true
				m.Types = append(m.Types, t)
			}
			if _, ok := f.Types[t]; !ok {
				f.Types[t] = fleet.TypeDef{}
			}
		}
		for _, c := range r.Classes {
			addType(model.TypeName(c))
			for class, enc := range opts.ClassEnclaves {
				if strings.EqualFold(class, c) && p.enclaves[enc] {
					addType(model.TypeName(enc))
				}
			}
		}
		for k, v := range r.Facts {
			m.Facts[k] = v
		}
		if r.Hostname != "" {
			m.Facts["hostname"] = r.Hostname
		}
		if p.factKeys["class"] {
			m.Facts["class"] = r.Classes[len(r.Classes)-1]
		}
		if p.factKeys["classes"] {
			m.Facts["classes"] = strings.Join(r.Classes, "\n")
		}
		if len(m.Facts) == 0 {
			m.Facts = nil
		}
		id := newMachineID(used)
		m.ID = id
		f.Machines[id] = m
	}
	for e := range p.enclaves {
		f.Types[model.TypeName(e)] = fleet.TypeDef{Enclave: true}
	}
	declared := map[string]bool{}
	for _, m := range f.Machines {
		for k := range m.Facts {
			declared[k] = true
		}
	}
	var missing []string
	for k := range p.factKeys {
		if !declared[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	for _, k := range missing {
		errs = append(errs, fmt.Sprintf("conditions or templates read the fact %q, which no machine declares; add a %s column", k, k))
	}
	if len(errs) > 0 {
		return f, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return f, nil
}
