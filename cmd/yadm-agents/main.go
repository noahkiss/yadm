package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/model"
)

const usage = `yadm-agents: one units file wires every coding-agent harness.

Usage:
  yadm-agents gen    [--dry-run] [--diff] [--as <machine>] [--only h,...] [--prune] [--allow-drop]
  yadm-agents verify [--offline]
  yadm-agents matrix [--format table|json|parity] [--machines a,b]

Common flags: --units <path> (default $YADM_AGENTS_UNITS, then
$XDG_CONFIG_HOME/yadm-agents/units.toml), --home <dir> (default $YADM_HOME,
then $HOME), --json.

gen writes this machine's wiring, only the keys it owns, atomically, and
only on change. --as renders another machine's wiring and never writes.
Exit codes: 0 ok, 1 a harness refused or verify found an error, 2 usage.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, newYadmEval()))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, ev Evaluator) int {
	kind := os.Getenv("YADM_KIND")
	var req *extexec.Request
	if kind == string(extexec.KindTask) || kind == string(extexec.KindCheck) || kind == string(extexec.KindSubcommand) {
		var r extexec.Request
		if err := json.NewDecoder(stdin).Decode(&r); err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintln(stderr, "yadm-agents: bad request:", err)
			return 1
		}
		req = &r
	}
	if kind == string(extexec.KindCheck) && (len(args) == 0 || args[0] != "verify") {
		args = append([]string{"verify"}, args...)
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	c := &cli{ev: ev, req: req, kind: kind, stdout: stdout, stderr: stderr}
	switch args[0] {
	case "gen":
		return c.gen(args[1:])
	case "verify":
		return c.verify(args[1:])
	case "matrix":
		return c.matrix(args[1:])
	}
	fmt.Fprintf(stderr, "yadm-agents: unknown command %q\n%s", args[0], usage)
	return 2
}

type cli struct {
	ev             Evaluator
	req            *extexec.Request
	kind           string
	stdout, stderr io.Writer
	units, home    string
	unitsFrom      string // where the units path came from: flag, env, xdg or home
	json           bool
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.StringVar(&c.units, "units", "", "units file")
	fs.StringVar(&c.home, "home", "", "home directory the harness files live in")
	fs.BoolVar(&c.json, "json", os.Getenv("YADM_JSON") == "1", "print JSON")
	return fs
}

func (c *cli) resolvePaths() {
	if c.home == "" {
		c.home = os.Getenv("YADM_HOME")
	}
	if c.home == "" && c.req != nil {
		c.home = c.req.Home
	}
	if c.home == "" {
		c.home, _ = os.UserHomeDir()
	}
	c.unitsFrom = "flag"
	if c.units == "" {
		c.units, c.unitsFrom = os.Getenv("YADM_AGENTS_UNITS"), "env"
	}
	if c.units == "" {
		cfg, from := os.Getenv("XDG_CONFIG_HOME"), "xdg"
		if cfg == "" {
			cfg, from = filepath.Join(c.home, ".config"), "home"
		}
		c.units, c.unitsFrom = filepath.Join(cfg, "yadm-agents", "units.toml"), from
	}
	// unitsTarget compares the two, so both must be absolute.
	if p, err := filepath.Abs(c.home); err == nil {
		c.home = p
	}
	if p, err := filepath.Abs(c.units); err == nil {
		c.units = p
	}
}

// unitsTarget names the units file relative to home, as a check request
// keys staged files.
func (c *cli) unitsTarget() string {
	rel, err := filepath.Rel(c.home, c.units)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return filepath.ToSlash(rel)
}

// finish prints text or, under the exec contract, one response object.
func (c *cli) finish(ok bool, text string, data any) int {
	code := 0
	if !ok {
		code = 1
	}
	if c.req != nil {
		raw, _ := json.Marshal(data)
		resp := extexec.Response{Schema: 1, OK: ok, Message: strings.TrimRight(text, "\n"), Data: raw}
		b, _ := json.Marshal(resp)
		fmt.Fprintln(c.stdout, string(b))
		if c.kind == string(extexec.KindCheck) || c.kind == string(extexec.KindTask) {
			return 0 // the response carries ok; a non-zero exit would hide it
		}
		return code
	}
	if c.json {
		b, _ := json.MarshalIndent(map[string]any{"schema": 1, "ok": ok, "data": data}, "", "  ")
		fmt.Fprintln(c.stdout, string(b))
		return code
	}
	fmt.Fprint(c.stdout, text)
	return code
}

// managedUnits is the home-relative units target yadm manages.
const managedUnits = ".config/yadm-agents/units.toml"

// unitsMismatch reports a units path that is not the file yadm hands over:
// a check stages, or a task reports changed, a units target other than the
// one yadm-agents reads. Reading the live file in its place would check or
// apply the wrong copy, so it fails loudly instead.
func (c *cli) unitsMismatch() error {
	if c.req == nil {
		return nil
	}
	want := c.unitsTarget()
	var ts []string
	for t := range c.req.Staged {
		ts = append(ts, string(t))
	}
	for _, t := range c.req.Changed {
		ts = append(ts, string(t))
	}
	sort.Strings(ts)
	for _, t := range ts {
		if path.Base(t) == "units.toml" && path.Base(path.Dir(t)) == "yadm-agents" && t != want {
			return c.mismatchErr(t)
		}
	}
	return nil
}

func (c *cli) mismatchErr(target string) error {
	from := map[string]string{"flag": "--units", "env": "YADM_AGENTS_UNITS", "xdg": "XDG_CONFIG_HOME", "home": "$HOME/.config"}[c.unitsFrom]
	return fmt.Errorf("units path mismatch: yadm manages %s but yadm-agents reads %s (from %s); pass --units %s in the task and check command (a task does not see YADM_AGENTS_UNITS), or unset XDG_CONFIG_HOME",
		target, c.units, from, filepath.Join(c.home, filepath.FromSlash(target)))
}

func (c *cli) load() (*File, error) {
	c.resolvePaths()
	if err := c.unitsMismatch(); err != nil {
		return nil, err
	}
	p := c.units
	if c.req != nil && c.req.Staged != nil {
		if s, ok := c.req.Staged[model.Target(c.unitsTarget())]; ok {
			p = s
		}
	}
	f, err := Load(p)
	if errors.Is(err, fs.ErrNotExist) && c.unitsFrom == "xdg" && c.unitsTarget() != managedUnits {
		if _, serr := os.Stat(filepath.Join(c.home, managedUnits)); serr == nil {
			return nil, c.mismatchErr(managedUnits)
		}
	}
	if err != nil {
		return nil, err
	}
	f.Path = c.units
	return f, nil
}

func (c *cli) gen(args []string) int {
	fs := c.flags("gen")
	var o GenOptions
	var diff bool
	var only string
	fs.BoolVar(&o.DryRun, "dry-run", false, "show what would change; write nothing")
	fs.BoolVar(&diff, "diff", false, "print the handler rows that would change")
	fs.StringVar(&o.As, "as", "", "render for another fleet machine (implies --dry-run)")
	fs.StringVar(&only, "only", "", "comma-separated harnesses")
	fs.BoolVar(&o.Prune, "prune", false, "drop live handlers that no unit produces")
	fs.BoolVar(&o.AllowDrop, "allow-drop", false, "allow removing a required unit's handlers")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := c.load()
	if err != nil {
		fmt.Fprintln(c.stderr, "yadm-agents:", err)
		return 1
	}
	o.Home = c.home
	if only != "" {
		o.Only = setOf(strings.Split(only, ",")...)
		named := setOf(f.Harnesses()...)
		for _, h := range sortedKeys(o.Only) {
			if !named[h] {
				fmt.Fprintf(c.stderr, "yadm-agents: --only %s: no cell names that harness (have: %s)\n", h, strings.Join(f.Harnesses(), ", "))
				return 2
			}
		}
	}
	if o.As != "" {
		this, err := c.ev.This()
		if err == nil && this == o.As {
			o.As = "" // this machine: evaluate with local facts
			o.DryRun = true
		}
	}
	rs, err := Gen(f, c.ev, o)
	if err != nil {
		fmt.Fprintln(c.stderr, "yadm-agents:", err)
		return 1
	}
	ok := true
	for _, r := range rs {
		if r.Status == StatusRefused {
			ok = false
		}
	}
	return c.finish(ok, formatResults(rs, diff), rs)
}

func (c *cli) verify(args []string) int {
	fs := c.flags("verify")
	var o VerifyOptions
	fs.BoolVar(&o.Offline, "offline", false, "do not evaluate cells through yadm")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := c.load()
	if err != nil {
		return c.finish(false, fmt.Sprintf("error: %v\n", err), []Finding{{"error", err.Error()}})
	}
	o.Home = c.home
	if c.req != nil {
		o.Staged = map[string]string{}
		for t, p := range c.req.Staged {
			o.Staged[string(t)] = p
		}
	}
	fs2 := Verify(f, c.ev, o)
	var b strings.Builder
	for _, x := range fs2 {
		fmt.Fprintf(&b, "%s: %s\n", x.Level, x.Msg)
	}
	if !hasErrors(fs2) {
		fmt.Fprintf(&b, "ok: %d units, %d cells\n", len(f.Units), countCells(f))
	}
	if fs2 == nil {
		fs2 = []Finding{}
	}
	return c.finish(!hasErrors(fs2), b.String(), fs2)
}

func countCells(f *File) int {
	n := 0
	for name := range f.Conditions {
		if u, _, ok := splitCell(name); ok && f.Unit(u) != nil {
			n++
		}
	}
	return n
}

func (c *cli) matrix(args []string) int {
	fs := c.flags("matrix")
	var format, machines string
	fs.StringVar(&format, "format", "table", "table, json or parity")
	fs.StringVar(&machines, "machines", "", "comma-separated machines (default: the fleet)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := c.load()
	if err != nil {
		fmt.Fprintln(c.stderr, "yadm-agents:", err)
		return 1
	}
	var ms []string
	if machines != "" {
		ms = strings.Split(machines, ",")
	}
	m, err := BuildMatrix(f, c.ev, ms)
	if err != nil {
		fmt.Fprintln(c.stderr, "yadm-agents:", err)
		return 1
	}
	if c.json || format == "json" {
		b, err := m.JSON()
		if err != nil {
			fmt.Fprintln(c.stderr, "yadm-agents:", err)
			return 1
		}
		c.json = false
		if c.req != nil {
			return c.finish(true, "", json.RawMessage(b))
		}
		fmt.Fprintln(c.stdout, string(b))
		return 0
	}
	switch format {
	case "table":
		return c.finish(true, m.Table(), m)
	case "parity":
		return c.finish(true, m.Parity(f), m)
	}
	fmt.Fprintf(c.stderr, "yadm-agents: unknown format %q\n", format)
	return 2
}
