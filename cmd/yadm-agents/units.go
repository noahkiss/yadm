package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// File is a parsed units file: the matrix.
type File struct {
	Path       string
	Schema     int
	Harness    map[string]HarnessConfig
	Units      []*Unit
	Conditions map[string]string // flattened: "<unit>.<harness>" cells and helper definitions
	byName     map[string]*Unit
}

// HarnessConfig holds per-harness settings from `[harness.<name>]`.
type HarnessConfig struct {
	Config string `toml:"config"` // the file the adapter owns keys in, relative to home
	// Trust lists project directories the harness trusts (codex). Each is
	// ~/..., $HOME/... or absolute, and must be inside home.
	Trust []string `toml:"trusted_projects"`
}

// Fields are the unit fields a `[unit.harness.<name>]` table may override.
type Fields struct {
	Kind    *string        `toml:"kind"`
	Script  *string        `toml:"script"`
	Args    []string       `toml:"args"`
	Run     *string        `toml:"run"`
	On      []string       `toml:"on"`
	Actions []string       `toml:"actions"`
	Match   any            `toml:"match"`   // string, or a table event -> matcher
	Timeout any            `toml:"timeout"` // integer seconds, or a table event -> seconds
	Extra   map[string]any `toml:"extra"`   // handler fields passed through verbatim
	Effect  *string        `toml:"effect"`  // deny | ask | context | rewrite | none
	Dir     *string        `toml:"dir"`
	File    *string        `toml:"file"`
	Via     *string        `toml:"via"` // another unit wires this one for the harness
	Note    *string        `toml:"note"`
}

// Unit is one `[[unit]]` row.
type Unit struct {
	Name     string            `toml:"name"`
	Required bool              `toml:"required"`
	First    bool              `toml:"first"` // leads every route list it is on
	Fields                     // base values
	Over     map[string]Fields `toml:"harness"`
	index    int
}

type rawFile struct {
	Schema     int                      `toml:"schema"`
	Harness    map[string]HarnessConfig `toml:"harness"`
	Units      []*Unit                  `toml:"unit"`
	Conditions map[string]any           `toml:"conditions"`
}

var unitName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]*$`)

// Load reads and parses a units file.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	f.Path = path
	return f, nil
}

// Parse parses units file bytes. It rejects unknown keys and malformed
// rows; kind, event and harness names stay open strings, which Check judges.
func Parse(b []byte) (*File, error) {
	var raw rawFile
	dec := toml.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		var sme *toml.StrictMissingError
		if errors.As(err, &sme) {
			return nil, fmt.Errorf("unknown key: %s", strings.TrimSpace(sme.String()))
		}
		return nil, err
	}
	if raw.Schema != 1 {
		return nil, fmt.Errorf("schema = %d, want 1", raw.Schema)
	}
	f := &File{Schema: raw.Schema, Harness: raw.Harness, Units: raw.Units, Conditions: map[string]string{}, byName: map[string]*Unit{}}
	if f.Harness == nil {
		f.Harness = map[string]HarnessConfig{}
	}
	if err := flattenConditions("", raw.Conditions, f.Conditions); err != nil {
		return nil, err
	}
	for h, c := range f.Harness {
		for _, p := range c.Trust {
			if !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, "$HOME/") && !strings.HasPrefix(p, "/") {
				return nil, fmt.Errorf("[harness.%s] trusted_projects: %q is relative; write ~/<path> or an absolute path", h, p)
			}
		}
	}
	for i, u := range f.Units {
		u.index = i
		if !unitName.MatchString(u.Name) {
			return nil, fmt.Errorf("unit %d: name %q: use letters, digits, _ and - (no dots)", i+1, u.Name)
		}
		if f.byName[u.Name] != nil {
			return nil, fmt.Errorf("unit %q defined twice", u.Name)
		}
		f.byName[u.Name] = u
		if err := u.Fields.validate(); err != nil {
			return nil, fmt.Errorf("unit %q: %w", u.Name, err)
		}
		for h, o := range u.Over {
			if err := o.validate(); err != nil {
				return nil, fmt.Errorf("unit %q harness %q: %w", u.Name, h, err)
			}
		}
	}
	return f, nil
}

func flattenConditions(prefix string, m map[string]any, out map[string]string) error {
	for k, v := range m {
		name := k
		if prefix != "" {
			name = prefix + "." + k
		}
		switch x := v.(type) {
		case string:
			if _, dup := out[name]; dup {
				return fmt.Errorf("condition %q defined twice", name)
			}
			out[name] = x
		case map[string]any:
			if err := flattenConditions(name, x, out); err != nil {
				return err
			}
		default:
			return fmt.Errorf("condition %q: want a string, got %T", name, v)
		}
	}
	return nil
}

func (f Fields) validate() error {
	if f.Script != nil {
		rest := strings.TrimPrefix(strings.TrimPrefix(*f.Script, "~/"), "$HOME/")
		if strings.ContainsAny(rest, scriptUnsafe) {
			return fmt.Errorf("script %q: a path with a quote, $, backtick, backslash or newline cannot be quoted for every harness", *f.Script)
		}
	}
	if _, err := eventMap[string](f.Match, "match"); err != nil {
		return err
	}
	if _, err := eventMap[int64](f.Timeout, "timeout"); err != nil {
		return err
	}
	for _, a := range f.Actions {
		if err := checkAction(a); err != nil {
			return err
		}
	}
	return nil
}

// eventMap reads a value that is either one T for every event or a table
// event -> T. The key "*" holds the value for every event.
func eventMap[T string | int64](v any, field string) (map[string]T, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case T:
		return map[string]T{"*": x}, nil
	case map[string]any:
		out := map[string]T{}
		for k, e := range x {
			t, ok := e.(T)
			if !ok {
				return nil, fmt.Errorf("%s.%s: want %T, got %T", field, k, *new(T), e)
			}
			out[k] = t
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s: want %T or a table of event -> %T, got %T", field, *new(T), *new(T), v)
}

// Unit returns the unit with that name, or nil.
func (f *File) Unit(name string) *Unit { return f.byName[name] }

// Cell returns the condition for unit × harness and whether the matrix has one.
func (f *File) Cell(unit, harness string) (string, bool) {
	c, ok := f.Conditions[unit+"."+harness]
	return c, ok
}

// Harnesses lists every harness a cell or a trusted_projects list names,
// sorted.
func (f *File) Harnesses() []string {
	seen := map[string]bool{}
	for h, c := range f.Harness {
		if len(c.Trust) > 0 {
			seen[h] = true
		}
	}
	for name := range f.Conditions {
		if u, h, ok := splitCell(name); ok && f.byName[u] != nil {
			seen[h] = true
		}
	}
	return sortedKeys(seen)
}

func splitCell(name string) (unit, harness string, ok bool) {
	i := strings.IndexByte(name, '.')
	if i <= 0 || strings.Count(name, ".") != 1 {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}

// Resolved is one unit seen from one harness: base fields with that
// harness's overrides applied.
type Resolved struct {
	Unit     string
	Index    int
	Harness  string
	Enabled  bool // the cell holds on the machine being rendered
	Required bool
	First    bool
	Kind     string
	Script   string
	Args     []string
	Run      string
	On       []string
	Actions  []string
	Match    map[string]string
	Timeout  map[string]int64
	Extra    map[string]any
	Effect   string
	Dir      string
	File     string
	Via      string
	Note     string
}

// Resolve applies harness h's overrides to the unit.
func (u *Unit) Resolve(h string) Resolved {
	f := u.Fields
	if o, ok := u.Over[h]; ok {
		f = merge(f, o)
	}
	r := Resolved{Unit: u.Name, Index: u.index, Harness: h, Required: u.Required, First: u.First,
		Kind: deref(f.Kind), Script: deref(f.Script), Args: f.Args, Run: deref(f.Run), On: f.On, Actions: f.Actions,
		Extra: f.Extra, Effect: deref(f.Effect), Dir: deref(f.Dir), File: deref(f.File), Via: deref(f.Via), Note: deref(f.Note)}
	r.Match, _ = eventMap[string](f.Match, "match")
	r.Timeout, _ = eventMap[int64](f.Timeout, "timeout")
	return r
}

func merge(base, o Fields) Fields {
	out := base
	if o.Kind != nil {
		out.Kind = o.Kind
	}
	if o.Script != nil {
		out.Script = o.Script
	}
	if o.Args != nil {
		out.Args = o.Args
	}
	if o.Run != nil {
		out.Run = o.Run
	}
	if o.On != nil {
		out.On = o.On
	}
	if o.Actions != nil {
		out.Actions = o.Actions
	}
	if o.Match != nil {
		out.Match = o.Match
	}
	if o.Timeout != nil {
		out.Timeout = o.Timeout
	}
	if o.Extra != nil {
		out.Extra = o.Extra
	}
	if o.Effect != nil {
		out.Effect = o.Effect
	}
	if o.Dir != nil {
		out.Dir = o.Dir
	}
	if o.File != nil {
		out.File = o.File
	}
	if o.Via != nil {
		out.Via = o.Via
	}
	if o.Note != nil {
		out.Note = o.Note
	}
	return out
}

// MatchFor returns the raw matcher set for event ev, if any.
func (r Resolved) MatchFor(ev string) (string, bool) {
	if m, ok := r.Match[ev]; ok {
		return m, true
	}
	m, ok := r.Match["*"]
	return m, ok
}

// TimeoutFor returns the timeout for event ev; 0 means none.
func (r Resolved) TimeoutFor(ev string) int64 {
	if t, ok := r.Timeout[ev]; ok {
		return t
	}
	return r.Timeout["*"]
}

// Command builds the handler command for event ev. A verbatim `run` wins;
// otherwise the adapter formats `script` and `args`. `{harness}` and
// `{event}` are replaced in both.
func (r Resolved) Command(ev string, quote bool) string {
	sub := strings.NewReplacer("{harness}", r.Harness, "{event}", ev)
	if r.Run != "" {
		return sub.Replace(r.Run)
	}
	if r.Script == "" {
		return ""
	}
	s := homeVar(r.Script)
	if quote || strings.ContainsAny(s, shellSplit) {
		s = `"` + s + `"`
	}
	for _, a := range r.Args {
		s += " " + sub.Replace(a)
	}
	return s
}

// shellSplit holds the characters a shell would split or glob on in an
// unquoted script path. Characters it would expand inside double quotes
// are refused at parse time (scriptUnsafe).
const shellSplit = " \t'&;|<>()*?[]{}#!~"

const scriptUnsafe = "\"`$\\\n\r"

// homeVar spells a leading ~/ as $HOME/, which every harness's shell expands.
func homeVar(p string) string {
	if strings.HasPrefix(p, "~/") {
		return "$HOME/" + p[2:]
	}
	return p
}

// ScriptName is the base name of the unit's check script, or "".
func (r Resolved) ScriptName() string {
	if r.Script == "" {
		return ""
	}
	i := strings.LastIndexByte(r.Script, '/')
	return r.Script[i+1:]
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
