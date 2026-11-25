package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/model"
)

// Default values that Parse fills in when the manifest leaves them out.
const (
	DefaultQuiet        = 2 * time.Minute
	DefaultTaskTimeout  = 5 * time.Minute
	DefaultCheckTimeout = 30 * time.Second
)

// Parse parses and validates a manifest. Unknown keys, unknown enum values,
// unsafe paths and inconsistent entries are errors. Parse fills in the
// documented defaults, so a parsed Manifest is complete. Conditions are
// checked by Resolve, which has the fleet's Vocabulary.
func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	d := toml.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		var sm *toml.StrictMissingError
		if errors.As(err, &sm) {
			return nil, fmt.Errorf("%s: %s", FileName, sm.String())
		}
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	var raw struct {
		Defaults map[string]any `toml:"defaults"`
	}
	if err := toml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", FileName, err)
	}
	if _, ok := raw.Defaults["quiet"]; !ok {
		m.Defaults.Quiet = model.Duration(DefaultQuiet)
	}
	for name, t := range m.Tasks {
		if t.Timeout == 0 {
			t.Timeout = model.Duration(DefaultTaskTimeout)
			m.Tasks[name] = t
		}
	}
	for name, c := range m.Checks {
		if c.Timeout == 0 {
			c.Timeout = model.Duration(DefaultCheckTimeout)
			m.Checks[name] = c
		}
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	if m.Conditions != nil {
		defs, includes, err := flattenConditions(FileName, m.Conditions, true)
		if err != nil {
			return nil, err
		}
		var errs []error
		for i, p := range includes {
			if err := validInclude(p); err != nil {
				errs = append(errs, fmt.Errorf("%s: conditions.include: %w", FileName, err))
			}
			if slices.Contains(includes[:i], p) {
				errs = append(errs, fmt.Errorf("%s: conditions.include: %q listed twice", FileName, p))
			}
		}
		if err := errors.Join(errs...); err != nil {
			return nil, err
		}
		m.named = namedConds{defs: defs, includes: includes}
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	var errs []error
	add := func(where string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %w", FileName, where, err))
		}
	}
	if m.Schema != Schema {
		add("schema", fmt.Errorf("got %d, want %d", m.Schema, Schema))
	}
	if m.Defaults.Quiet < 0 {
		add("defaults.quiet", errors.New("negative duration"))
	}
	for i, e := range m.Entries {
		add(fmt.Sprintf("file[%d] %q", i, e.Target), validateEntry(e))
	}
	for i, u := range m.Units {
		add(fmt.Sprintf("unit[%d] %q", i, u.Target), m.validateUnit(u))
	}
	for i, r := range m.Roots {
		where := fmt.Sprintf("root[%d] %q", i, r.Path)
		add(where, validRel(string(r.Path)))
		if IsGlob(string(r.Path)) {
			add(where, errors.New("a root is a directory, not a glob"))
		}
		if r.Enclave != "" {
			add(where, validName("enclave", string(r.Enclave)))
		}
		for _, g := range r.Ignore {
			add(where+" ignore", ValidPattern(g))
		}
	}
	for _, name := range sortedKeys(m.Tasks) {
		t := m.Tasks[name]
		where := "tasks." + name
		if len(t.Command) == 0 || t.Command[0] == "" {
			add(where, errors.New("command is empty"))
		}
		if t.Timeout < 0 {
			add(where, errors.New("negative timeout"))
		}
		for _, p := range append(append([]string{}, t.On...), t.OnRemove...) {
			add(where, ValidPattern(p))
		}
		for _, p := range t.Outputs {
			add(where+" outputs", ValidPattern(p))
		}
		for _, f := range t.OnFact {
			if f == "" || f == "fact:" {
				add(where+" on_fact", errors.New("empty input"))
			}
		}
	}
	for _, name := range sortedKeys(m.Checks) {
		c := m.Checks[name]
		where := "checks." + name
		if len(c.Command) == 0 || c.Command[0] == "" {
			add(where, errors.New("command is empty"))
		}
		if c.Timeout < 0 {
			add(where, errors.New("negative timeout"))
		}
		for _, p := range c.Paths {
			add(where, ValidPattern(p))
		}
	}
	for _, name := range sortedKeys(m.Plugins) {
		add("plugins."+name, validPlugin(name, m.Plugins[name]))
	}
	for _, p := range m.Protected {
		add("protected", ValidPattern(p))
	}
	return errors.Join(errs...)
}

// validPlugin checks a plugin's name and its $HOME-relative executables.
func validPlugin(name string, p PluginDef) error {
	var errs []error
	if !validPluginName(name) {
		errs = append(errs, errors.New("a plugin name is lower-case letters, digits, '-' and '_', starting with a letter"))
	}
	if slices.Contains(ReservedNames, name) {
		errs = append(errs, fmt.Errorf("%q is a built-in command; a plugin may not shadow it", name))
	}
	for _, argv := range []struct {
		key  string
		argv []string
		need bool
	}{{"command", p.Command, true}, {"news", p.News, false}} {
		switch {
		case len(argv.argv) == 0 && !argv.need:
		case len(argv.argv) == 0 || argv.argv[0] == "":
			errs = append(errs, fmt.Errorf("%s is empty", argv.key))
		default:
			if err := validRel(argv.argv[0]); err != nil {
				errs = append(errs, fmt.Errorf("%s: the executable is a path relative to $HOME: %w", argv.key, err))
			}
		}
	}
	if p.Schema < 0 {
		errs = append(errs, errors.New("negative schema"))
	}
	if strings.ContainsAny(p.Summary, "\n\r") {
		errs = append(errs, errors.New("summary is one line"))
	}
	return errors.Join(errs...)
}

func validPluginName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func validName(what, s string) error {
	if s == "" || strings.ContainsAny(s, "/\\:*?[ \t\n") {
		return fmt.Errorf("bad %s name %q", what, s)
	}
	return nil
}

func validateEntry(e Entry) error {
	var errs []error
	t := string(e.Target)
	glob := IsGlob(t)
	if glob {
		errs = append(errs, ValidPattern(t))
	} else {
		errs = append(errs, validRel(t))
	}
	if e.Enclave != "" {
		errs = append(errs, validName("enclave", string(e.Enclave)))
	}
	if s := string(e.Source); s != "" {
		if err := validRel(s); err != nil {
			errs = append(errs, fmt.Errorf("source: %w", err))
		} else if IsGlob(s) {
			errs = append(errs, fmt.Errorf("source %q: a source is never a glob; a glob entry's source names the directory that replaces the target's fixed prefix", s))
		}
		switch {
		case e.Enclave != "":
			want := "sealed/" + string(e.Enclave) + "/"
			if !strings.HasPrefix(s, want) {
				errs = append(errs, fmt.Errorf("source %q: an entry with enclave %q reads from %s", s, e.Enclave, want))
			}
		case !strings.HasPrefix(s, "files/"):
			errs = append(errs, fmt.Errorf("source %q: a plaintext entry reads from files/; set enclave to read from sealed/", s))
		}
	}
	switch e.Format {
	case FormatWhole, FormatText, FormatJSON, FormatJSONC, FormatTOML:
	default:
		errs = append(errs, fmt.Errorf("unknown format %q", e.Format))
	}
	structured := e.Format == FormatJSON || e.Format == FormatJSONC || e.Format == FormatTOML
	if (len(e.Keep) > 0 || len(e.Drop) > 0 || len(e.Seal) > 0) && !structured {
		errs = append(errs, errors.New("keep, drop and seal need format json, jsonc or toml"))
	}
	if e.Regions && e.Format != FormatWhole && e.Format != FormatText {
		errs = append(errs, fmt.Errorf("regions need a text file, not format %q", e.Format))
	}
	if e.Format == FormatText && !e.Regions {
		errs = append(errs, errors.New(`format "text" means marked regions; set regions = true`))
	}
	if e.Enclave != "" && (len(e.Seal) > 0 || e.Regions) {
		errs = append(errs, errors.New("a whole-file enclave entry needs no seal or regions"))
	}
	for k, enc := range e.Seal {
		if k == "" {
			errs = append(errs, errors.New("seal: empty key path"))
		}
		errs = append(errs, validName("enclave", string(enc)))
	}
	for _, k := range append(append([]string{}, e.Keep...), e.Drop...) {
		if k == "" {
			errs = append(errs, errors.New("keep/drop: empty key path"))
		}
	}
	if e.Mode&^0o777 != 0 {
		errs = append(errs, fmt.Errorf("mode %#o: only permission bits are allowed", uint32(e.Mode)))
	}
	switch e.Merge {
	case "", MergeText, MergeUnion, MergeAddOnly, MergeOurs, MergeTheirs, MergeGenerated, MergeJSONKeys, MergeTOMLKeys, MergeStructural:
	default:
		errs = append(errs, fmt.Errorf("unknown merge policy %q", e.Merge))
	}
	if len(e.Volatile) > 0 && !structured && e.Merge != MergeJSONKeys && e.Merge != MergeTOMLKeys {
		errs = append(errs, errors.New("volatile needs format json, jsonc or toml, or merge json-keys or toml-keys"))
	}
	for _, k := range e.Volatile {
		if k == "" {
			errs = append(errs, errors.New("volatile: empty key path"))
		}
	}
	if e.Quiet != nil && *e.Quiet < 0 {
		errs = append(errs, errors.New("negative quiet"))
	}
	return errors.Join(errs...)
}

func (m *Manifest) validateUnit(u Unit) error {
	t := string(u.Target)
	if err := validRel(t); err != nil {
		return err
	}
	if IsGlob(t) {
		return errors.New("a unit names one target, not a glob")
	}
	switch u.Kind {
	case UnitLaunchd, UnitSystemd:
	default:
		return fmt.Errorf("unknown unit kind %q: want launchd or systemd", u.Kind)
	}
	switch u.Reload {
	case "", ReloadAuto, ReloadNever:
	default:
		return fmt.Errorf("unknown unit reload %q: want auto or never", u.Reload)
	}
	for _, e := range m.Entries {
		if e.Target == u.Target || IsGlob(string(e.Target)) && Match(string(e.Target), t) {
			return nil
		}
	}
	return errors.New("no [[file]] entry produces this target")
}
