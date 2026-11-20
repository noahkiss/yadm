package importer

import (
	"fmt"
	"strings"
)

// Long condition keys.
const (
	condDefault      = "default"
	condClass        = "class"
	condOS           = "os"
	condArch         = "arch"
	condHostname     = "hostname"
	condUser         = "user"
	condDistro       = "distro"
	condDistroFamily = "distro_family"
	condTemplate     = "template"
	condExtension    = "extension"
)

// longKeys maps every accepted label, long or short, to its long form.
var longKeys = map[string]string{
	"default":       condDefault,
	"c":             condClass,
	"class":         condClass,
	"o":             condOS,
	"os":            condOS,
	"a":             condArch,
	"arch":          condArch,
	"h":             condHostname,
	"hostname":      condHostname,
	"u":             condUser,
	"user":          condUser,
	"d":             condDistro,
	"distro":        condDistro,
	"f":             condDistroFamily,
	"distro_family": condDistroFamily,
	"t":             condTemplate,
	"template":      condTemplate,
	"e":             condExtension,
	"extension":     condExtension,
}

// condWeight is the upstream specificity of a matching condition. Every
// condition except extension also adds 1000, so more conditions always win.
var condWeight = map[string]int{
	condDefault:      0,
	condArch:         1,
	condOS:           2,
	condDistro:       4,
	condDistroFamily: 8,
	condClass:        16,
	condHostname:     32,
	condUser:         64,
	condTemplate:     0,
}

// AltCond is one condition of an alternate file name.
type AltCond struct {
	Key   string // long form: default, class, os, arch, hostname, user, distro, distro_family, template, extension
	Value string
}

// AltName is a parsed alternate file name.
type AltName struct {
	// Base is the target path with the alternate suffix removed, for example
	// ".config/app/settings" for ".config/app##class.work/settings".
	Base  string
	Conds []AltCond
	// Alt is the path up to and including the tagged component, for example
	// ".config/app##class.work". It equals the whole path for a file-level
	// alternate.
	Alt string
	// Dir is true when the tagged component is a directory above the file.
	Dir bool
}

// Template reports whether the name carries a template condition, and its processor.
func (a AltName) Template() (string, bool) {
	for _, c := range a.Conds {
		if c.Key == condTemplate {
			return c.Value, true
		}
	}
	return "", false
}

// Score is the upstream specificity of the name when all its conditions match.
func (a AltName) Score() int {
	s := 0
	for _, c := range a.Conds {
		if c.Key == condExtension {
			continue
		}
		s += 1000 + condWeight[c.Key]
	}
	return s
}

// ParseAltName parses "dir/name##cond,cond". ok is false for a plain path.
// Only the first component that contains "##" is an alternate; a directory
// alternate covers every file below it.
func ParseAltName(path string) (AltName, bool, error) {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		j := strings.Index(p, "##")
		if j < 0 {
			continue
		}
		name, spec := p[:j], p[j+2:]
		if name == "" {
			return AltName{}, true, fmt.Errorf("alternate %q has an empty name", strings.Join(parts[:i+1], "/"))
		}
		conds, err := parseConds(spec)
		if err != nil {
			return AltName{}, true, err
		}
		for _, rest := range parts[i+1:] {
			if strings.Contains(rest, "##") {
				return AltName{}, true, fmt.Errorf("nested alternate below %q", strings.Join(parts[:i+1], "/"))
			}
		}
		base := append(append(append([]string{}, parts[:i]...), name), parts[i+1:]...)
		a := AltName{
			Base:  strings.Join(base, "/"),
			Conds: conds,
			Alt:   strings.Join(parts[:i+1], "/"),
			Dir:   i < len(parts)-1,
		}
		if _, isTmpl := a.Template(); isTmpl && a.Dir {
			return AltName{}, true, fmt.Errorf("template condition on directory alternate %q", a.Alt)
		}
		return a, true, nil
	}
	return AltName{}, false, nil
}

func parseConds(spec string) ([]AltCond, error) {
	if spec == "" {
		return nil, fmt.Errorf("empty condition list")
	}
	var out []AltCond
	seen := map[string]bool{}
	for _, field := range strings.Split(spec, ",") {
		label, value, hasValue := strings.Cut(field, ".")
		if strings.HasPrefix(label, "~") {
			return nil, fmt.Errorf("negated condition %q is not supported", field)
		}
		key, ok := longKeys[strings.ToLower(label)]
		if !ok {
			return nil, fmt.Errorf("unknown condition %q", field)
		}
		switch key {
		case condDefault:
			if hasValue {
				return nil, fmt.Errorf("condition %q takes no value", field)
			}
		case condTemplate, condExtension:
			// The value is optional: the processor or the extension.
		default:
			if value == "" {
				return nil, fmt.Errorf("condition %q needs a value", field)
			}
		}
		if key != condClass && key != condExtension && seen[key] {
			// Two values for a single-valued property can never both match.
			return nil, fmt.Errorf("condition %q repeats %s", field, key)
		}
		seen[key] = true
		out = append(out, AltCond{Key: key, Value: value})
	}
	return out, nil
}
