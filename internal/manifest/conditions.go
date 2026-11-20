package manifest

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
)

// includeKey is the reserved key of a `[conditions]` table that lists the
// files whose own `[conditions]` tables load too.
const includeKey = "include"

// namedConds is the manifest's named-condition state.
type namedConds struct {
	defs     []cond.Definition // the manifest's own, then each include's
	includes []string
	loaded   bool // LoadIncludes ran (or there is nothing to load)
}

// flattenConditions turns a decoded `[conditions]` table into definitions.
// A dotted key (`a.b = "…"`) decodes as a nested table; both it and a quoted
// key (`"a.b" = "…"`) name the condition `a.b`. top allows the include key.
func flattenConditions(file string, tbl map[string]any, top bool) ([]cond.Definition, []string, error) {
	var defs []cond.Definition
	var includes []string
	var errs []error
	seen := map[string]bool{}
	var walk func(prefix string, t map[string]any)
	walk = func(prefix string, t map[string]any) {
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			if prefix == "" && k == includeKey {
				if !top {
					errs = append(errs, fmt.Errorf("%s: conditions.include: an included file cannot include another", file))
					continue
				}
				list, ok := t[k].([]any)
				if !ok {
					errs = append(errs, fmt.Errorf("%s: conditions.include: want a list of source paths", file))
					continue
				}
				for _, v := range list {
					s, ok := v.(string)
					if !ok {
						errs = append(errs, fmt.Errorf("%s: conditions.include: want a list of source paths", file))
						continue
					}
					includes = append(includes, s)
				}
				continue
			}
			switch v := t[k].(type) {
			case string:
				if seen[name] {
					errs = append(errs, fmt.Errorf("%s: conditions.%s: defined twice", file, name))
					continue
				}
				seen[name] = true
				defs = append(defs, cond.Definition{Name: name, Src: v, File: file})
			case map[string]any:
				walk(name, v)
			default:
				errs = append(errs, fmt.Errorf("%s: conditions.%s: want a condition string", file, name))
			}
		}
	}
	walk("", tbl)
	return defs, includes, errors.Join(errs...)
}

func validInclude(p string) error {
	if err := validRel(p); err != nil {
		return err
	}
	if IsGlob(p) {
		return fmt.Errorf("%q: an include names one file, not a glob", p)
	}
	if strings.HasPrefix(p, "sealed/") || strings.HasPrefix(p, "keys/") {
		return fmt.Errorf("%q: an include cannot read sealed/ or keys/", p)
	}
	if p == FileName {
		return fmt.Errorf("%q: the manifest cannot include itself", p)
	}
	return nil
}

// Includes returns the source paths `conditions.include` lists, in order.
func (m *Manifest) Includes() []string { return slices.Clone(m.named.includes) }

// LoadIncludes reads each `conditions.include` file through read and adds
// its `[conditions]` table to the manifest's named conditions. Other tables
// in an included file are ignored. An included file cannot include another.
// It is a no-op when the manifest includes nothing; calling it twice is an
// error.
func (m *Manifest) LoadIncludes(read func(model.SourcePath) ([]byte, error)) error {
	if len(m.named.includes) == 0 {
		m.named.loaded = true
		return nil
	}
	if m.named.loaded {
		return errors.New("manifest: conditions.include already loaded")
	}
	var errs []error
	for _, p := range m.named.includes {
		b, err := read(model.SourcePath(p))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: conditions.include %q: %w", FileName, p, err))
			continue
		}
		var doc map[string]any
		if err := toml.Unmarshal(b, &doc); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		raw, ok := doc["conditions"]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no [conditions] table", p))
			continue
		}
		tbl, ok := raw.(map[string]any)
		if !ok {
			errs = append(errs, fmt.Errorf("%s: conditions: want a table", p))
			continue
		}
		defs, _, err := flattenConditions(p, tbl, false)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m.named.defs = append(m.named.defs, defs...)
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	m.named.loaded = true
	return nil
}

// Definitions returns every named condition: the manifest's own, then those
// of its includes once LoadIncludes ran.
func (m *Manifest) Definitions() []cond.Definition { return slices.Clone(m.named.defs) }

// Vocabulary returns v with the manifest's named conditions defined, for
// parsing a condition that may say `cond:NAME`. It fails when an include
// was declared but not loaded, or when a definition is bad.
func (m *Manifest) Vocabulary(v cond.Vocabulary) (cond.Vocabulary, error) {
	if len(m.named.includes) > 0 && !m.named.loaded {
		return v, fmt.Errorf("%s: conditions.include is not loaded", FileName)
	}
	if len(m.named.defs) == 0 {
		return v, nil
	}
	named, err := cond.Define(m.named.defs, v)
	if err != nil {
		return v, err
	}
	v.Conditions = named
	return v, nil
}
