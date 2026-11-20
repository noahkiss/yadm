package importer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/manifest"
)

// StripRule is what a legacy clean filter did to one target, restated as
// intra-file rules (design section 6). A filter that staged only owned
// tables is Keep; one that deleted runtime keys is Drop. Volatile and Merge
// set the entry's sync merge behaviour.
type StripRule struct {
	Format   manifest.Format      `toml:"format"`
	Keep     []string             `toml:"keep"`
	Drop     []string             `toml:"drop"`
	Volatile []string             `toml:"volatile"`
	Merge    manifest.MergePolicy `toml:"merge"`
}

// Filter maps one legacy gitattributes `filter=<name>` to rules. The core
// knows no filter by name: a non-transcrypt filter without a mapping fails
// the import, so a filter is never lost silently.
type Filter struct {
	// Crypt says the filter also runs transcrypt (a strip filter composed
	// with encryption). Its files are decrypted and sealed like `crypt` ones.
	Crypt bool `toml:"crypt"`
	// Paths maps a target (the legacy path without its `##` suffix) or a
	// target glob to its rule. A marked path that matches no entry fails the
	// import. An entry with no rule fields records that the filter changed
	// nothing for that path.
	Paths map[string]StripRule `toml:"paths"`
}

// FiltersFile is the file `yadm import --filters` reads:
//
//	[filters.strip-runtime.paths.".config/app/settings.json"]
//	format = "json"
//	drop = ["model"]
//
//	[filters.crypt-strip]
//	crypt = true
//	[filters.crypt-strip.paths.".config/tool/config.toml"]
//	format = "toml"
//	keep = ["model", "tui"]
//	drop = ["tui.nux"]
type FiltersFile struct {
	Filters map[string]Filter `toml:"filters"`
}

// ReadFilters reads and validates a filters file.
func ReadFilters(file string) (map[string]Filter, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return ParseFilters(b)
}

// ParseFilters parses a filters file strictly.
func ParseFilters(b []byte) (map[string]Filter, error) {
	var ff FiltersFile
	d := toml.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&ff); err != nil {
		return nil, fmt.Errorf("filters: %w", err)
	}
	var errs []error
	for _, name := range sortedNames(ff.Filters) {
		f := ff.Filters[name]
		if name == "" || name == "crypt" {
			errs = append(errs, fmt.Errorf("filters: %q cannot be mapped", name))
		}
		for _, p := range sortedNames(f.Paths) {
			if err := manifest.ValidPattern(p); err != nil {
				errs = append(errs, fmt.Errorf("filters.%s: path %q: %w", name, p, err))
			}
			r := f.Paths[p]
			if r.empty() {
				continue
			}
			switch r.Format {
			case manifest.FormatJSON, manifest.FormatJSONC, manifest.FormatTOML:
			case manifest.FormatWhole: // taken from the target's extension
			default:
				errs = append(errs, fmt.Errorf("filters.%s: path %q: unknown format %q", name, p, r.Format))
			}
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return ff.Filters, nil
}

func (r StripRule) empty() bool {
	return r.Format == "" && len(r.Keep) == 0 && len(r.Drop) == 0 && len(r.Volatile) == 0 && r.Merge == ""
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stripRule returns the rule a legacy filter applied to target. ok is false
// (with a problem recorded) when the filter has no mapping for it.
func (p *planner) stripRule(legacyPath, filter, target string) (StripRule, bool) {
	if filter == "" {
		return StripRule{}, true
	}
	f, mapped := p.opts.Filters[filter]
	if !mapped {
		if p.filters[filter] {
			return StripRule{}, true // a plain transcrypt filter
		}
		p.problem(legacyPath, "gitattributes filter %q has no mapping; map it with --filters (keep, drop or volatile rules) so what it stripped is not lost", filter)
		return StripRule{}, false
	}
	var hits []string
	for _, pat := range sortedNames(f.Paths) {
		if pat == target || manifest.IsGlob(pat) && manifest.Match(pat, target) {
			hits = append(hits, pat)
		}
	}
	switch len(hits) {
	case 0:
		p.problem(legacyPath, "gitattributes filter %q has no rule for %s; add filters.%s.paths.%q", filter, target, filter, target)
		return StripRule{}, false
	case 1:
	default:
		p.problem(legacyPath, "gitattributes filter %q: %d path rules match %s (%s)", filter, len(hits), target, strings.Join(hits, ", "))
		return StripRule{}, false
	}
	r := f.Paths[hits[0]]
	if r.Format == "" && len(r.Keep)+len(r.Drop)+len(r.Volatile) > 0 {
		r.Format = formatByExt(target)
		if r.Format == "" {
			p.problem(legacyPath, "gitattributes filter %q: cannot tell the format of %s; set format", filter, target)
			return StripRule{}, false
		}
	}
	return r, true
}

func formatByExt(target string) manifest.Format {
	switch strings.ToLower(path.Ext(target)) {
	case ".json":
		return manifest.FormatJSON
	case ".jsonc":
		return manifest.FormatJSONC
	case ".toml":
		return manifest.FormatTOML
	}
	return ""
}

// applyStrip sets a strip rule on an entry.
func applyStrip(e *manifest.Entry, r StripRule) {
	e.Format = r.Format
	e.Keep = append([]string(nil), r.Keep...)
	e.Drop = append([]string(nil), r.Drop...)
	e.Volatile = append([]string(nil), r.Volatile...)
	e.Merge = r.Merge
}
