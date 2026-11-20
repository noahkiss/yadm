package importer

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// tomlString writes a TOML basic string.
func tomlString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%q is not valid UTF-8", s)
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func tomlKey(s string) (string, error) {
	if bareKey.MatchString(s) {
		return s, nil
	}
	return tomlString(s)
}

// tomlWriter collects the first error so callers can write straight through.
type tomlWriter struct {
	b   strings.Builder
	err error
}

func (w *tomlWriter) raw(s string) { w.b.WriteString(s) }

func (w *tomlWriter) str(key, val string) {
	q, err := tomlString(val)
	if err != nil && w.err == nil {
		w.err = err
	}
	w.b.WriteString(key + " = " + q + "\n")
}

func (w *tomlWriter) key(k string) string {
	q, err := tomlKey(k)
	if err != nil && w.err == nil {
		w.err = err
	}
	return q
}

// encodeManifest writes manifest.toml and checks that it parses back to the
// same entries.
func encodeManifest(entries []manifest.Entry) ([]byte, error) {
	w := &tomlWriter{}
	w.raw(fmt.Sprintf("schema = %d\n", manifest.Schema))
	for _, e := range entries {
		w.raw("\n[[file]]\n")
		w.str("target", string(e.Target))
		if e.Source != defaultSource(e) {
			w.str("source", string(e.Source))
		}
		if e.When != "" {
			w.str("when", e.When)
		}
		if e.Enclave != "" {
			w.str("enclave", string(e.Enclave))
		}
		if e.Template {
			w.raw("template = true\n")
		}
		if e.Mode != 0 {
			w.raw(fmt.Sprintf("mode = 0o%o\n", uint32(e.Mode)))
		}
	}
	if w.err != nil {
		return nil, w.err
	}
	out := []byte(w.b.String())
	back, err := manifest.Parse(out)
	if err != nil {
		return nil, fmt.Errorf("generated manifest does not parse: %w", err)
	}
	if len(back.Entries) != len(entries) {
		return nil, fmt.Errorf("generated manifest has %d entries, want %d", len(back.Entries), len(entries))
	}
	for i := range entries {
		g, x := back.Entries[i], entries[i]
		if g.Source == "" {
			g.Source = defaultSource(g)
		}
		if g.Target != x.Target || g.Source != x.Source || g.When != x.When || g.Enclave != x.Enclave || g.Template != x.Template || g.Mode != x.Mode {
			return nil, fmt.Errorf("generated manifest entry %d does not round-trip", i)
		}
	}
	return out, nil
}

// defaultSource is the source an entry has when it names none.
func defaultSource(e manifest.Entry) model.SourcePath {
	if e.Enclave != "" {
		return model.SourcePath("sealed/" + string(e.Enclave) + "/" + string(e.Target))
	}
	return model.SourcePath("files/" + string(e.Target))
}

// encodeFleet writes fleet.toml and checks that it parses back.
func encodeFleet(f *fleet.File) ([]byte, error) {
	w := &tomlWriter{}
	w.raw(fmt.Sprintf("schema = %d\n", fleet.Schema))
	var types []string
	for t := range f.Types {
		types = append(types, string(t))
	}
	sort.Strings(types)
	for _, t := range types {
		w.raw("\n[types." + w.key(t) + "]\n")
		if f.Types[model.TypeName(t)].Enclave {
			w.raw("enclave = true\n")
		}
	}
	var ids []string
	for id := range f.Machines {
		ids = append(ids, string(id))
	}
	sort.Slice(ids, func(i, j int) bool {
		return f.Machines[model.MachineID(ids[i])].Name < f.Machines[model.MachineID(ids[j])].Name
	})
	for _, id := range ids {
		m := f.Machines[model.MachineID(id)]
		w.raw("\n[machines." + w.key(id) + "]\n")
		w.str("name", m.Name)
		var ts []string
		for _, t := range m.Types {
			q, err := tomlString(string(t))
			if err != nil && w.err == nil {
				w.err = err
			}
			ts = append(ts, q)
		}
		w.raw("types = [" + strings.Join(ts, ", ") + "]\n")
		if m.OS != "" {
			w.str("os", m.OS)
		}
		if m.Arch != "" {
			w.str("arch", m.Arch)
		}
		if len(m.Facts) > 0 {
			w.raw("\n[machines." + w.key(id) + ".facts]\n")
			var ks []string
			for k := range m.Facts {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			for _, k := range ks {
				w.str(w.key(k), m.Facts[k])
			}
		}
	}
	if w.err != nil {
		return nil, w.err
	}
	out := []byte(w.b.String())
	back, err := fleet.Parse(out)
	if err != nil {
		return nil, fmt.Errorf("generated fleet does not parse: %w", err)
	}
	if len(back.Machines) != len(f.Machines) || len(back.Types) != len(f.Types) {
		return nil, fmt.Errorf("generated fleet does not round-trip")
	}
	return out, nil
}
