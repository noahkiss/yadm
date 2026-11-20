package importer

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

const stripAttrs = ".config/notes/** filter=crypt diff=crypt merge=crypt\n" +
	".config/app/settings.json filter=strip-runtime\n" +
	".config/notes/tool.toml##class.personal filter=crypt-strip diff=crypt merge=crypt\n"

var stripExtra = map[string]string{
	".gitattributes":                          stripAttrs,
	".config/app/settings.json":               "{\n  \"theme\": \"dark\"\n}\n",
	".config/notes/tool.toml##class.personal": "model = \"m-1\"\n\n[tui]\nmode = \"@@CANARY@@\"\n",
}

const stripFilters = `
[filters.strip-runtime.paths.".config/app/settings.json"]
drop = ["model", "lastVersion"]
volatile = ["window.size"]

[filters.crypt-strip]
crypt = true
[filters.crypt-strip.paths.".config/notes/*.toml"]
format = "toml"
keep = ["model", "tui"]
drop = ["tui.nux"]
merge = "toml-keys"
`

func entryFor(t *testing.T, conv *converted, target string) manifest.Entry {
	t.Helper()
	m, err := manifest.Parse(conv.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if string(e.Target) == target {
			return e
		}
	}
	t.Fatalf("no entry for %s", target)
	return manifest.Entry{}
}

// TestImportStripFilters: a strip filter becomes the entry's format, keep,
// drop, volatile and merge fields; a strip filter that also runs transcrypt
// is decrypted and sealed, and its plaintext reaches neither files/ nor the
// output's object store.
func TestImportStripFilters(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, stripExtra)
	filters, err := ParseFilters([]byte(stripFilters))
	if err != nil {
		t.Fatal(err)
	}
	opts := testOptions(lf, filepath.Join(t.TempDir(), "source"), newFakeSealer())
	opts.Filters = filters
	conv, err := convert(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(conv.Problems) > 0 {
		t.Fatalf("problems: %v", conv.Problems)
	}
	plain := entryFor(t, conv, ".config/app/settings.json")
	if plain.Format != manifest.FormatJSON || !reflect.DeepEqual(plain.Drop, []string{"model", "lastVersion"}) ||
		!reflect.DeepEqual(plain.Volatile, []string{"window.size"}) || plain.Keep != nil || plain.Enclave != "" {
		t.Fatalf("strip-runtime entry: %+v", plain)
	}
	sealed := entryFor(t, conv, ".config/notes/tool.toml")
	if sealed.Format != manifest.FormatTOML || sealed.Enclave != "personal" || sealed.Merge != manifest.MergeTOMLKeys ||
		!reflect.DeepEqual(sealed.Keep, []string{"model", "tui"}) || !reflect.DeepEqual(sealed.Drop, []string{"tui.nux"}) {
		t.Fatalf("crypt-strip entry: %+v", sealed)
	}
	if src := defaultSource(sealed); conv.Files[src].Data == nil || sealed.Source != "" {
		t.Fatalf("crypt-strip source %s not sealed", src)
	}
	for p, f := range conv.Files {
		if strings.HasPrefix(string(p), "files/") && strings.Contains(string(f.Data), lf.Canary.String()) {
			t.Fatalf("plaintext in %s", p)
		}
	}

	out := filepath.Join(t.TempDir(), "source")
	opts.Output = out
	if _, err := Import(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	secrecytest.AssertRepoClean(t, out, lf.Canary)
}

// TestImportStripFilterProblems: a filter is never lost silently.
func TestImportStripFilterProblems(t *testing.T) {
	hermetic(t)
	cases := map[string]struct {
		filters string
		path    string
		reason  string
	}{
		"unmapped filter": {
			filters: `[filters.crypt-strip]
crypt = true
[filters.crypt-strip.paths.".config/notes/tool.toml"]
format = "toml"
keep = ["model"]
`,
			path: ".config/app/settings.json", reason: `filter "strip-runtime" has no mapping`,
		},
		"no path rule": {
			filters: `[filters.strip-runtime.paths.".config/other.json"]
drop = ["x"]
[filters.crypt-strip]
crypt = true
[filters.crypt-strip.paths.".config/notes/tool.toml"]
keep = ["model"]
`,
			path: ".config/app/settings.json", reason: "no rule for .config/app/settings.json",
		},
		"crypt filter not marked crypt": {
			filters: `[filters.strip-runtime.paths.".config/app/settings.json"]
drop = ["x"]
[filters.crypt-strip.paths.".config/notes/tool.toml"]
keep = ["model"]
`,
			path: ".config/notes/tool.toml##class.personal", reason: "not marked with a transcrypt filter",
		},
	}
	lf := buildLegacy(t, stripExtra)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			filters, err := ParseFilters([]byte(c.filters))
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "source")
			opts := testOptions(lf, out, newFakeSealer())
			opts.Filters = filters
			rep, err := Import(context.Background(), opts)
			if err == nil {
				t.Fatal("import succeeded")
			}
			found := false
			for _, p := range rep.Problems {
				if p.Path == c.path && strings.Contains(p.Reason, c.reason) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want %s: %s, got %v", c.path, c.reason, rep.Problems)
			}
			if rep.Commit != "" {
				t.Fatal("a failed import committed")
			}
		})
	}
	// Without any filters file, the strip filter fails too.
	opts := testOptions(lf, filepath.Join(t.TempDir(), "source"), newFakeSealer())
	if rep, err := Import(context.Background(), opts); err == nil || len(rep.Problems) == 0 {
		t.Fatal("an unmapped strip filter was dropped silently")
	}
}

func TestParseFiltersRejects(t *testing.T) {
	for name, in := range map[string]string{
		"unknown field":  "[filters.x]\nstrip = true\n",
		"bad format":     "[filters.x.paths.\"a.yaml\"]\nformat = \"yaml\"\ndrop = [\"k\"]\n",
		"crypt reserved": "[filters.crypt]\ncrypt = true\n",
		"unsafe path":    "[filters.x.paths.\"../a.json\"]\ndrop = [\"k\"]\n",
	} {
		if _, err := ParseFilters([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
