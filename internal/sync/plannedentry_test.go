package sync

import (
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// TestPlannedEntry: a staged target's entry is the one that produces it
// from its source, as written, whether or not its when holds here; a file
// in an owned root gets the root's when and enclave; anything else has none.
func TestPlannedEntry(t *testing.T) {
	m, err := manifest.Parse([]byte(`schema = 1

[[file]]
target = ".config/app/conf"
source = "files/.config/app/conf-a"
when = "os:darwin"

[[file]]
target = ".config/app/conf"
source = "files/.config/app/conf-b"
when = "os:linux"

[[file]]
target = ".config/globbed/*"
enclave = "personal"

[[root]]
path = ".config/tool"
when = "type:work"

[[root]]
path = ".config/tool/inner"
enclave = "client"
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		target model.Target
		source model.SourcePath
		want   *extexec.Entry
	}{
		{".config/app/conf", "files/.config/app/conf-b", &extexec.Entry{Target: ".config/app/conf", Source: "files/.config/app/conf-b", When: "os:linux"}},
		{".config/globbed/new", "sealed/personal/.config/globbed/new", &extexec.Entry{Target: ".config/globbed/*", Source: "sealed/personal/.config/globbed/new", Enclave: "personal"}},
		{".config/tool/x", "files/.config/tool/x", &extexec.Entry{Target: ".config/tool", Source: "files/.config/tool/x", When: "type:work", Root: true}},
		{".config/tool/inner/y", "sealed/client/.config/tool/inner/y", &extexec.Entry{Target: ".config/tool/inner", Source: "sealed/client/.config/tool/inner/y", Enclave: "client", Root: true}},
		{".config/tool/inner/plain", "files/.config/tool/inner/plain", nil}, // not the root's source: no claim of its enclave
		{".other", "files/.other", nil},
	} {
		got := plannedEntry(m, c.target, c.source)
		switch {
		case got == nil && c.want == nil:
		case got == nil || c.want == nil || *got != *c.want:
			t.Errorf("plannedEntry(%s, %s) = %+v, want %+v", c.target, c.source, got, c.want)
		}
	}
	if plannedEntry(nil, ".x", "files/.x") != nil {
		t.Error("no manifest gave an entry")
	}
}
