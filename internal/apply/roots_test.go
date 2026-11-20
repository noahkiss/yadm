package apply

import (
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// TestExpandRootsLeavesNamedFilesAlone: root expansion adds an entry-less
// file only; whatever the manifest says about a file, applying here or not,
// decides it.
func TestExpandRootsLeavesNamedFilesAlone(t *testing.T) {
	plain := manifest.Root{Path: ".config/shell", Ignore: []string{"cache/**"}}
	sealed := manifest.Root{Path: ".config/private", Enclave: "personal"}
	cases := []struct {
		name    string
		entries []manifest.Entry
		tasks   map[string]manifest.TaskDef
		file    model.SourcePath
		want    model.Target // "" when nothing may be added
		enc     model.EnclaveName
	}{
		{name: "entry-less plain file", file: "files/.config/shell/new.sh", want: ".config/shell/new.sh"},
		{name: "entry-less sealed file", file: "sealed/personal/.config/private/new.md", want: ".config/private/new.md", enc: "personal"},
		{name: "literal entry, when false here",
			entries: []manifest.Entry{{Target: ".config/shell/work.sh", When: "type:work"}},
			file:    "files/.config/shell/work.sh"},
		{name: "glob entry, when false here",
			entries: []manifest.Entry{{Target: ".config/shell/work/**", When: "type:work"}},
			file:    "files/.config/shell/work/a.sh"},
		{name: "glob entry with a source directory",
			entries: []manifest.Entry{{Target: ".config/other/**", Source: "files/.config/shell/vendor", When: "type:work"}},
			file:    "files/.config/shell/vendor/x.sh"},
		{name: "explicit source of another target",
			entries: []manifest.Entry{{Target: ".config/shell/os.sh", Source: "files/.config/shell/os-linux.sh", When: "os:linux"}},
			file:    "files/.config/shell/os-linux.sh"},
		{name: "root ignore glob", file: "files/.config/shell/cache/x"},
		{name: "task output",
			tasks: map[string]manifest.TaskDef{"gen": {Command: []string{"gen"}, Outputs: []string{".config/shell/gen/**"}}},
			file:  "files/.config/shell/gen/out.sh"},
		{name: "sealed source under a plain root", file: "sealed/personal/.config/shell/x.sh"},
		{name: "plain source under an enclave root", file: "files/.config/private/x.md"},
		{name: "outside every root", file: "files/.config/elsewhere/x"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			man := &manifest.Manifest{Schema: 1, Entries: c.entries, Roots: []manifest.Root{plain, sealed}, Tasks: c.tasks}
			plan := &manifest.Plan{Targets: map[model.Target]manifest.Resolved{}, Roots: []manifest.Root{plain, sealed}}
			ExpandRoots(man, plan, []model.SourcePath{c.file}, nil)
			if c.want == "" {
				if len(plan.Targets) != 0 {
					t.Fatalf("added %v", plan.Targets)
				}
				return
			}
			r, ok := plan.Targets[c.want]
			if !ok || len(plan.Targets) != 1 {
				t.Fatalf("targets %v, want %s", plan.Targets, c.want)
			}
			if r.Source != c.file || r.Entry.Enclave != c.enc || r.Index != RootIndex {
				t.Errorf("resolved %+v", r)
			}
		})
	}
}
