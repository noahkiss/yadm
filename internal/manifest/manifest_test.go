package manifest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
)

// fixtureFleet decodes the fixture fleet directly, so these tests do not
// depend on fleet.Parse.
func fixtureFleet(t *testing.T) *fleet.File {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixture.Dir(), "source", "fleet.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var f fleet.File
	if err := toml.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for id, m := range f.Machines {
		m.ID = id
		f.Machines[id] = m
	}
	return &f
}

func fixtureVocab(t *testing.T) cond.Vocabulary {
	f := fixtureFleet(t)
	v := f.Vocabulary()
	v.Enclaves = map[string]bool{}
	for _, e := range f.Enclaves() {
		v.Enclaves[string(e)] = true
	}
	return v
}

func ctxFor(t *testing.T, id model.MachineID) model.Context {
	t.Helper()
	m, ok := fixtureFleet(t).Machines[id]
	if !ok {
		t.Fatalf("no machine %s", id)
	}
	return model.Context{Machine: m, Home: "/test/home", User: "user"}
}

// fixtureTree lists the fixture source tree as it looks once sealed: the
// plaintext files under source/, plus sealed/<enclave>/<target> for every
// enclave-plain input.
func fixtureTree(t *testing.T) []model.SourcePath {
	t.Helper()
	var out []model.SourcePath
	walk := func(root, prefix string) {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			out = append(out, model.SourcePath(prefix+filepath.ToSlash(rel)))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	walk(filepath.Join(fixture.Dir(), "source"), "")
	walk(filepath.Join(fixture.Dir(), "enclave-plain"), "sealed/")
	return out
}

func fixtureManifest(t *testing.T) *Manifest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixture.Dir(), "source", FileName))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseFixture(t *testing.T) {
	m := fixtureManifest(t)
	if m.Defaults.Quiet.D() != 2*time.Hour {
		t.Errorf("quiet: %v", m.Defaults.Quiet)
	}
	if got := m.Tasks["first-setup"].Timeout.D(); got != DefaultTaskTimeout {
		t.Errorf("default task timeout: %v", got)
	}
	if got := m.Tasks["package-bundle"].Timeout.D(); got != 10*time.Minute {
		t.Errorf("task timeout: %v", got)
	}
	if got := m.Checks["no-private-keys"].Timeout.D(); got != 20*time.Second {
		t.Errorf("check timeout: %v", got)
	}
	if err := m.Validate(fixtureVocab(t)); err != nil {
		t.Errorf("validate: %v", err)
	}
}

func TestParseDefaults(t *testing.T) {
	m, err := Parse([]byte("schema = 1\n[checks.c]\ncommand = [\"x\"]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Defaults.Quiet.D() != DefaultQuiet || m.Checks["c"].Timeout.D() != DefaultCheckTimeout {
		t.Errorf("defaults not filled: %+v %+v", m.Defaults, m.Checks["c"])
	}
	m, err = Parse([]byte("schema = 1\n[defaults]\nquiet = \"0s\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Defaults.Quiet != 0 {
		t.Errorf("explicit 0s quiet overwritten: %v", m.Defaults.Quiet)
	}
	q := model.Duration(5 * time.Second)
	if m.Quiet(Entry{Quiet: &q}) != q || m.Quiet(Entry{}) != 0 {
		t.Error("Quiet override")
	}
}

func TestParseErrors(t *testing.T) {
	const head = "schema = 1\n"
	cases := []struct{ name, src, msg string }{
		{"unknown top key", head + "colour = 1\n", "colour"},
		{"unknown entry key", head + "[[file]]\ntarget = \"a\"\ntempalte = true\n", "tempalte"},
		{"unknown task key", head + "[tasks.x]\ncommand = [\"a\"]\nonn = []\n", "onn"},
		{"schema", "schema = 2\n", "want 1"},
		{"no schema", "", "want 1"},
		{"bad toml", "schema = \n", FileName},
		{"absolute target", head + "[[file]]\ntarget = \"/etc/passwd\"\n", "must be relative"},
		{"dotdot target", head + "[[file]]\ntarget = \"../outside\"\n", `".." segment`},
		{"empty segment", head + "[[file]]\ntarget = \"a//b\"\n", "empty"},
		{"empty target", head + "[[file]]\nwhen = \"true\"\n", "empty path"},
		{"dotdot source", head + "[[file]]\ntarget = \"a\"\nsource = \"files/../fleet.toml\"\n", `".." segment`},
		{"source outside files", head + "[[file]]\ntarget = \"a\"\nsource = \"keys/x\"\n", "reads from files/"},
		{"plaintext from sealed", head + "[[file]]\ntarget = \"a\"\nsource = \"sealed/personal/a\"\n", "reads from files/"},
		{"enclave from files", head + "[[file]]\ntarget = \"a\"\nenclave = \"personal\"\nsource = \"files/a\"\n", "reads from sealed/personal/"},
		{"enclave from other enclave", head + "[[file]]\ntarget = \"a\"\nenclave = \"personal\"\nsource = \"sealed/client/a\"\n", "reads from sealed/personal/"},
		{"bad enclave name", head + "[[file]]\ntarget = \"a\"\nenclave = \"a/b\"\n", "bad enclave name"},
		{"glob source", head + "[[file]]\ntarget = \"a/**\"\nsource = \"files/b/*\"\n", "never a glob"},
		{"bad glob", head + "[[file]]\ntarget = \"a/[x\"\n", "syntax error"},
		{"partial doublestar", head + "[[file]]\ntarget = \"a/b**\"\n", "whole segment"},
		{"unknown format", head + "[[file]]\ntarget = \"a\"\nformat = \"yaml\"\n", `unknown format "yaml"`},
		{"keep without format", head + "[[file]]\ntarget = \"a\"\nkeep = [\"x\"]\n", "need format"},
		{"seal without format", head + "[[file]]\ntarget = \"a\"\nseal = { x = \"personal\" }\n", "need format"},
		{"regions with json", head + "[[file]]\ntarget = \"a\"\nformat = \"json\"\nregions = true\n", "regions need a text file"},
		{"text without regions", head + "[[file]]\ntarget = \"a\"\nformat = \"text\"\n", "set regions = true"},
		{"enclave with regions", head + "[[file]]\ntarget = \"a\"\nenclave = \"personal\"\nregions = true\n", "needs no seal or regions"},
		{"bad mode", head + "[[file]]\ntarget = \"a\"\nmode = 600\n", "only permission bits"},
		{"setuid mode", head + "[[file]]\ntarget = \"a\"\nmode = 0o4755\n", "only permission bits"},
		{"negative quiet", head + "[[file]]\ntarget = \"a\"\nquiet = \"-1s\"\n", "negative quiet"},
		{"bad duration", head + "[defaults]\nquiet = \"soon\"\n", FileName},
		{"unit kind", head + "[[file]]\ntarget = \"a\"\n[[unit]]\ntarget = \"a\"\nkind = \"initd\"\n", "unknown unit kind"},
		{"unit orphan", head + "[[unit]]\ntarget = \"a\"\nkind = \"launchd\"\n", "no [[file]] entry"},
		{"unit glob", head + "[[file]]\ntarget = \"a/**\"\n[[unit]]\ntarget = \"a/*\"\nkind = \"launchd\"\n", "not a glob"},
		{"root glob", head + "[[root]]\npath = \".config/*\"\n", "not a glob"},
		{"root absolute", head + "[[root]]\npath = \"/etc\"\n", "must be relative"},
		{"task no command", head + "[tasks.x]\non = [\"a\"]\n", "command is empty"},
		{"task bad on", head + "[tasks.x]\non = [\"[\"]\ncommand = [\"a\"]\n", "syntax error"},
		{"check no command", head + "[checks.x]\npaths = [\"**\"]\n", "command is empty"},
		{"protected abs", head + "protected = [\"/x\"]\n", "must be relative"},
	}
	for _, tc := range cases {
		_, err := Parse([]byte(tc.src))
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: got %v, want error containing %q", tc.name, err, tc.msg)
		}
	}
}

func TestParseReportsEveryProblem(t *testing.T) {
	_, err := Parse([]byte("schema = 1\n[[file]]\ntarget = \"/a\"\n[[file]]\ntarget = \"b\"\nformat = \"ini\"\n"))
	if err == nil || !strings.Contains(err.Error(), "file[0]") || !strings.Contains(err.Error(), "file[1]") {
		t.Errorf("want both entries reported, got %v", err)
	}
}

func TestResolveFixture(t *testing.T) {
	m := fixtureManifest(t)
	tree := fixtureTree(t)
	v := fixtureVocab(t)
	shared := map[model.Target]model.SourcePath{
		".config/shell/aliases.sh":     "files/.config/shell/aliases.sh",
		".config/packages/list":        "files/.config/packages/list",
		".gitconfig":                   "files/.gitconfig.tmpl",
		".config/editor/settings.json": "files/.config/editor/settings.json",
		".ssh/config":                  "files/.ssh/config",
	}
	cases := []struct {
		id    model.MachineID
		extra map[model.Target]model.SourcePath
		unit  model.Target
		kind  UnitKind
		tasks []string
	}{
		{fixture.HostA, map[model.Target]model.SourcePath{
			".config/shell/os.sh":                            "files/.config/shell/os-darwin.sh",
			".config/notes/private.md":                       "sealed/personal/.config/notes/private.md",
			"Library/LaunchAgents/example.sync-helper.plist": "files/Library/LaunchAgents/example.sync-helper.plist",
		}, "Library/LaunchAgents/example.sync-helper.plist", UnitLaunchd, []string{"first-setup", "package-bundle"}},
		{fixture.HostB, map[model.Target]model.SourcePath{
			".config/shell/os.sh":                            "files/.config/shell/os-darwin.sh",
			".config/work/proxy.conf":                        "files/.config/work/proxy.conf",
			"Library/LaunchAgents/example.sync-helper.plist": "files/Library/LaunchAgents/example.sync-helper.plist",
		}, "Library/LaunchAgents/example.sync-helper.plist", UnitLaunchd, []string{"cleanup-cache", "first-setup", "package-bundle"}},
		{fixture.HostC, map[model.Target]model.SourcePath{
			".config/shell/os.sh":                      "files/.config/shell/os-linux.sh",
			".config/work/proxy.conf":                  "files/.config/work/proxy.conf",
			".config/client-tool/token":                "sealed/client/.config/client-tool/token",
			".config/systemd/user/sync-helper.service": "files/.config/systemd/user/sync-helper.service",
		}, ".config/systemd/user/sync-helper.service", UnitSystemd, []string{"cleanup-cache", "first-setup", "package-bundle"}},
	}
	for _, tc := range cases {
		p, err := m.Resolve(ctxFor(t, tc.id), tree, v)
		if err != nil {
			t.Fatalf("%s: %v", tc.id, err)
		}
		want := map[model.Target]model.SourcePath{}
		for k, s := range shared {
			want[k] = s
		}
		for k, s := range tc.extra {
			want[k] = s
		}
		got := map[model.Target]model.SourcePath{}
		units := 0
		for k, r := range p.Targets {
			got[k] = r.Source
			if r.Target != k || m.Entries[r.Index].Target != r.Entry.Target {
				t.Errorf("%s: %s: inconsistent Resolved %+v", tc.id, k, r)
			}
			if r.Unit != nil {
				units++
				if k != tc.unit || r.Unit.Kind != tc.kind {
					t.Errorf("%s: unit on %s kind %s", tc.id, k, r.Unit.Kind)
				}
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: targets\n got %v\nwant %v", tc.id, got, want)
		}
		if units != 1 {
			t.Errorf("%s: %d units attached", tc.id, units)
		}
		var tasks []string
		for k := range p.Tasks {
			tasks = append(tasks, k)
		}
		sort.Strings(tasks)
		if !reflect.DeepEqual(tasks, tc.tasks) {
			t.Errorf("%s: tasks %v, want %v", tc.id, tasks, tc.tasks)
		}
		if len(p.Checks) != 1 || len(p.Roots) != 1 {
			t.Errorf("%s: checks %d roots %d", tc.id, len(p.Checks), len(p.Roots))
		}
	}
}

// TestResolveCollisions follows design.md section 4: two applying entries
// for one target fail, whatever their kind or order. Stock yadm broke ties
// by order instead (first non-template, last template); the importer must
// produce mutually exclusive conditions to reproduce that.
func TestResolveCollisions(t *testing.T) {
	src := `schema = 1
[[file]]
target = ".b"
source = "files/b1"
[[file]]
target = ".b"
source = "files/b2.tmpl"
template = true
when = "os:linux"
[[file]]
target = ".a"
[[file]]
target = ".a"
source = "files/a2"
template = true
[[file]]
target = ".config/tool/**"
[[file]]
target = ".config/tool/x.json"
format = "json"
keep = ["k"]
[[file]]
target = ".c"
source = "files/c-darwin"
when = "os:darwin"
[[file]]
target = ".c"
source = "files/c-linux"
when = "os:linux"
`
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	tree := []model.SourcePath{"files/.a", "files/a2", "files/b1", "files/b2.tmpl", "files/.config/tool/x.json", "files/c-darwin", "files/c-linux"}
	ctx := model.Context{Machine: model.Machine{Name: "h", OS: "linux"}}
	_, err = m.Resolve(ctx, tree, cond.Vocabulary{})
	var ce *CollisionError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CollisionError, got %v", err)
	}
	want := []Collision{{".a", []int{2, 3}}, {".b", []int{0, 1}}, {".config/tool/x.json", []int{4, 5}}}
	if !reflect.DeepEqual(ce.Collisions, want) {
		t.Errorf("collisions\n got %+v\nwant %+v", ce.Collisions, want)
	}
	// On darwin only .a and the glob collide; .b and .c have one applying entry each.
	ctx.Machine.OS = "darwin"
	_, err = m.Resolve(ctx, tree, cond.Vocabulary{})
	if !errors.As(err, &ce) || len(ce.Collisions) != 2 {
		t.Errorf("darwin: %v", err)
	}
}

func TestResolveChecksEveryCondition(t *testing.T) {
	v := fixtureVocab(t)
	ctx := ctxFor(t, fixture.HostA)
	cases := []struct{ name, src, msg string }{
		{"typo in non-applying entry", "[[file]]\ntarget = \"a\"\nwhen = \"os:linux & type:wrok\"\n", `unknown type "wrok"`},
		{"unknown fact", "[[file]]\ntarget = \"a\"\nwhen = \"fact:colour\"\n", `unknown fact "colour"`},
		{"unit when", "[[file]]\ntarget = \"a\"\n[[unit]]\ntarget = \"a\"\nkind = \"systemd\"\nwhen = \"bogus\"\n", "unit[0]"},
		{"root when", "[[root]]\npath = \"a\"\nwhen = \"type:nope\"\n", "root[0]"},
		{"task when", "[tasks.t]\ncommand = [\"x\"]\nwhen = \"observed:nope=x\"\n", "tasks.t"},
		{"check when", "[checks.c]\ncommand = [\"x\"]\nwhen = \"(\"\n", "checks.c"},
		{"unknown enclave", "[[file]]\ntarget = \"a\"\nenclave = \"secret\"\nwhen = \"false\"\n", `unknown enclave "secret"`},
		{"plain type as enclave", "[[file]]\ntarget = \"a\"\nenclave = \"work\"\n", `"work" is not an enclave`},
		{"seal to unknown", "[[file]]\ntarget = \"a.json\"\nformat = \"json\"\nseal = { k = \"nobody\" }\n", `unknown enclave "nobody"`},
		{"root enclave", "[[root]]\npath = \"a\"\nenclave = \"nobody\"\n", `unknown enclave "nobody"`},
	}
	for _, tc := range cases {
		m, err := Parse([]byte("schema = 1\n" + tc.src))
		if err != nil {
			t.Fatalf("%s: parse: %v", tc.name, err)
		}
		_, err = m.Resolve(ctx, nil, v)
		if err == nil || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: got %v, want %q", tc.name, err, tc.msg)
		}
	}
}

func TestResolveGlobs(t *testing.T) {
	src := `schema = 1
[[file]]
target = ".config/tool/**"
when = "os:linux"
[[file]]
target = ".config/tool/**"
source = "files/tool-darwin"
when = "os:darwin"
[[file]]
target = ".local/bin/*"
[[file]]
target = ".config/vault/**"
enclave = "personal"
`
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	tree := []model.SourcePath{
		"files/.config/tool/a.conf", "files/.config/tool/sub/b.conf", "files/.config/toolbox/c",
		"files/tool-darwin/a.conf", "files/tool-darwin/d/e",
		"files/.local/bin/run", "files/.local/bin/sub/nested",
		"sealed/personal/.config/vault/key", "files/.config/vault/decoy",
	}
	v := cond.Vocabulary{Types: map[string]bool{"personal": true}}
	want := map[string]map[model.Target]model.SourcePath{
		"linux": {
			".config/tool/a.conf":     "files/.config/tool/a.conf",
			".config/tool/sub/b.conf": "files/.config/tool/sub/b.conf",
			".local/bin/run":          "files/.local/bin/run",
			".config/vault/key":       "sealed/personal/.config/vault/key",
		},
		"darwin": {
			".config/tool/a.conf": "files/tool-darwin/a.conf",
			".config/tool/d/e":    "files/tool-darwin/d/e",
			".local/bin/run":      "files/.local/bin/run",
			".config/vault/key":   "sealed/personal/.config/vault/key",
		},
	}
	for osName, w := range want {
		p, err := m.Resolve(model.Context{Machine: model.Machine{OS: osName}}, tree, v)
		if err != nil {
			t.Fatal(err)
		}
		got := map[model.Target]model.SourcePath{}
		for k, r := range p.Targets {
			got[k] = r.Source
		}
		if !reflect.DeepEqual(got, w) {
			t.Errorf("%s:\n got %v\nwant %v", osName, got, w)
		}
	}
}

func TestResolveMissingSource(t *testing.T) {
	m, err := Parse([]byte("schema = 1\n[[file]]\ntarget = \".a\"\n[[file]]\ntarget = \".b\"\nwhen = \"false\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Resolve(model.Context{}, []model.SourcePath{"files/other"}, cond.Vocabulary{}); err == nil || !strings.Contains(err.Error(), "files/.a is not in the source tree") {
		t.Errorf("got %v", err)
	}
	p, err := m.Resolve(model.Context{}, nil, cond.Vocabulary{})
	if err != nil || p.Targets[".a"].Source != "files/.a" {
		t.Errorf("nil tree must skip the existence check: %v %+v", err, p)
	}
}

func TestWhy(t *testing.T) {
	src := `schema = 1
protected = [".config/secret-tool/**"]
[[file]]
target = ".config/shell/os.sh"
source = "files/os-darwin.sh"
when = "os:darwin"
[[file]]
target = ".config/shell/os.sh"
source = "files/os-linux.sh"
when = "os:linux"
[[file]]
target = ".config/work/**"
when = "type:work"
[[file]]
target = ".config/tool/**"
[[file]]
target = ".reviewed"
review = true
[[root]]
path = ".config"
[[root]]
path = ".config/shell"
[[root]]
path = ".config/work"
when = "type:work"
`
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	tree := []model.SourcePath{"files/os-darwin.sh", "files/os-linux.sh", "files/.config/work/proxy.conf", "files/.config/tool/a", "files/.reviewed"}
	v := cond.Vocabulary{Types: map[string]bool{"work": true}}
	p, err := m.Resolve(model.Context{Machine: model.Machine{OS: "darwin"}}, tree, v)
	if err != nil {
		t.Fatal(err)
	}

	x, err := p.Why(".config/shell/os.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !x.Managed || x.Resolved.Index != 0 || len(x.Rejected) != 1 || x.Rejected[0].Index != 1 ||
		!strings.Contains(x.Rejected[0].Reason, `"os:linux" is false`) || x.InRoot == nil || x.InRoot.Path != ".config/shell" || x.Protected {
		t.Errorf("os.sh: %+v", x)
	}

	x, _ = p.Why(".config/work/proxy.conf")
	if x.Managed || len(x.Rejected) != 1 || x.Rejected[0].When != "type:work" || x.InRoot.Path != ".config" {
		t.Errorf("proxy.conf: %+v", x)
	}

	x, _ = p.Why(".config/tool/b")
	if x.Managed || len(x.Rejected) != 1 || !strings.Contains(x.Rejected[0].Reason, "files/.config/tool/b") {
		t.Errorf("tool/b: %+v", x)
	}

	x, _ = p.Why(".config/secret-tool/x")
	if !x.Protected || x.Managed {
		t.Errorf("protected glob: %+v", x)
	}
	x, _ = p.Why(".reviewed")
	if !x.Protected || !x.Managed {
		t.Errorf("review entry: %+v", x)
	}
	x, _ = p.Why("manifest.toml")
	if !x.Protected || x.InRoot != nil {
		t.Errorf("builtin: %+v", x)
	}
	x, _ = p.Why(".unrelated")
	if x.Managed || x.Protected || x.InRoot != nil || len(x.Rejected) != 0 {
		t.Errorf("unrelated: %+v", x)
	}
	for _, bad := range []model.Target{"", "/abs", "../x", ".config/*"} {
		if _, err := p.Why(bad); err == nil {
			t.Errorf("Why(%q) accepted", bad)
		}
	}
}

func TestFileMode(t *testing.T) {
	cases := []struct {
		e    Entry
		exec bool
		want fs.FileMode
	}{
		{Entry{}, false, 0o644},
		{Entry{}, true, 0o755},
		{Entry{Enclave: "personal"}, true, 0o600},
		{Entry{Mode: 0o640}, true, 0o640},
		{Entry{Mode: 0o700, Enclave: "personal"}, false, 0o700},
	}
	for _, tc := range cases {
		if got := (Resolved{Entry: tc.e}).FileMode(tc.exec); got != tc.want {
			t.Errorf("%+v exec=%v: %#o, want %#o", tc.e, tc.exec, got, tc.want)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"**", "a", true},
		{"**", "a/b/c", true},
		{"a/**", "a/b", true},
		{"a/**", "a", true},
		{"a/**", "ab/c", false},
		{"a/**/z", "a/z", true},
		{"a/**/z", "a/b/c/z", true},
		{"a/**/z", "a/b/c/y", false},
		{"a/*", "a/b", true},
		{"a/*", "a/b/c", false},
		{"*.json", "x.json", true},
		{"*.json", "d/x.json", false},
		{"**/*.json", "d/e/x.json", true},
		{".config/work/**", ".config/work/proxy.conf", true},
		{"a/[bc]", "a/c", true},
		{"a/[", "a/[", false},
		{"keys/**", "keys/personal/1.toml", true},
	}
	for _, tc := range cases {
		if got := Match(tc.pat, tc.name); got != tc.want {
			t.Errorf("Match(%q, %q) = %v", tc.pat, tc.name, got)
		}
	}
}

// TestFixtureVocabularyEnclavesOptional: without an enclave set, a plain type
// named as an enclave passes Resolve; fleet has to supply the set.
func TestFixtureVocabularyEnclavesOptional(t *testing.T) {
	m, err := Parse([]byte("schema = 1\n[[file]]\ntarget = \"a\"\nenclave = \"work\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	v := fixtureVocab(t)
	v.Enclaves = nil
	if _, err := m.Resolve(ctxFor(t, fixture.HostB), nil, v); err != nil {
		t.Errorf("nil Enclaves must skip the check: %v", err)
	}
}
