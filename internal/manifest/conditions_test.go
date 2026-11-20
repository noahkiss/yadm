package manifest

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

const namedManifest = `schema = 1

[conditions]
include = ["conditions/agents.toml"]
gui = "os:darwin"
desk.gui = "cond:gui & type:work"
"desk.any" = "cond:desk.gui | cond:agents.on"

[[file]]
target = ".config/tool/a.conf"
source = "files/a-desk.conf"
when = "cond:desk.gui"

[[file]]
target = ".config/tool/a.conf"
source = "files/a-other.conf"
when = "!cond:desk.gui"

[tasks.t]
command = ["x"]
when = "cond:agents.on"
`

const agentsInclude = `# other tables in an included file are ignored
[agents]
anything = 1

[conditions]
agents.on = "type:personal | fact:proxy"
`

func readMap(files map[string]string) func(model.SourcePath) ([]byte, error) {
	return func(p model.SourcePath) ([]byte, error) {
		b, ok := files[string(p)]
		if !ok {
			return nil, fs.ErrNotExist
		}
		return []byte(b), nil
	}
}

func TestNamedConditionsResolve(t *testing.T) {
	m, err := Parse([]byte(namedManifest))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Includes(); len(got) != 1 || got[0] != "conditions/agents.toml" {
		t.Fatalf("Includes = %q", got)
	}
	v := fixtureVocab(t)
	tree := []model.SourcePath{"files/a-desk.conf", "files/a-other.conf"}
	// Resolving before the includes are loaded fails loudly.
	if _, err := m.Resolve(ctxFor(t, "m-d4e5f6"), tree, v); err == nil || !strings.Contains(err.Error(), "conditions.include is not loaded") {
		t.Fatalf("resolve before load: %v", err)
	}
	if err := m.LoadIncludes(readMap(map[string]string{"conditions/agents.toml": agentsInclude})); err != nil {
		t.Fatal(err)
	}
	if n := len(m.Definitions()); n != 4 {
		t.Errorf("%d definitions, want 4", n)
	}
	// host-b: darwin + work -> desk.gui; it has fact proxy -> agents.on.
	p, err := m.Resolve(ctxFor(t, "m-d4e5f6"), tree, v)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Targets[".config/tool/a.conf"].Source; got != "files/a-desk.conf" {
		t.Errorf("host-b source = %s", got)
	}
	if _, ok := p.Tasks["t"]; !ok {
		t.Error("host-b: task t not selected")
	}
	ex, err := p.Why(".config/tool/a.conf")
	if err != nil {
		t.Fatal(err)
	}
	if ex.WhenExpanded != "os:darwin & type:work" {
		t.Errorf("WhenExpanded = %q", ex.WhenExpanded)
	}
	if len(ex.Rejected) != 1 || ex.Rejected[0].Expanded != "!(os:darwin & type:work)" {
		t.Errorf("Rejected = %+v", ex.Rejected)
	}
	// host-c: linux -> not desk.gui.
	p, err = m.Resolve(ctxFor(t, "m-g7h8i9"), tree, v)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Targets[".config/tool/a.conf"].Source; got != "files/a-other.conf" {
		t.Errorf("host-c source = %s", got)
	}
	if _, ok := p.Tasks["t"]; ok {
		t.Error("host-c: task t selected")
	}
	// A plain manifest's why carries no expansion.
	fm := fixtureManifest(t)
	fp, err := fm.Resolve(ctxFor(t, "m-a1b2c3"), fixtureTree(t), v)
	if err != nil {
		t.Fatal(err)
	}
	for tg := range fp.Targets {
		if ex, _ := fp.Why(tg); ex.WhenExpanded != "" {
			t.Errorf("%s: unexpected expansion %q", tg, ex.WhenExpanded)
		}
	}
}

func TestNamedConditionsErrors(t *testing.T) {
	const head = "schema = 1\n"
	parseCases := []struct{ name, src, msg string }{
		{"include not a list", head + "[conditions]\ninclude = \"x.toml\"\n", "conditions.include: want a list"},
		{"include glob", head + "[conditions]\ninclude = [\"c/*.toml\"]\n", "not a glob"},
		{"include sealed", head + "[conditions]\ninclude = [\"sealed/personal/c.toml\"]\n", "sealed/ or keys/"},
		{"include self", head + "[conditions]\ninclude = [\"manifest.toml\"]\n", "include itself"},
		{"include twice", head + "[conditions]\ninclude = [\"c.toml\", \"c.toml\"]\n", "listed twice"},
		{"include unsafe", head + "[conditions]\ninclude = [\"../c.toml\"]\n", "segment"},
		{"not a string", head + "[conditions]\na = 1\n", "conditions.a: want a condition string"},
		{"defined twice", head + "[conditions]\n\"a.b\" = \"true\"\n[conditions.a]\nb = \"false\"\n", "conditions.a.b: defined twice"},
	}
	for _, c := range parseCases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.src))
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("err = %v, want %q", err, c.msg)
			}
		})
	}
	v := fixtureVocab(t)
	resolveCases := []struct {
		name, src string
		files     map[string]string
		msg       []string
	}{
		{"cycle across include", head + "[conditions]\ninclude = [\"c.toml\"]\na = \"cond:b\"\n",
			map[string]string{"c.toml": "[conditions]\nb = \"cond:a\"\n"}, []string{"cycle", "a -> b -> a", "c.toml: conditions.b"}},
		{"duplicate across include", head + "[conditions]\ninclude = [\"c.toml\"]\na = \"true\"\n",
			map[string]string{"c.toml": "[conditions]\na = \"false\"\n"}, []string{"c.toml: conditions.a: already defined in manifest.toml"}},
		{"unknown name", head + "[conditions]\na = \"cond:zz\"\n", nil, []string{"manifest.toml: conditions.a", `unknown condition "zz"`}},
		{"unknown in when", head + "[[file]]\ntarget = \"x\"\nwhen = \"cond:nope\"\n", nil, []string{`file[0] "x": when`, `unknown condition "nope"`}},
		{"bad term in include", head + "[conditions]\ninclude = [\"c.toml\"]\n",
			map[string]string{"c.toml": "[conditions]\nq = \"type:nope\"\n"}, []string{"c.toml: conditions.q", `unknown type "nope"`}},
	}
	for _, c := range resolveCases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse([]byte(c.src))
			if err != nil {
				t.Fatal(err)
			}
			if err := m.LoadIncludes(readMap(c.files)); err != nil {
				t.Fatal(err)
			}
			err = m.Validate(v)
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range c.msg {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err %q lacks %q", err, w)
				}
			}
		})
	}
	loadCases := []struct {
		name  string
		files map[string]string
		msg   string
	}{
		{"missing file", map[string]string{}, "conditions.include \"c.toml\""},
		{"no table", map[string]string{"c.toml": "x = 1\n"}, "c.toml: no [conditions] table"},
		{"nested include", map[string]string{"c.toml": "[conditions]\ninclude = [\"d.toml\"]\n"}, "cannot include another"},
		{"bad toml", map[string]string{"c.toml": "[conditions\n"}, "c.toml"},
	}
	for _, c := range loadCases {
		t.Run(c.name, func(t *testing.T) {
			m, err := Parse([]byte(head + "[conditions]\ninclude = [\"c.toml\"]\n"))
			if err != nil {
				t.Fatal(err)
			}
			err = m.LoadIncludes(readMap(c.files))
			if err == nil || !strings.Contains(err.Error(), c.msg) {
				t.Fatalf("err = %v, want %q", err, c.msg)
			}
			if c.name == "missing file" && !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("missing include does not wrap fs.ErrNotExist: %v", err)
			}
		})
	}
}
