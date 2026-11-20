package cond

import (
	"slices"
	"strings"
	"testing"
)

func TestNamedConditions(t *testing.T) {
	defs := []Definition{
		{Name: "gui", Src: "os:darwin | fact:editor=editor-one", File: "manifest.toml"},
		{Name: "desk.gui", Src: "cond:gui & !type:client", File: "conditions/extra.toml"},
		{Name: "pkg", Src: "observed:packages=tool-one", File: "manifest.toml"},
	}
	named, err := Define(defs, vocab())
	if err != nil {
		t.Fatal(err)
	}
	v := vocab()
	v.Conditions = named
	x, err := Parse("cond:desk.gui & cond:pkg", v)
	if err != nil {
		t.Fatal(err)
	}
	if got := x.String(); got != "cond:desk.gui & cond:pkg" {
		t.Errorf("String = %q", got)
	}
	if got, want := Expand(x), "(os:darwin | fact:editor=editor-one) & !type:client & observed:packages=tool-one"; got != want {
		t.Errorf("Expand = %q, want %q", got, want)
	}
	if !x.Eval(hostA()) || x.Eval(hostC()) {
		t.Errorf("eval: host-a %v host-c %v", x.Eval(hostA()), x.Eval(hostC()))
	}
	if got := Names(x); !slices.Equal(got, []string{"desk.gui", "gui", "pkg"}) {
		t.Errorf("Names = %q", got)
	}
	if got := Collectors(x); !slices.Equal(got, []string{"packages"}) {
		t.Errorf("Collectors = %q", got)
	}
	// Without named conditions, Expand equals String.
	y, _ := Parse("!(type:work | os:linux) & fact:editor", vocab())
	if Expand(y) != y.String() {
		t.Errorf("Expand %q != String %q", Expand(y), y.String())
	}
	// A named condition used under ! keeps its grouping.
	z, _ := Parse("!cond:gui", v)
	if got := Expand(z); got != "!(os:darwin | fact:editor=editor-one)" {
		t.Errorf("Expand(!cond:gui) = %q", got)
	}
}

func TestNamedConditionErrors(t *testing.T) {
	cases := []struct {
		name string
		defs []Definition
		want []string
	}{
		{"cycle", []Definition{
			{Name: "a", Src: "cond:b", File: "manifest.toml"},
			{Name: "b", Src: "os:linux & cond:a", File: "conditions/x.toml"},
		}, []string{"cycle", "a -> b -> a", "conditions.a"}},
		{"self", []Definition{{Name: "a", Src: "cond:a", File: "manifest.toml"}}, []string{"manifest.toml: conditions.a: cycle a -> a"}},
		{"unknown", []Definition{{Name: "a", Src: "cond:nope", File: "manifest.toml"}}, []string{"manifest.toml: conditions.a", `unknown condition "nope"`}},
		{"duplicate", []Definition{
			{Name: "a", Src: "true", File: "manifest.toml"},
			{Name: "a", Src: "false", File: "conditions/x.toml"},
		}, []string{"conditions/x.toml: conditions.a: already defined in manifest.toml"}},
		{"bad term", []Definition{{Name: "a", Src: "type:nope", File: "f.toml"}}, []string{"f.toml: conditions.a", `unknown type "nope"`}},
		{"bad name", []Definition{{Name: "a..b", Src: "true", File: "f.toml"}}, []string{"f.toml: conditions.a..b: bad condition name"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Define(c.defs, vocab())
			if err == nil {
				t.Fatal("no error")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
		})
	}
	// An unknown name in a plain condition fails at parse time.
	if _, err := Parse("cond:missing", vocab()); err == nil || !strings.Contains(err.Error(), `unknown condition "missing"`) {
		t.Errorf("Parse(cond:missing) = %v", err)
	}
	if _, err := Parse("cond:a=b", vocab()); err == nil {
		t.Error("cond:a=b parsed")
	}
}
