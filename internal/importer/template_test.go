package importer

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/render"
)

func TestConvertTemplate(t *testing.T) {
	src := strings.Join([]string{
		`home={{env.HOME}} user={{ yadm.user }}`,
		`host={{ yadm.hostname }} os={{yadm.os}}`,
		`  {% if yadm.class == "Work" %}`,
		`work`,
		`{% if yadm.os != "Darwin" %}`,
		`not darwin`,
		`{% endif %}`,
		`{% else %}`,
		`other`,
		`  {%endif%}`,
		`{% include "inc/part.txt" %}`,
		`tail`,
		``,
		``,
	}, "\n")
	inc := func(p string) ([]byte, bool, error) {
		if p == ".config/app/inc/part.txt" {
			return []byte("{% if yadm.hostname == \"host-a\" %}\npart\n{% endif %}\n"), true, nil
		}
		return nil, false, nil
	}
	res, probs := convertTemplate("legacy##template", ".config/app/conf", []byte(src), inc)
	if len(probs) > 0 {
		t.Fatalf("problems: %v", probs)
	}
	want := strings.Join([]string{
		`home={{ home }} user={{ user }}`,
		`host={{ machine.facts.hostname }} os={{ machine.os }}`,
		`{% if type:work %}`,
		`work`,
		`{% if !os:darwin %}`,
		`not darwin`,
		`{% endif %}`,
		`{% else %}`,
		`other`,
		`{% endif %}`,
		`{% if fact:hostname=host-a %}`,
		`part`,
		`{% endif %}`,
		`tail`,
		``,
	}, "\n")
	if string(res.Out) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", res.Out, want)
	}
	if !res.Facts["hostname"] {
		t.Error("hostname fact not recorded")
	}
}

func TestConvertTemplateProblems(t *testing.T) {
	cases := map[string]string{
		"{{ env.EDITOR }}\n":                        "env.EDITOR",
		"{{ yadm.source }}\n":                       "yadm.source",
		"{% if env.HOME == \"x\" %}\n{% endif %}\n": "if on env.HOME",
		"{% if yadm.class == \"a\" %}\n":            "unterminated",
		"{% endif %}\n":                             "endif without",
		"{% else %}\n":                              "else without",
		"{% include \"missing\" %}\n":               "not in the repository",
		"{% include \"/etc/x\" %}\n":                "outside",
	}
	for src, want := range cases {
		_, probs := convertTemplate("t##template", "t", []byte(src), func(string) ([]byte, bool, error) { return nil, false, nil })
		if len(probs) == 0 {
			t.Errorf("%q: no problem", src)
			continue
		}
		if !strings.Contains(probs[0].Reason, want) {
			t.Errorf("%q: reason %q, want it to mention %q", src, probs[0].Reason, want)
		}
		if probs[0].Path == "" {
			t.Errorf("%q: problem without path", src)
		}
	}
}

// TestConvertTemplateEscapes checks that text upstream prints as is, but
// which would open a tag in the new syntax, renders back to itself.
func TestConvertTemplateEscapes(t *testing.T) {
	cases := []struct{ src, want string }{
		{"type Opts = {{ x: string }}\n", "type Opts = {{ x: string }}\n"},
		{"n=${#arr}\n", "n=${#arr}\n"},
		{"x {% if yadm.os == \"Linux\" %} y\n", "x {% if yadm.os == \"Linux\" %} y\n"},
		{"{# not a comment #}\n", "{# not a comment #}\n"},
		{"{{{ env.HOME }}}\n", "{/home/u}\n"},
		{"{%{{ yadm.user }}\n", "{%u\n"},
		{"f() {\n  echo {{ yadm.user }}\n}\n", "f() {\n  echo u\n}\n"},
	}
	v := cond.Vocabulary{Types: map[string]bool{}, FactKeys: map[string]bool{}, Collectors: map[string]bool{}}
	eng := render.New(v)
	ctx := model.Context{Home: "/home/u", User: "u"}
	for _, tc := range cases {
		res, probs := convertTemplate("t##template", "t", []byte(tc.src), nil)
		if len(probs) > 0 {
			t.Errorf("%q: problems %v", tc.src, probs)
			continue
		}
		out, err := eng.Render("t", res.Out, ctx)
		if err != nil {
			t.Errorf("%q: converted %q does not render: %v", tc.src, res.Out, err)
			continue
		}
		if string(out) != tc.want {
			t.Errorf("%q: renders %q, want %q", tc.src, out, tc.want)
		}
	}
}

func TestConvertTemplateTrailingNewlines(t *testing.T) {
	res, _ := convertTemplate("t", "t", []byte("a\n\n\n"), nil)
	if string(res.Out) != "a\n" {
		t.Errorf("got %q", res.Out)
	}
	res, _ = convertTemplate("t", "t", []byte("a"), nil)
	if string(res.Out) != "a\n" {
		t.Errorf("got %q", res.Out)
	}
}
