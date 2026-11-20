package importer

import (
	"strings"
	"testing"
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
		"const f = ({{ a }}) => 1\n":                `literal "{{"`,
		"n=${#arr}\n":                               `literal "{#"`,
		"x {% if yadm.os == \"Linux\" %} y\n":       `literal "{%"`,
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
