package render

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
)

func vocab() cond.Vocabulary {
	return cond.Vocabulary{
		Types:      map[string]bool{"personal": true, "work": true, "client": true},
		FactKeys:   map[string]bool{"editor": true, "proxy": true},
		Collectors: map[string]bool{"packages": true, "broken": true, "absent": true},
	}
}

func ctxA() model.Context {
	return model.Context{
		Machine: model.Machine{ID: "m-a", Name: "host-a", Types: []model.TypeName{"personal"}, OS: "darwin", Arch: "arm64",
			Facts: map[string]string{"editor": "editor-one"}},
		Home: "/test/home-a",
		User: "user-a",
		Observed: map[string]model.ObservedFact{
			"packages": {Items: []string{"tool-one", "tool-two"}},
			"broken":   {Error: "exit 1"},
		},
	}
}

func TestRender(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"plain", "a\nb\n", "a\nb\n"},
		{"no trailing newline gains one", "a", "a\n"},
		{"trailing newlines collapse", "a\n\n\n", "a\n"},
		{"empty", "", "\n"},
		{"vars", "{{ home }} {{user}} {{ machine.id }} {{ machine.name }} {{ machine.os }} {{ machine.arch }}\n",
			"/test/home-a user-a m-a host-a darwin arm64\n"},
		{"fact", "e={{ machine.facts.editor }}\n", "e=editor-one\n"},
		{"observed", "{{ observed.packages }}\n", "tool-one\ntool-two\n"},
		{"literal", `{{ "{{" }} x {{ "}}" }}` + "\n", "{{ x }}\n"},
		{"single brace is text", "a { b } c {x}\n", "a { b } c {x}\n"},
		{"stray close is text", "a }} %} #}\n", "a }} %} #}\n"},
		{"comment inline", "a{# note #}b\n", "ab\n"},
		{"comment line removed", "a\n{# note #}\nb\n", "a\nb\n"},
		{"indented comment line removed", "a\n  {# note #}  \nb\n", "a\nb\n"},
		{"if line removed", "x\n{% if os:darwin %}\nmac\n{% endif %}\ny\n", "x\nmac\ny\n"},
		{"if false", "x\n{% if os:linux %}\nlinux\n{% endif %}\ny\n", "x\ny\n"},
		{"else", "{% if type:work %}\nwork\n{% else %}\nhome\n{% endif %}\n", "home\n"},
		{"elif", "{% if os:linux %}\nL\n{% elif arch:arm64 %}\nARM\n{% else %}\nX\n{% endif %}\n", "ARM\n"},
		{"inline if keeps text", "a{% if true %}b{% endif %}c\n", "abc\n"},
		{"inline if false", "a {% if false %}b{% else %}c{% endif %} d\n", "a c d\n"},
		{"nested", "{% if os:darwin %}\n{% if type:work %}\nW\n{% else %}\nP\n{% endif %}\n{% endif %}\n", "P\n"},
		{"var alone keeps newline", "{{ user }}\n{{ user }}\n", "user-a\nuser-a\n"},
		{"two tags on one line not alone", "{% if true %}{% endif %}\nz\n", "\nz\n"},
		{"tag at eof", "a\n{% if true %}\nb\n{% endif %}", "a\nb\n"},
		{"untaken branch may name a missing fact", "{% if fact:proxy %}\n{{ machine.facts.proxy }}\n{% endif %}\nok\n", "ok\n"},
		{"crlf text kept", "a\r\nb\r\n", "a\r\nb\r\n"},
		{"crlf block line removed", "a\r\n{% if true %}\r\nb\r\n{% endif %}\r\nc\r\n", "a\r\nb\r\nc\r\n"},
	}
	eng := New(vocab())
	for _, tc := range cases {
		got, err := eng.Render("t.tmpl", []byte(tc.src), ctxA())
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRenderErrors(t *testing.T) {
	cases := []struct {
		name, src, msg string
		line, col      int
	}{
		{"unknown var", "a\n  {{ hostname }}\n", `unknown variable "hostname"`, 2, 6},
		{"filter", "{{ user | upper }}", `unknown variable "user | upper"`, 1, 4},
		{"unknown fact", "{{ machine.facts.editr }}", `unknown fact "editr"`, 1, 4},
		{"unknown collector", "{{ observed.pkgs }}", `unknown collector "pkgs"`, 1, 4},
		{"bad fact key", "{{ machine.facts.a b }}", `bad fact key`, 1, 4},
		{"missing fact", "x\n{{ machine.facts.proxy }}", `fact "proxy" is not declared`, 2, 4},
		{"missing observed", "{{ observed.absent }}", `has no observed value`, 1, 4},
		{"failed observed", "{{ observed.broken }}", `collector "broken" failed`, 1, 4},
		{"empty expr", "ab{{ }}", "empty expression", 1, 3},
		{"bad string", `{{ "x" }}`, "a string may only be", 1, 4},
		{"unterminated string", `{{ "{{ }}`, "unterminated string", 1, 4},
		{"unterminated var", "a {{ home\n}}", "unterminated", 1, 3},
		{"unterminated block", "{% if true", "unterminated", 1, 1},
		{"unterminated comment", "x\n{# note\n#}", "unterminated", 2, 1},
		{"unknown directive", "{% for x in y %}", `unknown directive "for"`, 1, 4},
		{"include", "\n\n{% include other %}", `unknown directive "include"`, 3, 4},
		{"empty block", "{% %}", "empty block tag", 1, 1},
		{"if no cond", "{% if %}{% endif %}", "if needs a condition", 1, 6},
		{"bad cond", "{% if type:wrok %}{% endif %}", `unknown type "wrok"`, 1, 12},
		{"cond syntax", "{% if os:darwin & %}{% endif %}", "found the end", 1, 19},
		{"elif without if", "{% elif true %}", "elif without if", 1, 1},
		{"else without if", "{% else %}", "else without if", 1, 1},
		{"endif without if", "x\n{% endif %}", "endif without if", 2, 1},
		{"if without endif", "a\n{% if true %}\nb\n", "if without endif", 2, 1},
		{"else with cond", "{% if true %}{% else os:linux %}{% endif %}", "else takes no condition", 1, 21},
		{"endif with arg", "{% if true %}{% endif x %}", "endif takes nothing", 1, 22},
		{"second else", "{% if true %}{% else %}{% else %}{% endif %}", "second else", 1, 24},
		{"elif after else", "{% if true %}{% else %}{% elif true %}{% endif %}", "elif after else", 1, 24},
		{"untaken branch still parsed", "{% if false %}{{ nope }}{% endif %}", `unknown variable "nope"`, 1, 18},
	}
	eng := New(vocab())
	for _, tc := range cases {
		_, err := eng.Render("t.tmpl", []byte(tc.src), ctxA())
		var re *Error
		if !errors.As(err, &re) {
			t.Errorf("%s: want *Error, got %v", tc.name, err)
			continue
		}
		if re.Name != "t.tmpl" || re.Line != tc.line || re.Col != tc.col || !strings.Contains(re.Msg, tc.msg) {
			t.Errorf("%s: got %v, want t.tmpl:%d:%d: ...%s", tc.name, re, tc.line, tc.col, tc.msg)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := Validate("x", []byte("{{ machine.facts.proxy }}"), vocab()); err != nil {
		t.Errorf("a missing value is not a syntax error: %v", err)
	}
	if err := Validate("x", []byte("{{ nope }}"), vocab()); err == nil {
		t.Error("unknown variable must fail validation")
	}
}

// TestFixtureGitconfig renders the fixture template for each fixture machine shape.
func TestFixtureGitconfig(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(fixture.Dir(), "source", "files", ".gitconfig.tmpl"))
	if err != nil {
		t.Fatal(err)
	}
	eng := New(vocab())
	work := ctxA()
	work.Machine.Types = []model.TypeName{"work", "client"}
	work.Machine.OS = "linux"
	for _, tc := range []struct {
		ctx        model.Context
		has, lacks []string
	}{
		{ctxA(), []string{"personal.example.invalid", "helper = os-keychain", "editor = editor-one", "excludesfile = /test/home-a/.config/git/ignore"}, []string{"work.example", "{"}},
		{work, []string{"work.example.invalid"}, []string{"personal.example", "credential", "{"}},
	} {
		out, err := eng.Render(".gitconfig.tmpl", src, tc.ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range tc.has {
			if !bytes.Contains(out, []byte(s)) {
				t.Errorf("%s: missing %q in\n%s", tc.ctx.Machine.OS, s, out)
			}
		}
		for _, s := range tc.lacks {
			if bytes.Contains(out, []byte(s)) {
				t.Errorf("%s: unexpected %q in\n%s", tc.ctx.Machine.OS, s, out)
			}
		}
		if !bytes.HasPrefix(out, []byte("[user]\n")) || bytes.HasSuffix(out, []byte("\n\n")) {
			t.Errorf("block lines not consumed:\n%q", out)
		}
	}
}

// FuzzRender checks the engine never panics, errors carry a sane position,
// and text with no tags passes through except for the trailing newline.
func FuzzRender(f *testing.F) {
	for _, s := range []string{"", "a\n", "{{ home }}", "{% if os:darwin %}\nx\n{% else %}\ny\n{% endif %}\n", "{# c #}", `{{ "{{" }}`, "{%", "{{ \"", "{% if (( %}"} {
		f.Add([]byte(s))
	}
	eng := New(vocab())
	f.Fuzz(func(t *testing.T, src []byte) {
		out, err := eng.Render("f", src, ctxA())
		if err != nil {
			var re *Error
			if !errors.As(err, &re) {
				t.Fatalf("error is not *Error: %v", err)
			}
			if re.Line < 1 || re.Col < 1 || re.Line > bytes.Count(src, []byte("\n"))+1 {
				t.Fatalf("bad position %d:%d", re.Line, re.Col)
			}
			return
		}
		if !bytes.HasSuffix(out, []byte("\n")) || bytes.HasSuffix(out, []byte("\n\n")) {
			t.Fatalf("output must end with exactly one newline: %q", out)
		}
		if !bytes.Contains(src, []byte("{")) {
			want := append(bytes.TrimRight(src, "\n"), '\n')
			if !bytes.Equal(out, want) {
				t.Fatalf("plain text changed: %q -> %q", src, out)
			}
		}
	})
}
