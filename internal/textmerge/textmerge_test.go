package textmerge

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

const gitconfigBase = `[user]
	name = Example User
	email = user@example.invalid
[core]
	editor = editor-one
	autocrlf = input
[alias]
	st = status
	co = checkout
	br = branch
[pull]
	rebase = true
[init]
	defaultBranch = main
`

func TestMerge3Identities(t *testing.T) {
	b := []byte(gitconfigBase)
	x := []byte(strings.Replace(gitconfigBase, "co = checkout", "co = switch", 1))
	for name, tc := range map[string][3][]byte{
		"theirs unchanged": {b, x, b},
		"ours unchanged":   {b, b, x},
		"same change":      {b, x, x},
	} {
		got, conf, err := Merge3(tc[0], tc[1], tc[2])
		if err != nil || len(conf) > 0 || !bytes.Equal(got, x) {
			t.Errorf("%s: %q %v %v", name, got, conf, err)
		}
	}
	got, conf, err := Merge3(nil, nil, nil)
	if err != nil || len(conf) > 0 || len(got) != 0 {
		t.Fatalf("empty: %q %v %v", got, conf, err)
	}
}

func TestMerge3Clean(t *testing.T) {
	ours := strings.Replace(gitconfigBase, "editor = editor-one", "editor = editor-two", 1)
	theirs := strings.Replace(gitconfigBase, "defaultBranch = main", "defaultBranch = trunk", 1)
	theirs = strings.Replace(theirs, "[pull]\n", "[fetch]\n\tprune = true\n[pull]\n", 1)
	want := strings.Replace(theirs, "editor = editor-one", "editor = editor-two", 1)
	got, conf, err := Merge3([]byte(gitconfigBase), []byte(ours), []byte(theirs))
	if err != nil || len(conf) > 0 || string(got) != want {
		t.Fatalf("got %q %v %v", got, conf, err)
	}
}

func TestMerge3Conflict(t *testing.T) {
	ours := strings.Replace(gitconfigBase, "editor = editor-one", "editor = editor-two", 1)
	theirs := strings.Replace(gitconfigBase, "editor = editor-one", "editor = editor-three", 1)
	theirs = strings.Replace(theirs, "rebase = true", "rebase = false", 1)
	got, conf, err := Merge3([]byte(gitconfigBase), []byte(ours), []byte(theirs))
	if err != nil {
		t.Fatal(err)
	}
	if len(conf) != 1 {
		t.Fatalf("conflicts: %+v", conf)
	}
	c := conf[0]
	if string(c.Ours) != "\teditor = editor-two\n" || string(c.Theirs) != "\teditor = editor-three\n" || string(c.Base) != "\teditor = editor-one\n" {
		t.Fatalf("region: %+v", c)
	}
	if c.OursStart != 4 || c.OursEnd != 5 {
		t.Fatalf("region lines: %d-%d", c.OursStart, c.OursEnd)
	}
	want := strings.Replace(theirs, "\teditor = editor-three\n", MarkerOurs+"\n\teditor = editor-two\n"+MarkerSep+"\n\teditor = editor-three\n"+MarkerTheirs+"\n", 1)
	if string(got) != want {
		t.Fatalf("merged:\n%s", got)
	}
}

func TestMerge3CRLFAndNoFinalNewline(t *testing.T) {
	base := "a\r\nb\r\nc"
	ours := "A\r\nb\r\nc"
	theirs := "a\r\nb\r\nc\r\nd"
	got, conf, err := Merge3([]byte(base), []byte(ours), []byte(theirs))
	if err != nil || len(conf) > 0 || string(got) != "A\r\nb\r\nc\r\nd" {
		t.Fatalf("got %q %v %v", got, conf, err)
	}
	// Both add different last lines without a final newline: the markers
	// still sit on their own lines and keep CRLF.
	got, conf, err = Merge3([]byte(base), []byte(base+"\r\nx"), []byte(base+"\r\ny"))
	if err != nil || len(conf) != 1 {
		t.Fatalf("got %q %v %v", got, conf, err)
	}
	want := "a\r\nb\r\n" + MarkerOurs + "\r\nc\r\nx\r\n" + MarkerSep + "\r\nc\r\ny\r\n" + MarkerTheirs + "\r\n"
	if string(got) != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestBinary(t *testing.T) {
	bin := []byte("plist\x00\x01\x02")
	if _, _, err := Merge3(bin, nil, nil); !errors.Is(err, ErrBinary) {
		t.Fatal(err)
	}
	if _, err := Diff("a", "b", nil, bin); !errors.Is(err, ErrBinary) {
		t.Fatal(err)
	}
	if _, err := PatchTemplate(bin, nil, nil); !errors.Is(err, ErrBinary) {
		t.Fatal(err)
	}
	if IsBinary([]byte("plain text\n")) {
		t.Fatal("text detected as binary")
	}
}

func TestDiffGolden(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n"
	b := "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\n11\n12\n13"
	got, err := Diff("a/f", "b/f", []byte(a), []byte(b))
	if err != nil {
		t.Fatal(err)
	}
	want := `--- a/f
+++ b/f
@@ -2,7 +2,7 @@
 2
 3
 4
-5
+five
 6
 7
 8
@@ -10,3 +10,4 @@
 10
 11
 12
+13
\ No newline at end of file
`
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	if d, _ := Diff("a", "b", []byte(a), []byte(a)); d != "" {
		t.Fatalf("equal inputs: %q", d)
	}
	got, _ = Diff("a", "b", nil, []byte("x\n"))
	if got != "--- a\n+++ b\n@@ -0,0 +1 @@\n+x\n" {
		t.Fatalf("from empty: %q", got)
	}
}

// applyUnified applies a unified diff made by Diff to a.
func applyUnified(t *testing.T, a []byte, d string) []byte {
	t.Helper()
	if d == "" {
		return a
	}
	src := lines(a)
	var out []string
	pos := 0
	dl := strings.SplitAfter(d, "\n")
	for i := 2; i < len(dl); i++ {
		l := dl[i]
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "@@") {
			var as string
			fmt.Sscanf(l, "@@ -%s", &as)
			n, _ := strconv.Atoi(strings.Split(as, ",")[0])
			if strings.HasSuffix(as, ",0") {
				n++
			}
			out = append(out, src[pos:n-1]...)
			pos = n - 1
			continue
		}
		body := l[1:]
		if i+1 < len(dl) && strings.HasPrefix(dl[i+1], `\ No newline`) {
			body = strings.TrimSuffix(body, "\n")
			i++
		}
		switch l[0] {
		case ' ':
			out = append(out, body)
			pos++
		case '-':
			pos++
		case '+':
			out = append(out, body)
		}
	}
	out = append(out, src[pos:]...)
	return join(out)
}

func TestDiffApplies(t *testing.T) {
	cases := [][2]string{
		{gitconfigBase, strings.Replace(gitconfigBase, "[pull]\n\trebase = true\n", "", 1)},
		{gitconfigBase, "[user]\n\tname = Other\n"},
		{"", "a\nb"},
		{"a\nb", ""},
		{"x\r\ny\r\nz\r\n", "x\r\nY\r\nz\r\n"},
		{"Host *\n  ServerAliveInterval 60\n\nHost a\n  User git", "Host *\n  ServerAliveInterval 30\n\nHost a\n  User git\n"},
	}
	for i, c := range cases {
		d, err := Diff("a", "b", []byte(c[0]), []byte(c[1]))
		if err != nil {
			t.Fatal(err)
		}
		if got := applyUnified(t, []byte(c[0]), d); string(got) != c[1] {
			t.Errorf("case %d: diff does not apply:\n%s\ngot %q", i, d, got)
		}
	}
}

func TestPatchTemplate(t *testing.T) {
	tmpl := `[user]
	name = {{ machine.facts.fullname }}
	email = user@example.invalid
[core]
	editor = editor-one
{% if os:darwin %}
	trustctime = false
{% endif %}
[alias]
	st = status
	co = checkout
`
	render := `[user]
	name = Example User
	email = user@example.invalid
[core]
	editor = editor-one
	trustctime = false
[alias]
	st = status
	co = checkout
`
	edited := strings.Replace(render, "co = checkout", "co = switch\n\tsw = switch", 1)
	got, err := PatchTemplate([]byte(tmpl), []byte(render), []byte(edited))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(tmpl, "co = checkout", "co = switch\n\tsw = switch", 1); string(got) != want {
		t.Fatalf("got\n%s", got)
	}
	// An edit next to a directive applies with a smaller context.
	edited = strings.Replace(render, "editor = editor-one", "editor = editor-two", 1)
	got, err = PatchTemplate([]byte(tmpl), []byte(render), []byte(edited))
	if err != nil || !strings.Contains(string(got), "editor = editor-two\n{% if os:darwin %}") {
		t.Fatalf("near directive: %q %v", got, err)
	}
	// An edit to a rendered expression does not apply.
	edited = strings.Replace(render, "Example User", "Other User", 1)
	if _, err := PatchTemplate([]byte(tmpl), []byte(render), []byte(edited)); !errors.Is(err, ErrPatch) {
		t.Fatalf("rendered value edit: %v", err)
	}
	// No edit: the template comes back unchanged.
	if got, err := PatchTemplate([]byte(tmpl), []byte(render), []byte(render)); err != nil || string(got) != tmpl {
		t.Fatal("no-op patch changed the template")
	}
}

func TestPatchTemplateAmbiguous(t *testing.T) {
	tmpl := "x\n{% if a %}\nsame\n{% else %}\nsame\n{% endif %}\n"
	render := "x\nsame\n"
	if _, err := PatchTemplate([]byte(tmpl), []byte(render), []byte("x\nchanged\n")); !errors.Is(err, ErrPatch) {
		t.Fatalf("ambiguous hunk applied: %v", err)
	}
}

func TestPatchTemplateCRLF(t *testing.T) {
	tmpl := "a = {{ home }}\r\nb = 1\r\nc = 2\r\nd = 3"
	render := "a = /home/x\r\nb = 1\r\nc = 2\r\nd = 3"
	edited := "a = /home/x\r\nb = 1\r\nc = 20\r\nd = 3"
	got, err := PatchTemplate([]byte(tmpl), []byte(render), []byte(edited))
	if err != nil || string(got) != "a = {{ home }}\r\nb = 1\r\nc = 20\r\nd = 3" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestLargeDivergentInputs(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&a, "a%d\n", i)
		fmt.Fprintf(&b, "b%d\n", i)
	}
	d, err := Diff("a", "b", []byte(a.String()), []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if got := applyUnified(t, []byte(a.String()), d); string(got) != b.String() {
		t.Fatal("bounded diff does not apply")
	}
	if got, conf, err := Merge3([]byte(a.String()), []byte(b.String()), []byte(a.String())); err != nil || len(conf) > 0 || string(got) != b.String() {
		t.Fatal("bounded merge")
	}
}

func FuzzMerge3(f *testing.F) {
	f.Add(gitconfigBase, strings.Replace(gitconfigBase, "st", "s", 1), "x\n"+gitconfigBase)
	f.Add("a\nb\nc", "a\nB\nc", "a\nb\nC")
	f.Fuzz(func(t *testing.T, base, ours, theirs string) {
		got, conf, err := Merge3([]byte(base), []byte(ours), []byte(theirs))
		if err != nil {
			return
		}
		if base == theirs && (len(conf) > 0 || string(got) != ours) {
			t.Fatalf("Merge3(b,x,b) != x: %q", got)
		}
		if base == ours && (len(conf) > 0 || string(got) != theirs) {
			t.Fatalf("Merge3(b,b,x) != x: %q", got)
		}
		if ours == theirs && (len(conf) > 0 || string(got) != ours) {
			t.Fatalf("Merge3(b,x,x) != x: %q", got)
		}
		d, err := Diff("a", "b", []byte(base), []byte(ours))
		if err == nil {
			if back := applyUnified(t, []byte(base), d); !bytes.Equal(back, []byte(ours)) {
				t.Fatalf("diff does not apply:\n%s", d)
			}
		}
	})
}
