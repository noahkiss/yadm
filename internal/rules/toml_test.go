package rules

import (
	"bytes"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

var tomlSpec = Spec{Source: testSource,
	Format: manifest.FormatTOML,
	Drop:   []string{"state", "ui.last_opened", "history"},
	Seal: map[string]model.EnclaveName{
		"auth.token":        personal,
		"servers.*.api_key": personal,
	},
}

func tomlLive(secret string) string {
	return `# Tool configuration.
model = "example-model" # default
state = "running"

[ui]
theme = "dark"
# remembered by the app
last_opened = "2026-01-01T00:00:00Z"
font = { family = "Mono Example", size = 12 }

[auth]
# Sealed for the personal enclave.
token = "` + secret + `"
user = "example"

[servers.alpha]
url = "https://alpha.example.invalid"
api_key = "` + secret + `-alpha"

[servers.beta]
url = "https://beta.example.invalid"
api_key = '` + secret + `-beta'

[history]
entries = [
  "one",
  "two",
]
`
}

func TestTOMLMemberRoundTrip(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	live := []byte(tomlLive(c.String()))
	src := mustSource(t, live, nil, tomlSpec, s)
	assertNoCanary(t, c, "source", src)
	// A dropped key's comment stays in the source, so a re-insert lands
	// under it again.
	for _, gone := range []string{"state", "last_opened", "history"} {
		if strings.Contains(string(src), gone) {
			t.Errorf("source keeps %s:\n%s", gone, src)
		}
	}
	for _, kept := range []string{"# Tool configuration.", `model = "example-model" # default`, "font = { family", "# Sealed for the personal enclave.", `token = "yadm:1:personal:1:`} {
		if !strings.Contains(string(src), kept) {
			t.Errorf("source lacks %s:\n%s", kept, src)
		}
	}
	if got := mustTarget(t, src, live, tomlSpec, s); !bytes.Equal(got, live) && !literalOnly(got, live) {
		t.Fatalf("ToTarget(ToSource(live), live) != live:\n%s", got)
	}
}

// literalOnly reports whether a and b differ only in the quoting of a
// literal string that sealing rewrites as a basic string.
func literalOnly(a, b []byte) bool {
	return bytes.Equal(bytes.ReplaceAll(a, []byte(`"`), []byte(`'`)), bytes.ReplaceAll(b, []byte(`"`), []byte(`'`)))
}

func TestTOMLStableRoundTrip(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	// Basic strings only, so the round trip is byte-exact.
	live := []byte(strings.ReplaceAll(tomlLive(c.String()), "'", `"`))
	src := mustSource(t, live, nil, tomlSpec, s)
	if got := mustTarget(t, src, live, tomlSpec, s); !bytes.Equal(got, live) {
		t.Fatalf("target:\n%s\nwant\n%s", got, live)
	}
	if again := mustSource(t, live, src, tomlSpec, s); !bytes.Equal(again, src) {
		t.Fatalf("no-op capture changed the source")
	}
	edited := bytes.Replace(live, []byte(`theme = "dark"`), []byte(`theme = "light"`), 1)
	src2 := mustSource(t, edited, src, tomlSpec, s)
	if want := bytes.Replace(src, []byte(`theme = "dark"`), []byte(`theme = "light"`), 1); !bytes.Equal(src2, want) {
		t.Fatalf("edit:\n%s", src2)
	}

	// Non-member: sealed keys absent, round trip restores the tokens.
	nm := member()
	tgt := mustTarget(t, src, nil, tomlSpec, nm)
	assertNoCanary(t, c, "non-member target", tgt)
	if bytes.Contains(tgt, []byte("api_key")) || bytes.Contains(tgt, []byte("token =")) {
		t.Fatalf("non-member target:\n%s", tgt)
	}
	if back := mustSource(t, tgt, src, tomlSpec, nm); !bytes.Equal(back, src) {
		t.Fatalf("non-member capture:\n%s\nwant\n%s", back, src)
	}
	edited = bytes.Replace(tgt, []byte(`user = "example"`), []byte(`user = "example2"`), 1)
	back := mustSource(t, edited, src, tomlSpec, nm)
	if want := bytes.Replace(src, []byte(`user = "example"`), []byte(`user = "example2"`), 1); !bytes.Equal(back, want) {
		t.Fatalf("non-member edit:\n%s\nwant\n%s", back, want)
	}
	// The non-member deletes the whole [auth] table: the token comes back.
	i := bytes.Index(edited, []byte("[auth]"))
	j := bytes.Index(edited, []byte("[servers.alpha]"))
	noAuth := append(append([]byte(nil), edited[:i]...), edited[j:]...)
	back = mustSource(t, noAuth, src, tomlSpec, nm)
	if !bytes.Contains(back, []byte(`token = "yadm:1:personal:`)) {
		t.Fatalf("token lost:\n%s", back)
	}
	if _, err := (tomlFormat{}).parse(back); err != nil {
		t.Fatal(err)
	}
}

func TestTOMLSealGuard(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	live := []byte(strings.ReplaceAll(tomlLive(c.String()), "'", `"`))
	src := mustSource(t, live, nil, tomlSpec, s)

	noKey := bytes.Replace(live, []byte(`token = "`+c.String()+"\"\n"), nil, 1)
	assertViolation(t, noKey, src, tomlSpec, s, SealedKeyRemoved, c)

	moved := bytes.Replace(live, []byte(`theme = "dark"`), []byte(`theme = "`+c.String()+`"`), 1)
	assertViolation(t, moved, src, tomlSpec, s, SealedValueLeaked, c)

	broken := append(append([]byte(nil), live...), []byte("[ui]\n")...)
	assertViolation(t, broken, src, tomlSpec, s, ParseFailed, c)
}

func TestTOMLKeep(t *testing.T) {
	spec := Spec{Source: testSource, Format: manifest.FormatTOML, Keep: []string{"editor", "ui.theme"}}
	live := []byte(`top = 1

[ui]
theme = "dark"
zoom = 2

[editor]
tab = 4

[editor.extra]
x = true

[app]
window = "big"
`)
	s := member()
	src := mustSource(t, live, nil, spec, s)
	want := `
[ui]
theme = "dark"

[editor]
tab = 4

[editor.extra]
x = true

`
	if string(src) != want {
		t.Fatalf("source:\n%q", src)
	}
	if got := mustTarget(t, src, live, spec, s); !bytes.Equal(got, live) {
		t.Fatalf("target:\n%s", got)
	}
	// The repo changes a kept value; app keys stay.
	src2 := bytes.Replace(src, []byte("tab = 4"), []byte("tab = 8"), 1)
	if got := mustTarget(t, src2, live, spec, s); !bytes.Equal(got, bytes.Replace(live, []byte("tab = 4"), []byte("tab = 8"), 1)) {
		t.Fatalf("target:\n%s", got)
	}
	// A live file without the [editor] table gets it appended.
	bare := []byte("top = 1\n\n[ui]\ntheme = \"light\"\n")
	got := mustTarget(t, src, bare, spec, s)
	if _, err := (tomlFormat{}).parse(got); err != nil || !bytes.Contains(got, []byte("[editor.extra]")) || !bytes.Contains(got, []byte(`theme = "dark"`)) {
		t.Fatalf("target:\n%s (%v)", got, err)
	}
}

func TestTOMLEditor(t *testing.T) {
	f := tomlFormat{}
	doc := []byte("a.b = 1 # c\nlist = [1, { z = 2 }, [3, 4]]\ninl = { p = \"q\", r = 's' }\n\n[t]\n# about k\nk = \"v\"\nm = 2\n\n[[arr]]\nq = 1\n[[arr]]\nq = 2\n")
	root, err := f.parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if n := find(root, []string{"list", "2", "1"}); n == nil || string(doc[n.vStart:n.vEnd]) != "4" {
		t.Fatalf("nested array element: %+v", n)
	}
	if n := find(root, []string{"list", "1", "z"}); n == nil || string(doc[n.vStart:n.vEnd]) != "2" {
		t.Fatal("inline table in array")
	}
	if n := find(root, []string{"arr", "1", "q"}); n == nil || string(doc[n.vStart:n.vEnd]) != "2" {
		t.Fatal("array of tables")
	}
	cases := []struct {
		path []string
		want string
	}{
		{[]string{"a", "b"}, "list = [1, { z = 2 }, [3, 4]]\ninl = { p = \"q\", r = 's' }\n\n[t]\n# about k\nk = \"v\"\nm = 2\n\n[[arr]]\nq = 1\n[[arr]]\nq = 2\n"},
		{[]string{"list", "1"}, "a.b = 1 # c\nlist = [1, [3, 4]]\ninl = { p = \"q\", r = 's' }\n\n[t]\n# about k\nk = \"v\"\nm = 2\n\n[[arr]]\nq = 1\n[[arr]]\nq = 2\n"},
		{[]string{"inl", "r"}, "a.b = 1 # c\nlist = [1, { z = 2 }, [3, 4]]\ninl = { p = \"q\" }\n\n[t]\n# about k\nk = \"v\"\nm = 2\n\n[[arr]]\nq = 1\n[[arr]]\nq = 2\n"},
		{[]string{"t", "k"}, "a.b = 1 # c\nlist = [1, { z = 2 }, [3, 4]]\ninl = { p = \"q\", r = 's' }\n\n[t]\n# about k\nm = 2\n\n[[arr]]\nq = 1\n[[arr]]\nq = 2\n"},
		{[]string{"t"}, "a.b = 1 # c\nlist = [1, { z = 2 }, [3, 4]]\ninl = { p = \"q\", r = 's' }\n\n[[arr]]\nq = 1\n[[arr]]\nq = 2\n"},
		{[]string{"arr", "0"}, "a.b = 1 # c\nlist = [1, { z = 2 }, [3, 4]]\ninl = { p = \"q\", r = 's' }\n\n[t]\n# about k\nk = \"v\"\nm = 2\n\n[[arr]]\nq = 2\n"},
	}
	for _, tc := range cases {
		out, err := deletePaths(f, doc, [][]string{tc.path}, false)
		if err != nil {
			t.Fatalf("%v: %v", tc.path, err)
		}
		if string(out) != tc.want {
			t.Errorf("delete %v:\n%q\nwant\n%q", tc.path, out, tc.want)
		}
	}
	// Comment ownership: the owning delete takes the comment above.
	out, err := deletePaths(f, doc, [][]string{{"t", "k"}}, true)
	if err != nil || bytes.Contains(out, []byte("about k")) {
		t.Fatalf("owned comment kept: %q %v", out, err)
	}
	// Insert into an inline table and a section.
	src := []byte("inl = { p = \"q\", r = 's', n = 5 }\n[t]\nk = \"v\"\nnew = [1]\nm = 2\n")
	got, err := put(f, doc, []string{"inl", "n"}, src, false)
	if err != nil || !bytes.Contains(got, []byte("inl = { p = \"q\", r = 's', n = 5 }")) {
		t.Fatalf("inline insert: %q %v", got, err)
	}
	got, err = put(f, doc, []string{"t", "new"}, src, false)
	if err != nil || !bytes.Contains(got, []byte("k = \"v\"\nnew = [1]\nm = 2\n")) {
		t.Fatalf("section insert: %q %v", got, err)
	}
}

func TestTOMLCRLF(t *testing.T) {
	spec := Spec{Source: testSource, Format: manifest.FormatTOML, Drop: []string{"t.b"}}
	live := []byte("[t]\r\na = 1\r\nb = 2\r\nc = 3\r\n")
	src := mustSource(t, live, nil, spec, member())
	if string(src) != "[t]\r\na = 1\r\nc = 3\r\n" {
		t.Fatalf("source %q", src)
	}
	if got := mustTarget(t, src, live, spec, member()); !bytes.Equal(got, live) {
		t.Fatalf("target %q", got)
	}
}

func TestTOMLDropMidFileTables(t *testing.T) {
	spec := Spec{Source: testSource, Format: manifest.FormatTOML, Drop: []string{"history", "servers"}}
	live := []byte(`top = 1

[history]
entries = ["one"]

[servers.alpha]
url = "a"

[servers.beta]
url = "b"

# the auth table
[auth]
user = "example"
`)
	s := member()
	src := mustSource(t, live, nil, spec, s)
	if want := "top = 1\n\n# the auth table\n[auth]\nuser = \"example\"\n"; string(src) != want {
		t.Fatalf("source:\n%q", src)
	}
	if got := mustTarget(t, src, live, spec, s); !bytes.Equal(got, live) {
		t.Fatalf("target:\n%s", got)
	}
}
