package rules

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

const personal model.EnclaveName = "personal"

var settingsSpec = Spec{
	Format: manifest.FormatJSONC,
	Keep:   []string{"editor.*", "terminal.font", `files\.exclude`},
	Drop:   []string{"window.state", "recent"},
	Seal:   map[string]model.EnclaveName{"sync.token": personal},
}

// liveSettings is an app-written settings file on a member machine.
func liveSettings(secret string) string {
	return `{
  // Repo-owned keys (keep): editor.* and terminal.font.
  "editor": {
    "fontSize": 13,
    "tabSize": 2
  },
  "terminal": {
    "font": "Mono Example",
    "size": 11 // app-owned
  },
  // A key whose name contains dots.
  "files.exclude": {
    "**/.cache": true
  },
  "window": {"state": "maximized", "zoom": 1},
  "recent": ["/tmp/a", "/tmp/b"],
  // Sealed for the personal enclave.
  "sync": {
    "token": "` + secret + `"
  },
  "telemetry": false,
}
`
}

func mustSource(t *testing.T, target, prev []byte, spec Spec, s Sealer) []byte {
	t.Helper()
	out, vio, err := ToSource(target, prev, spec, s)
	if err != nil {
		t.Fatalf("ToSource: %v", err)
	}
	if len(vio) > 0 {
		t.Fatalf("ToSource violations: %+v", vio)
	}
	return out
}

func mustTarget(t *testing.T, source, live []byte, spec Spec, s Sealer) []byte {
	t.Helper()
	out, err := ToTarget(source, live, spec, s)
	if err != nil {
		t.Fatalf("ToTarget: %v", err)
	}
	return out
}

func assertNoCanary(t *testing.T, c secrecytest.Canary, what string, b []byte) {
	t.Helper()
	if bytes.Contains(b, c.Bytes()) {
		t.Fatalf("%s contains the canary:\n%s", what, b)
	}
}

func assertViolation(t *testing.T, target, prev []byte, spec Spec, s Sealer, kind ViolationKind, canaries ...secrecytest.Canary) {
	t.Helper()
	out, vio, err := ToSource(target, prev, spec, s)
	if err != nil {
		t.Fatalf("ToSource: %v", err)
	}
	if out != nil {
		t.Fatalf("ToSource returned bytes with violations: %q", out)
	}
	found := false
	for _, v := range vio {
		if v.Kind == kind {
			found = true
		}
		for _, c := range canaries {
			if strings.Contains(v.Path+v.Detail, c.String()) {
				t.Fatalf("violation carries plaintext: %+v", v)
			}
		}
	}
	if !found {
		t.Fatalf("want violation %s, got %+v", kind, vio)
	}
}

func TestJSONCSettingsMember(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	live := []byte(liveSettings(c.String()))

	src := mustSource(t, live, nil, settingsSpec, s)
	assertNoCanary(t, c, "source", src)
	for _, gone := range []string{"window", "recent", "telemetry", `"size"`, "app-owned"} {
		if strings.Contains(string(src), gone) {
			t.Errorf("source keeps %s:\n%s", gone, src)
		}
	}
	for _, kept := range []string{`"fontSize": 13`, `"font": "Mono Example"`, `"**/.cache": true`, `"token": "yadm:1:personal:1:`} {
		if !strings.Contains(string(src), kept) {
			t.Errorf("source lacks %s:\n%s", kept, src)
		}
	}

	// Apply on the same machine reproduces the live file byte for byte.
	if got := mustTarget(t, src, live, settingsSpec, s); !bytes.Equal(got, live) {
		t.Fatalf("ToTarget(ToSource(live), live) != live:\n%s", got)
	}
	// A no-op capture returns the source unchanged.
	if again := mustSource(t, live, src, settingsSpec, s); !bytes.Equal(again, src) {
		t.Fatalf("no-op capture changed the source:\n%s", again)
	}

	// Editing a kept value touches only that value's bytes.
	edited := bytes.Replace(live, []byte(`"fontSize": 13`), []byte(`"fontSize": 14`), 1)
	src2 := mustSource(t, edited, src, settingsSpec, s)
	if want := bytes.Replace(src, []byte(`"fontSize": 13`), []byte(`"fontSize": 14`), 1); !bytes.Equal(src2, want) {
		t.Fatalf("edit changed more than the value:\n%s", src2)
	}

	// Editing an app-owned value is a no-op for the source.
	app := bytes.Replace(live, []byte(`"zoom": 1`), []byte(`"zoom": 2`), 1)
	if got := mustSource(t, app, src, settingsSpec, s); !bytes.Equal(got, src) {
		t.Fatalf("app-owned edit changed the source:\n%s", got)
	}

	// Applying on a fresh machine (no live file) gives the owned keys only.
	fresh := mustTarget(t, src, nil, settingsSpec, s)
	if !bytes.Contains(fresh, c.Bytes()) || bytes.Contains(fresh, []byte("telemetry")) {
		t.Fatalf("fresh target:\n%s", fresh)
	}
}

func TestJSONCSettingsNonMember(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	src := mustSource(t, []byte(liveSettings(c.String())), nil, settingsSpec, member(personal))
	other := member()

	// A non-member's live file: its own app keys, no sealed key.
	live := []byte(`{
  "editor": {
    "fontSize": 12
  },
  "terminal": {"font": "Other"},
  "sync": {
  },
  "zoomLevel": 3
}
`)
	tgt := mustTarget(t, src, live, settingsSpec, other)
	assertNoCanary(t, c, "non-member target", tgt)
	if bytes.Contains(tgt, []byte("token")) {
		t.Fatalf("non-member target holds the sealed key:\n%s", tgt)
	}
	if !bytes.Contains(tgt, []byte(`"zoomLevel": 3`)) || !bytes.Contains(tgt, []byte(`"fontSize": 13`)) {
		t.Fatalf("non-member target:\n%s", tgt)
	}
	// Capturing the non-member's target puts the token back: no change.
	if back := mustSource(t, tgt, src, settingsSpec, other); !bytes.Equal(back, src) {
		t.Fatalf("non-member capture changed the source:\n%s\nwant\n%s", back, src)
	}
	// A real edit on the non-member keeps the stored token.
	edited := bytes.Replace(tgt, []byte(`"fontSize": 13`), []byte(`"fontSize": 15`), 1)
	back := mustSource(t, edited, src, settingsSpec, other)
	// The source takes the non-member's layout; the token is the stored one.
	tok := src[bytes.Index(src, []byte("yadm:1:personal")):]
	tok = tok[:bytes.IndexByte(tok, '"')]
	if !bytes.Contains(back, []byte(`"fontSize": 15`)) || !bytes.Contains(back, tok) {
		t.Fatalf("non-member edit:\n%s", back)
	}
	if got := mustTarget(t, back, edited, settingsSpec, other); !bytes.Equal(got, edited) {
		t.Fatalf("non-member edit does not round-trip:\n%s", got)
	}
	// The non-member removes the whole sync object: the token still comes back.
	noSync := []byte(strings.Replace(string(edited), "  \"sync\": {\n  },\n", "", 1))
	back = mustSource(t, noSync, src, settingsSpec, other)
	if !bytes.Contains(back, []byte(`"token": "yadm:1:personal`)) {
		t.Fatalf("token lost:\n%s", back)
	}
	// A non-member cannot write a value at a sealed key.
	withVal := bytes.Replace(tgt, []byte("\"sync\": {\n  }"), []byte("\"sync\": {\n    \"token\": \"guess-guess-guess\"\n  }"), 1)
	assertViolation(t, withVal, src, settingsSpec, other, SealNotMember)
}

func TestSealGuard(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	live := []byte(liveSettings(c.String()))
	src := mustSource(t, live, nil, settingsSpec, s)

	t.Run("sealed key removed", func(t *testing.T) {
		tgt := []byte(strings.Replace(string(live), `"token": "`+c.String()+`"`, `"other": 1`, 1))
		assertViolation(t, tgt, src, settingsSpec, s, SealedKeyRemoved, c)
	})
	t.Run("parent removed", func(t *testing.T) {
		i := strings.Index(string(live), "  // Sealed for")
		j := strings.Index(string(live), "  \"telemetry\"")
		tgt := []byte(string(live)[:i] + string(live)[j:])
		assertViolation(t, tgt, src, settingsSpec, s, SealedKeyRemoved, c)
	})
	t.Run("copied to a kept key", func(t *testing.T) {
		tgt := bytes.Replace(live, []byte(`"tabSize": 2`), []byte(`"tabSize": 2, "theme": "`+c.String()+`"`), 1)
		assertViolation(t, tgt, src, settingsSpec, s, SealedValueLeaked, c)
	})
	t.Run("pasted into a comment", func(t *testing.T) {
		// In keep mode the target's comments belong to the app, so a
		// comment-only edit captures nothing; a kept value change makes the
		// capture take the comment, and the guard must catch it.
		tgt := bytes.Replace(live, []byte(`"fontSize": 13,`), []byte(`"fontSize": 14, // `+c.String()), 1)
		assertViolation(t, tgt, src, settingsSpec, s, SealedValueLeaked, c)
		only := bytes.Replace(live, []byte(`"fontSize": 13,`), []byte(`"fontSize": 13, // `+c.String()), 1)
		out, vio, err := ToSource(only, src, settingsSpec, s)
		if err != nil || len(vio) > 0 || !bytes.Equal(out, src) {
			t.Fatalf("comment-only edit: %v %v", vio, err)
		}
		seal := Spec{Format: manifest.FormatJSONC, Seal: settingsSpec.Seal}
		ssrc := mustSource(t, live, nil, seal, s)
		assertViolation(t, only, ssrc, seal, s, SealedValueLeaked, c)
	})
	t.Run("old value pasted after a change", func(t *testing.T) {
		tgt := bytes.Replace(live, []byte(c.String()), []byte("new-token-value-0001"), 1)
		tgt = bytes.Replace(tgt, []byte(`"tabSize": 2`), []byte(`"tabSize": 2, "x": "`+c.String()+`"`), 1)
		assertViolation(t, tgt, src, settingsSpec, s, SealedValueLeaked, c)
	})
	t.Run("not a string", func(t *testing.T) {
		tgt := bytes.Replace(live, []byte(`"`+c.String()+`"`), []byte(`{"v": 1}`), 1)
		assertViolation(t, tgt, src, settingsSpec, s, SealedNotString, c)
	})
	t.Run("parse failure", func(t *testing.T) {
		tgt := append(append([]byte(nil), live...), []byte("}}")...)
		assertViolation(t, tgt, src, settingsSpec, s, ParseFailed, c)
	})
}

func TestDropKeepsLiveValues(t *testing.T) {
	spec := Spec{Format: manifest.FormatJSON, Drop: []string{"window.state", "recent"}}
	live := []byte(`{
  "a": 1,
  "window": {
    // where the window was
    "state": "maximized",
    "zoom": 1
  },
  "b": [1, 2],
  "recent": ["x"]
}
`)
	s := member()
	src := mustSource(t, live, nil, spec, s)
	want := `{
  "a": 1,
  "window": {
    // where the window was
    "zoom": 1
  },
  "b": [1, 2]
}
`
	if string(src) != want {
		t.Fatalf("source:\n%s", src)
	}
	if got := mustTarget(t, src, live, spec, s); !bytes.Equal(got, live) {
		t.Fatalf("target:\n%s", got)
	}
	// The repo changes a value; the dropped values stay as the app wrote them.
	src2 := bytes.Replace(src, []byte(`"a": 1`), []byte(`"a": 2`), 1)
	got := mustTarget(t, src2, live, spec, s)
	if want := bytes.Replace(live, []byte(`"a": 1`), []byte(`"a": 2`), 1); !bytes.Equal(got, want) {
		t.Fatalf("target after repo change:\n%s", got)
	}
}

func TestWildcardAndEscapedPaths(t *testing.T) {
	spec := Spec{
		Format: manifest.FormatJSON,
		Seal:   map[string]model.EnclaveName{"mcp.servers.*.env.TOKEN": personal},
	}
	c := secrecytest.NewCanary(t, "personal")
	live := []byte(`{
  "mcp": {
    "servers": {
      "one": {"cmd": "tool-one", "env": {"TOKEN": "` + c.String() + `-1"}},
      "two": {"cmd": "tool-two", "env": {"TOKEN": "` + c.String() + `-2", "MODE": "x"}}
    }
  }
}
`)
	s := member(personal)
	src := mustSource(t, live, nil, spec, s)
	assertNoCanary(t, c, "source", src)
	if n := strings.Count(string(src), "yadm:1:personal:"); n != 2 {
		t.Fatalf("want 2 tokens, got %d:\n%s", n, src)
	}
	if got := mustTarget(t, src, live, spec, s); !bytes.Equal(got, live) {
		t.Fatalf("target:\n%s", got)
	}
	nm := mustTarget(t, src, nil, spec, member())
	assertNoCanary(t, c, "non-member target", nm)
	if bytes.Contains(nm, []byte("TOKEN")) {
		t.Fatalf("non-member target:\n%s", nm)
	}
	if back := mustSource(t, nm, src, spec, member()); !bytes.Equal(back, src) {
		t.Fatalf("non-member round trip:\n%s", back)
	}

	p, err := parsePattern(`files\.exclude.a\*b`)
	if err != nil {
		t.Fatal(err)
	}
	if !p.matches([]string{"files.exclude", "a*b"}) || p.matches([]string{"files", "exclude", "a*b"}) {
		t.Fatalf("escaped pattern: %+v", p)
	}
	if joinPath([]string{"files.exclude", "a*b"}) != `files\.exclude.a\*b` {
		t.Fatal("joinPath does not escape")
	}
}

func TestSpecErrors(t *testing.T) {
	_, err := ToTarget([]byte("{}"), nil, Spec{Format: manifest.FormatJSON, Drop: []string{"a"}, Seal: map[string]model.EnclaveName{"a.b": personal}}, member())
	if err == nil {
		t.Fatal("a dropped seal path must be refused")
	}
	if _, err := ToTarget([]byte("x"), nil, Spec{Format: "yaml", Drop: []string{"a"}}, member()); err == nil {
		t.Fatal("unknown format must fail")
	}
	if _, err := ToTarget([]byte(`{"a": "plain"}`), nil, Spec{Format: manifest.FormatJSON, Seal: map[string]model.EnclaveName{"a": personal}}, member(personal)); err == nil {
		t.Fatal("a sealed key without a token in the source must fail")
	}
}

func TestEmptySpecPassesBytes(t *testing.T) {
	in := []byte("anything\x00 at all")
	got, err := ToTarget(in, []byte("live"), Spec{}, member())
	if err != nil || !bytes.Equal(got, in) {
		t.Fatalf("got %q %v", got, err)
	}
	out, vio, err := ToSource(in, nil, Spec{}, member())
	if err != nil || len(vio) > 0 || !bytes.Equal(out, in) {
		t.Fatalf("got %q %v %v", out, vio, err)
	}
}

// TestSecrecyStores writes every capture output to a tree and a git
// repository and proves the canary reaches neither.
func TestSecrecyStores(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	repo := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(repo, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(repo, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	jsrc := mustSource(t, []byte(liveSettings(c.String())), nil, settingsSpec, s)
	write("files/settings.json", jsrc)
	tsrc := mustSource(t, []byte(tomlLive(c.String())), nil, tomlSpec, s)
	write("files/config.toml", tsrc)
	rsrc := mustSource(t, []byte(sshLive(c.String(), "\n")), nil, Spec{Regions: true}, s)
	write("files/ssh_config", rsrc)
	// A non-member's home gets only the non-member renders.
	home := t.TempDir()
	for name, pair := range map[string][2]any{
		"settings.json": {jsrc, settingsSpec},
		"config.toml":   {tsrc, tomlSpec},
		"ssh_config":    {rsrc, Spec{Regions: true}},
	} {
		out := mustTarget(t, pair[0].([]byte), nil, pair[1].(Spec), member())
		if err := os.WriteFile(filepath.Join(home, name), out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("add", "-A")
	git("commit", "-q", "-m", "test")
	secrecytest.AssertTreeClean(t, filepath.Join(repo, "files"), c)
	secrecytest.AssertRepoClean(t, repo, c)
	secrecytest.AssertTreeClean(t, home, c)
}

func TestUnsupportedEditIsNotImplemented(t *testing.T) {
	// Inserting into an array of tables is not supported by the TOML editor.
	spec := Spec{Format: manifest.FormatTOML, Drop: []string{"srv.1.secret"}}
	live := []byte("[[srv]]\nname = \"a\"\n[[srv]]\nname = \"b\"\nsecret = \"x\"\n")
	src := mustSource(t, live, nil, spec, member())
	_, err := ToTarget(src, live, spec, member())
	if err != nil && !errors.Is(err, model.ErrNotImplemented) {
		t.Fatalf("want nil or ErrNotImplemented, got %v", err)
	}
}
