package oracle

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProfiles(t *testing.T) {
	in := "hostname\tfriendly\tclasses\tos\tdecrypt\n" +
		"host-a\talpha\tpersonal\tLinux\tyes\n" +
		"host-b\tbeta\twork,corp\t\tno\n"
	ps, err := ParseProfiles(strings.NewReader(in), "Darwin")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("got %d profiles", len(ps))
	}
	if ps[0].OS != "Linux" || !ps[0].Decrypt || ps[0].User != UserToken {
		t.Errorf("profile 0: %+v", ps[0])
	}
	if ps[1].OS != "Darwin" || ps[1].Decrypt || strings.Join(ps[1].Classes, ",") != "work,corp" {
		t.Errorf("profile 1: %+v", ps[1])
	}
	if _, err := ParseProfiles(strings.NewReader("hostname\tclasses\nhost-a\tx\n"), ""); err == nil {
		t.Error("want error when no os is known")
	}
}

func TestNormalize(t *testing.T) {
	got := Normalize([]byte("/sb/home/x and /sb/data"), [][2]string{{"/sb/home", HomeToken}, {"/sb", "@@SANDBOX@@"}})
	if string(got) != HomeToken+"/x and @@SANDBOX@@/data" {
		t.Errorf("got %q", got)
	}
}

// fixture builds a synthetic dotfiles repo. Encryption is added when
// transcrypt is installed.
func fixture(t *testing.T, git string, withCrypt bool) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "src")
	files := map[string]string{
		".plain":                            "plain\n",
		".shell##class.personal":            "personal shell\n",
		".shell##class.work":                "work shell\n",
		".editor##os.Linux":                 "linux editor\n",
		".editor##os.Darwin":                "mac editor\n",
		".host##class.work,hostname.host-b": "host-b only\n",
		".rendered##template": "home={{env.HOME}}\n" +
			"{% if yadm.class == \"work\" %}\nwork line\n{% else %}\nother line\n{% endif %}\n" +
			"os={{yadm.os}} host={{yadm.hostname}}\n\n\n",
		".config/tool##class.work/a.conf":     "a\n",
		".config/tool##class.work/sub/b.conf": "b\n",
		".secret##class.personal":             "personal secret\n",
		".config/key##class.personal/k":       "personal key\n",
		"bin/run":                             "#!/bin/sh\necho run\n",
	}
	if withCrypt {
		files[".gitattributes"] = "*##class.personal filter=crypt diff=crypt merge=crypt\n" +
			"*##class.personal/** filter=crypt diff=crypt merge=crypt\n" +
			"**/*##class.personal/** filter=crypt diff=crypt merge=crypt\n"
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0o644)
		if strings.HasPrefix(name, "bin/") {
			mode = 0o755
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(".plain", filepath.Join(dir, ".plain-link")); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid")
	runIn := func(name string, args ...string) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
	}
	runIn(git, "init", "-q", "-b", "main")
	if withCrypt {
		runIn("transcrypt", "-y", "-c", "aes-256-cbc", "-p", "fixture-password")
	}
	runIn(git, "add", "-A")
	runIn(git, "commit", "-q", "-m", "fixture")
	return filepath.Join(dir, ".git")
}

func TestRunFixture(t *testing.T) {
	// The oracle drives upstream yadm. YADM_ORACLE_BIN names it when the yadm
	// on PATH is this project's binary.
	yadm := os.Getenv("YADM_ORACLE_BIN")
	if yadm == "" {
		var err error
		if yadm, err = exec.LookPath("yadm"); err != nil {
			t.Skip("stock yadm not installed")
		}
	}
	if v, _ := exec.Command(yadm, "version").CombinedOutput(); !strings.Contains(string(v), "yadm version") {
		t.Skipf("%s is not upstream yadm; set YADM_ORACLE_BIN", yadm)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	_, terr := exec.LookPath("transcrypt")
	withCrypt := terr == nil
	src := fixture(t, git, withCrypt)
	out := t.TempDir()

	profiles := []Profile{
		{Name: "personal", Hostname: "host-a", Classes: []string{"personal"}, OS: "Linux", User: UserToken, Decrypt: withCrypt},
		{Name: "work", Hostname: "host-b", Classes: []string{"other", "work"}, OS: "Darwin", User: UserToken},
	}
	got := map[string]*Manifest{}
	for _, p := range profiles {
		m, err := Run(Options{Repo: src, Out: out, Yadm: yadm, Git: git, Profile: p})
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		got[p.Name] = m
	}
	find := func(m *Manifest, path string) *Entry {
		for i := range m.Targets {
			if m.Targets[i].Path == path {
				return &m.Targets[i]
			}
		}
		return nil
	}
	read := func(name, path string) string {
		b, err := os.ReadFile(filepath.Join(out, name, "content", path))
		if err != nil {
			t.Fatalf("%s %s: %v", name, path, err)
		}
		return string(b)
	}

	pm, wm := got["personal"], got["work"]
	if e := find(pm, ".shell"); e == nil || e.Kind != KindLink || e.Source != ".shell##class.personal" {
		t.Errorf("personal .shell: %+v", e)
	}
	if read("personal", ".shell") != "personal shell\n" || read("work", ".shell") != "work shell\n" {
		t.Error("wrong .shell content")
	}
	if read("personal", ".editor") != "linux editor\n" || read("work", ".editor") != "mac editor\n" {
		t.Error("os override did not select the alternate")
	}
	if find(pm, ".host") != nil || find(wm, ".host") == nil {
		t.Error("hostname alternate selected wrongly")
	}
	e := find(wm, ".rendered")
	if e == nil || !e.Template || e.Source != ".rendered##template" || !e.Normalized {
		t.Fatalf("work .rendered: %+v", e)
	}
	want := "home=" + HomeToken + "\nwork line\nos=Darwin host=host-b\n"
	if r := read("work", ".rendered"); r != want {
		t.Errorf("work .rendered = %q, want %q", r, want)
	}
	if r := read("personal", ".rendered"); !strings.Contains(r, "other line") || !strings.Contains(r, "os=Linux") {
		t.Errorf("personal .rendered = %q", r)
	}
	if e := find(wm, ".config/tool/sub/b.conf"); e == nil || e.Source != ".config/tool##class.work/sub/b.conf" || e.LinkAt != ".config/tool" {
		t.Errorf("dir alternate: %+v", e)
	}
	if e := find(wm, "bin/run"); e == nil || e.Mode != "0755" || e.Kind != KindPlain {
		t.Errorf("bin/run: %+v", e)
	}
	if e := find(wm, ".plain-link"); e == nil || !e.TrackedSymlink {
		t.Errorf("tracked symlink: %+v", e)
	}
	for _, m := range got {
		for _, e := range m.Targets {
			if strings.Contains(e.Path, "##") && e.LinkAt == "" {
				t.Errorf("%s: target with ## name: %s", m.Profile.Name, e.Path)
			}
		}
	}

	if !withCrypt {
		t.Log("transcrypt not installed; encryption checks skipped")
		return
	}
	// The enclave guarantee: the work profile holds no personal plaintext.
	if len(wm.Encrypted) == 0 {
		t.Fatal("no encrypted paths detected")
	}
	if find(wm, ".secret") != nil {
		t.Error("work profile resolved a personal path")
	}
	for _, u := range wm.Unresolved {
		if strings.Contains(u.Path, "##class.personal") && u.Kind == KindPlain && !u.Ciphertext {
			t.Errorf("work profile holds plaintext of %s", u.Path)
		}
	}
	err = filepath.Walk(filepath.Join(out, "work"), func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), "personal secret") || strings.Contains(string(b), "personal key") {
			t.Errorf("personal plaintext in work output: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if read("personal", ".secret") != "personal secret\n" || read("personal", ".config/key/k") != "personal key\n" {
		t.Error("personal profile did not decrypt")
	}
	var raw map[string]any
	b, _ := os.ReadFile(filepath.Join(out, "work", "manifest.json"))
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
}
