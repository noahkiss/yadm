package importer

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

const fixtureKey = "fixture-transcrypt-key"

// legacyFixture is a synthetic upstream-yadm repository.
type legacyFixture struct {
	Dir      string
	Head     string
	Machines string
	Canary   secrecytest.Canary
}

// extra files beyond testdata/legacy, written at build time.
var legacyExtra = map[string]string{
	".config/tool##class.work/config.toml":                     "work tool\n",
	".config/tool##class.work/only-work.txt":                   "only on the plain work variant\n",
	".config/tool##class.work,hostname.asset-0001/config.toml": "asset tool\n",
	"bin/hello":                            "#!/bin/sh\necho hello\n",
	".config/notes/run.sh##class.personal": "#!/bin/sh\necho @@CANARY@@\n",
	".config/shell/env.sh##class.work,template": "export DATA={{ env.HOME }}/data\n" +
		"{% include \"aliases.sh\" %}\n" +
		"{% if yadm.hostname == \"asset-0001\" %}\nexport ASSET=1\n{% endif %}\n",
	".ssh/config": "Host example\n  User someone\n",
}

var legacyExec = map[string]bool{"bin/hello": true, ".config/notes/run.sh##class.personal": true}

var legacyLinks = map[string]string{
	"bin/hi":                               "hello",
	".config/notes/latest##class.personal": "private.md",
}

// buildLegacy writes testdata/legacy plus the synthetic extras into a git
// repository. Files the attributes mark for transcrypt are committed as
// ciphertext only; the canary never enters its object store as plaintext.
func buildLegacy(t *testing.T, extra map[string]string) *legacyFixture {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "legacy")
	can := secrecytest.NewCanary(t, "personal")
	files := map[string][]byte{}
	src := fixture.LegacyDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		rel = filepath.ToSlash(rel)
		if rel == "README.txt" {
			return nil
		}
		if rel == "dot-gitattributes" {
			rel = ".gitattributes"
		}
		b, err := os.ReadFile(p)
		files[rel] = b
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range legacyExtra {
		files[k] = []byte(v)
	}
	for k, v := range extra {
		files[k] = []byte(v)
	}
	salt := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	for rel, b := range files {
		b = bytes.ReplaceAll(b, []byte("@@CANARY@@"), can.Bytes())
		if strings.HasPrefix(rel, ".config/notes/") {
			b = transcryptEncrypt(b, fixtureKey, salt)
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		mode := fs.FileMode(0o644)
		if legacyExec[rel] {
			mode = 0o755
		}
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	for rel, to := range legacyLinks {
		if err := os.Symlink(to, filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
			t.Fatal(err)
		}
	}
	gitT(t, dir, "init", "-q", "-b", "main")
	gitT(t, dir, "add", "-A")
	gitT(t, dir, "-c", "user.name=Legacy", "-c", "user.email=legacy@example.invalid", "commit", "-q", "-m", "legacy")
	head := strings.TrimSpace(gitT(t, dir, "rev-parse", "HEAD"))
	secrecytest.AssertRepoClean(t, dir, can)
	return &legacyFixture{Dir: dir, Head: head, Machines: filepath.Join(src, ".config", "yadm", "machines.tsv"), Canary: can}
}

func hermetic(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_COMMITTER_NAME", "Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.invalid")
	t.Setenv("YADM_TEST_TRANSCRYPT", fixtureKey)
}

func testOptions(lf *legacyFixture, out string, s Sealer) Options {
	return Options{
		Legacy: lf.Dir, Machines: lf.Machines, Output: out, PasswordEnv: "YADM_TEST_TRANSCRYPT",
		ClassEnclaves: map[string]model.EnclaveName{"personal": "personal"}, Sealer: s,
	}
}

func TestImportEndToEnd(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, nil)
	out := filepath.Join(t.TempDir(), "source")
	sealer := newFakeSealer()
	rep, err := Import(context.Background(), testOptions(lf, out, sealer))
	if err != nil {
		t.Fatalf("%v %v", err, rep.Problems)
	}
	if rep.Machines != 3 || rep.Commit == "" {
		t.Fatalf("report %+v", rep)
	}

	// One commit, parent the legacy head, with the trailer.
	if parent := strings.TrimSpace(gitT(t, out, "rev-parse", "HEAD^")); parent != lf.Head {
		t.Errorf("parent %s, want legacy head %s", parent, lf.Head)
	}
	if n := strings.TrimSpace(gitT(t, out, "rev-list", "--count", "HEAD")); n != "2" {
		t.Errorf("history has %s commits, want 2", n)
	}
	if msg := gitT(t, out, "log", "-1", "--format=%B"); !strings.Contains(msg, "Legacy-Head: "+lf.Head) {
		t.Errorf("no Legacy-Head trailer in %q", msg)
	}
	tree := gitT(t, out, "ls-tree", "-r", "HEAD")
	for _, want := range []string{
		"100644 blob", "\tmanifest.toml", "\tfleet.toml",
		"\tsealed/personal/.config/notes/private.md",
		"100755 blob",
	} {
		if !strings.Contains(tree, want) {
			t.Errorf("tree lacks %q", want)
		}
	}
	if strings.Contains(tree, "##") && !strings.Contains(tree, "files/.gitconfig##") {
		t.Errorf("unexpected alternate name in tree")
	}

	// Secrecy: the canary is in neither the object store nor the worktree.
	secrecytest.AssertRepoClean(t, out, lf.Canary)
	secrecytest.AssertTreeClean(t, out, lf.Canary)

	// What each machine receives.
	conv, err := convert(context.Background(), testOptions(lf, out, sealer))
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		content string // substring; "" means absent
		mode    fs.FileMode
	}
	cases := map[string]map[string]want{
		"host-a": {
			".gitconfig":                 {"os-keychain", 0o644},
			".config/notes/private.md":   {lf.Canary.String(), 0o600},
			".config/notes/latest":       {lf.Canary.String(), 0o600},
			".config/notes/run.sh":       {lf.Canary.String(), 0o700},
			".config/tool/config.toml":   {"", 0},
			".config/shell/proxy.conf":   {"proxy = laptop-a.example.invalid\n", 0o644},
			"bin/hi":                     {"echo hello", 0o755},
			".ssh/config":                {"Host example", 0o600},
			".config/shell/env.sh":       {"", 0},
			".config/yadm/machines.tsv":  {"host-a", 0o644},
			".config/tool/only-work.txt": {"", 0},
		},
		"host-b": {
			".gitconfig":                 {"Example User", 0o644},
			".config/notes/private.md":   {"", 0},
			".config/tool/config.toml":   {"asset tool", 0o644},
			".config/tool/only-work.txt": {"", 0},
			".config/shell/proxy.conf":   {"proxy = asset-0001\nwork = 1\n", 0o644},
			".config/shell/env.sh":       {"export DATA=HOMEDIR/data\nalias ll=\"ls -la\"\nexport ASSET=1\n", 0o644},
		},
		"host-c": {
			".config/tool/config.toml":   {"work tool", 0o644},
			".config/tool/only-work.txt": {"only on the plain work variant", 0o644},
			".config/shell/env.sh":       {"export DATA=HOMEDIR/data\nalias ll=\"ls -la\"\n", 0o644},
		},
	}
	for name, targets := range cases {
		m := fleetMachine(t, conv, name)
		member := func(e model.EnclaveName) bool { return m.HasType(model.TypeName(e)) }
		got, probs, err := refResolve(conv, sealer, model.Context{Machine: m, Home: "HOMEDIR", User: "test"}, member)
		if err != nil || len(probs) > 0 {
			t.Fatalf("%s: %v %v", name, err, probs)
		}
		for tg, w := range targets {
			r, ok := got[model.Target(tg)]
			if w.content == "" {
				if ok && !r.Skipped {
					t.Errorf("%s: %s should be absent, got %q", name, tg, r.Content)
				}
				continue
			}
			if !ok || r.Skipped {
				t.Errorf("%s: %s missing", name, tg)
				continue
			}
			if !strings.Contains(string(r.Content), w.content) {
				t.Errorf("%s: %s = %q, want it to contain %q", name, tg, r.Content, w.content)
			}
			if r.Mode != w.mode {
				t.Errorf("%s: %s mode %o, want %o", name, tg, r.Mode, w.mode)
			}
		}
		if !m.HasType("personal") {
			for tg, r := range got {
				if bytes.Contains(r.Content, lf.Canary.Bytes()) {
					t.Errorf("%s (not a member) receives enclave plaintext at %s", name, tg)
				}
			}
		}
	}
}

func TestImportFleet(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, nil)
	conv, err := convert(context.Background(), testOptions(lf, "", newFakeSealer()))
	if err != nil || len(conv.Problems) > 0 {
		t.Fatalf("%v %v", err, conv.Problems)
	}
	b := fleetMachine(t, conv, "host-b")
	if b.OS != "linux" || b.Facts["hostname"] != "asset-0001" || b.Facts["editor"] != "editor-two" {
		t.Errorf("host-b: %+v", b)
	}
	c := fleetMachine(t, conv, "host-c")
	if !c.HasType("work") || !c.HasType("client") || c.HasType("personal") {
		t.Errorf("host-c types %v", c.Types)
	}
	if !strings.Contains(string(conv.Fleet), "[types.personal]\nenclave = true\n") {
		t.Errorf("personal is not an enclave:\n%s", conv.Fleet)
	}
	if strings.Contains(string(conv.Manifest), "when = \"default") {
		t.Errorf("manifest mentions the default condition:\n%s", conv.Manifest)
	}
}

func TestImportProblemsWriteNothing(t *testing.T) {
	hermetic(t)
	cases := map[string]struct {
		extra  map[string]string
		mutate func(*Options)
		path   string
		reason string
	}{
		"env var": {
			extra: map[string]string{".config/bad##template": "ok\n{{ env.EDITOR }}\n"},
			path:  ".config/bad##template", reason: "env.EDITOR",
		},
		"other processor": {
			extra: map[string]string{".config/bad##template.esh": "x\n"},
			path:  ".config/bad##template.esh", reason: "esh",
		},
		"bad condition": {
			extra: map[string]string{".config/bad##flavour.sweet": "x\n"},
			path:  ".config/bad##flavour.sweet", reason: "unknown condition",
		},
		"wrong password": {
			mutate: func(o *Options) { o.PasswordEnv = "YADM_TEST_WRONG" },
			path:   ".config/notes/private.md##class.personal", reason: "password",
		},
		"no sealer": {
			mutate: func(o *Options) { o.Sealer = nil },
			path:   ".config/notes/private.md##class.personal", reason: "sealer",
		},
		"no enclave": {
			mutate: func(o *Options) { o.ClassEnclaves = nil },
			path:   ".config/notes/private.md##class.personal", reason: "enclave",
		},
		"dangling link": {
			extra: map[string]string{},
			path:  "bin/nowhere", reason: "not provided",
		},
	}
	t.Setenv("YADM_TEST_WRONG", "wrong")
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if name == "dangling link" {
				legacyLinks["bin/nowhere"] = "missing-file"
				defer delete(legacyLinks, "bin/nowhere")
			}
			lf := buildLegacy(t, c.extra)
			out := filepath.Join(t.TempDir(), "source")
			opts := testOptions(lf, out, newFakeSealer())
			if c.mutate != nil {
				c.mutate(&opts)
			}
			rep, err := Import(context.Background(), opts)
			if !errors.Is(err, ErrProblems) {
				t.Fatalf("err %v, want ErrProblems", err)
			}
			found := false
			for _, p := range rep.Problems {
				if p.Path == c.path && strings.Contains(p.Reason, c.reason) {
					found = true
				}
				if strings.Contains(p.Reason, fixtureKey) {
					t.Errorf("problem leaks the password: %s", p)
				}
			}
			if !found {
				t.Errorf("problems %v lack %s: %s", rep.Problems, c.path, c.reason)
			}
			if rep.Commit != "" {
				t.Error("commit made despite problems")
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Errorf("output written despite problems: %v", err)
			}
		})
	}
}

func TestImportRefusesNonEmptyOutput(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, nil)
	out := t.TempDir()
	if err := os.WriteFile(filepath.Join(out, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Import(context.Background(), testOptions(lf, out, newFakeSealer())); err == nil {
		t.Fatal("import into a non-empty directory succeeded")
	}
}

func TestImportDryRun(t *testing.T) {
	hermetic(t)
	lf := buildLegacy(t, nil)
	opts := testOptions(lf, "", newFakeSealer())
	opts.DryRun = true
	rep, err := Import(context.Background(), opts)
	if err != nil || rep.Commit != "" || len(rep.Mappings) == 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, m := range rep.Mappings {
		if strings.Contains(string(m.Target), "##") {
			t.Errorf("target %s keeps an alternate suffix", m.Target)
		}
	}
}
