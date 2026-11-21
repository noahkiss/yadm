package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

const globNewManifest = hookManifest + `
[[file]]
target = ".local/libexec/dotfiles/**"
`

// globalExcludes points git's global config at an excludes file holding
// pattern, as a user's ~/.config/git/ignore would.
func globalExcludes(t *testing.T, pattern string) {
	t.Helper()
	dir := t.TempDir()
	ignore := filepath.Join(dir, "ignore")
	writeFile(t, ignore, pattern+"\n")
	cfg := filepath.Join(dir, "gitconfig")
	writeFile(t, cfg, "[core]\n\texcludesFile = "+ignore+"\n")
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)
}

// TestCommitNewFileUnderGlob: a new file that an applying glob entry
// matches, with no source yet, is captured by `yadm commit <path>` and by
// `yadm track <path>`: its source lands under the entry, no manifest entry
// is added, and a peer receives it. A user's global git excludes that match
// the path change nothing. `yadm sync` alone does not pick the file up.
func TestCommitNewFileUnderGlob(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := hookTree()
	tree["manifest.toml"] = globNewManifest
	tree["files/.local/libexec/dotfiles/old-script"] = "#!/bin/sh\necho old\n"
	remote := seedRemote(t, root, tree)
	hookMachine(t, root, remote, "b", "host-b")
	a := hookMachine(t, root, remote, "a", "host-a")
	globalExcludes(t, "*.local/")

	const script = ".local/libexec/dotfiles/new-script"
	abs := filepath.Join(a.Home, script)
	writeFile(t, abs, "#!/bin/sh\necho new\n")
	if err := os.Chmod(abs, 0o755); err != nil {
		t.Fatal(err)
	}
	x := decode[manifest.Explanation](t, yadmOK(t, "why", script).Data)
	if x.Managed || len(x.Rejected) != 1 || !strings.Contains(x.Rejected[0].Reason, "yadm commit "+script) {
		t.Fatalf("why before the commit: %+v", x)
	}

	// The timer's sync leaves it alone: a new file outside an owned root is
	// a decision.
	head := git(t, a.Source, "rev-parse", "main")
	yadmOK(t, "sync")
	if got := git(t, a.Source, "rev-parse", "main"); got != head {
		t.Fatalf("sync committed a new file under a glob:\n%s", git(t, a.Source, "show", "--stat", "main"))
	}

	if env, code, _ := yadm(t, "commit", "--dry-run", script); code != ExitOK {
		t.Fatalf("commit --dry-run: exit %d %+v", code, env.Error)
	}
	env := yadmOK(t, "commit", script)
	if pushed := decode[struct{ Pushed bool }](t, env.Data).Pushed; !pushed {
		t.Fatalf("commit did not push: %+v", env.Data)
	}
	if subj := git(t, a.Source, "log", "-1", "--format=%s", "main"); subj != "add "+script {
		t.Fatalf("subject %q", subj)
	}
	if files := git(t, a.Source, "show", "--name-only", "--format=", "main"); files != "files/"+script {
		t.Fatalf("commit files: %q", files)
	}
	if ls := git(t, a.Source, "ls-tree", "main", "files/"+script); !strings.HasPrefix(ls, "100755 ") {
		t.Fatalf("source mode: %q", ls)
	}
	if man := git(t, a.Source, "show", "main:manifest.toml"); man != strings.TrimSpace(globNewManifest) {
		t.Fatalf("the manifest changed:\n%s", man)
	}
	x = decode[manifest.Explanation](t, yadmOK(t, "why", script).Data)
	if !x.Managed || x.Resolved == nil || x.Resolved.Entry.Target != ".local/libexec/dotfiles/**" {
		t.Fatalf("why after the commit: %+v", x)
	}
	st := decode[struct {
		Drift []any
		Holds []any
	}](t, yadmOK(t, "status").Data)
	if len(st.Drift) != 0 || len(st.Holds) != 0 {
		t.Fatalf("status after the commit: %+v", st)
	}
	if out, _, code := yadmRaw(t, "git", "status", "--porcelain", "--ignored"); code != 0 || out != "" {
		t.Fatalf("the clone is not clean: exit %d %q", code, out)
	}

	// track takes the same path: it captures under the glob entry.
	const other = ".local/libexec/dotfiles/sub/other"
	writeFile(t, filepath.Join(a.Home, other), "other\n")
	env = yadmOK(t, "track", other)
	d := decode[struct {
		Target, Source, Scope, Commit, Glob string
		Pushed                              bool
	}](t, env.Data)
	if d.Target != other || d.Source != "files/"+other || d.Scope != "shared" || d.Commit == "" || !d.Pushed || d.Glob != ".local/libexec/dotfiles/**" {
		t.Fatalf("track data: %+v", d)
	}
	if man := git(t, a.Source, "show", "main:manifest.toml"); man != strings.TrimSpace(globNewManifest) {
		t.Fatalf("track added an entry:\n%s", man)
	}
	// A second entry for a glob-covered path would collide: refused.
	writeFile(t, filepath.Join(a.Home, ".local/libexec/dotfiles/third"), "3\n")
	if env, code, _ := yadm(t, "track", ".local/libexec/dotfiles/third", "--when", "type:work"); code != ExitUsage || !strings.Contains(env.Error.Message, "yadm commit") {
		t.Fatalf("track --when under a glob: exit %d %+v", code, env.Error)
	}

	b := useMachine(t, root, "b")
	yadmOK(t, "sync")
	if got := readFile(t, filepath.Join(b.Home, script)); got != "#!/bin/sh\necho new\n" {
		t.Fatalf("host-b %s: %q", script, got)
	}
	if info, err := os.Stat(filepath.Join(b.Home, script)); err != nil || info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("host-b %s mode: %v %v", script, info, err)
	}
	if got := readFile(t, filepath.Join(b.Home, other)); got != "other\n" {
		t.Fatalf("host-b %s: %q", other, got)
	}
}

// TestCommitNewFileUnderSealedGlob: a new file under a glob entry with an
// enclave is sealed into sealed/<enclave>/ by a member, and held by a
// non-member; a new file under a glob entry with sealed key paths commits
// only the sealed value. No canary reaches any repository or a
// non-member's $HOME.
func TestCommitNewFileUnderSealedGlob(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	man := filepath.Join(fx.Root, "manifest.toml")
	// The fixture's check runs a command no test machine allowed; the gate
	// would hold every file.
	const check = "[checks.no-private-keys]\npaths = [\"**\"]\ncommand = [\"secret-check\", \"--stdin-json\"]\ntimeout = \"20s\"\n"
	base := readFile(t, man)
	if !strings.Contains(base, check) {
		t.Fatal("fixture manifest lacks its check")
	}
	writeFile(t, man, strings.Replace(base, check, "", 1)+`
[[file]]
target = ".config/vault/**"
enclave = "personal"

[[file]]
target = ".config/apps/*.json"
format = "json"
seal = { "token" = "personal" }

[[file]]
target = ".config/shell/private/**"
enclave = "personal"
`)
	remote := fixtureRemote(t, root, fx)
	canary := fx.Canaries["personal"]

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")
	writeFile(t, filepath.Join(a.Home, ".config/vault/new"), "secret "+canary.String()+"\n")
	writeFile(t, filepath.Join(a.Home, ".config/apps/new.json"), `{"token": "`+canary.String()+`", "theme": "dark"}`+"\n")
	// One commit per scope: personal and shared. The fixture's untrusted
	// tasks and root hold too; they are not this test's concern.
	if env := yadmOK(t, "commit", ".config/vault/new", ".config/apps/new.json"); len(decode[struct{ Commits []string }](t, env.Data).Commits) != 2 {
		t.Fatalf("member commit: %s", mustJSON(t, env.Data))
	}
	files := git(t, a.Source, "ls-tree", "-r", "--name-only", "main")
	if !strings.Contains(files, "sealed/personal/.config/vault/new") || strings.Contains(files, "files/.config/vault/new") {
		t.Fatalf("enclave glob file not sealed:\n%s", files)
	}
	src := git(t, a.Source, "show", "main:files/.config/apps/new.json")
	if !strings.Contains(src, `"theme": "dark"`) || strings.Contains(src, canary.String()) {
		t.Fatalf("sealed key path source: %s", src)
	}
	if got := readFile(t, filepath.Join(a.Home, ".config/vault/new")); !strings.Contains(got, canary.String()) {
		t.Fatalf("member target changed: %q", got)
	}
	st := decode[struct {
		Drift []struct{ Target string }
		Holds []struct{ Target string }
	}](t, yadmOK(t, "status").Data)
	for _, d := range st.Drift {
		if d.Target == ".config/vault/new" || d.Target == ".config/apps/new.json" {
			t.Fatalf("drift after the commit: %+v", st)
		}
	}
	for _, h := range st.Holds {
		if h.Target == ".config/vault/new" || h.Target == ".config/apps/new.json" {
			t.Fatalf("hold after the commit: %+v", st)
		}
	}

	// A file inside the plain owned root .config/shell that the enclave
	// glob matches is the glob's: an unnamed commit seals it.
	yadmOK(t, "root", "allow", ".config/shell")
	writeFile(t, filepath.Join(a.Home, ".config/shell/private/env"), "export K="+canary.String()+"\n")
	yadmOK(t, "commit")
	files = git(t, a.Source, "ls-tree", "-r", "--name-only", "main")
	if !strings.Contains(files, "sealed/personal/.config/shell/private/env") || strings.Contains(files, "files/.config/shell/private/env") {
		t.Fatalf("a glob file in an owned root was not sealed:\n%s", files)
	}
	secrecytest.AssertRepoClean(t, a.Source, canary)
	secrecytest.AssertRepoClean(t, remote, canary)

	// host-b is not a member: its new file under the enclave glob is held,
	// never committed in plaintext.
	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	secrecytest.AssertTreeClean(t, b.Home, canary)
	head := git(t, b.Source, "rev-parse", "main")
	mine := secrecytest.NewCanary(t, "non-member")
	writeFile(t, filepath.Join(b.Home, ".config/vault/mine"), "mine "+mine.String()+"\n")
	env, code, _ := yadm(t, "commit", ".config/vault/mine")
	if code != ExitAttention {
		t.Fatalf("non-member commit: exit %d %+v", code, env.Error)
	}
	hs := decode[struct {
		Holds []struct{ Target, Reason string }
	}](t, env.Data).Holds
	var guarded bool
	for _, h := range hs {
		guarded = guarded || h.Target == ".config/vault/mine" && h.Reason == "seal_guard"
	}
	if !guarded {
		t.Fatalf("non-member holds: %+v", hs)
	}
	if got := git(t, b.Source, "rev-parse", "main"); got != head {
		t.Fatal("a non-member committed a file under an enclave glob")
	}
	secrecytest.AssertRepoClean(t, b.Source, canary, mine)
	secrecytest.AssertRepoClean(t, remote, canary, mine)
}
