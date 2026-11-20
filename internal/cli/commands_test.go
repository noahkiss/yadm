package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/importer"
)

func TestExternalSubcommand(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	useMachine(t, root, "x")
	bin := filepath.Join(root, "bin")
	scripts := map[string]string{
		"yadm-hello": `#!/bin/sh
read req
case "$req" in *'"kind":"subcommand"'*) ;; *) exit 9 ;; esac
echo '{"schema":1,"ok":true,"items":["b","a"],"message":"hi '"$YADM_KIND"'","next":["yadm status"]}'
`,
		"yadm-lines": "#!/bin/sh\ncat >/dev/null\nprintf 'two\\none\\n\\n'\n",
		"yadm-fails": "#!/bin/sh\ncat >/dev/null\necho oops >&2\nexit 3\n",
	}
	for n, s := range scripts {
		writeFile(t, filepath.Join(bin, n), s)
		if err := os.Chmod(filepath.Join(bin, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	env, code, _ := yadm(t, "hello", "arg1")
	d := decode[map[string]any](t, env.Data)
	if code != ExitOK || env.Command != "hello" || d["message"] != "hi subcommand" || len(env.Next) != 1 {
		t.Fatalf("hello: exit %d %+v", code, env)
	}
	if items := d["items"].([]any); len(items) != 2 || items[0] != "a" {
		t.Fatalf("items not normalized: %v", items)
	}
	env, code, _ = yadm(t, "lines")
	if code != ExitOK || len(decode[map[string][]string](t, env.Data)["items"]) != 2 {
		t.Fatalf("lines: exit %d %+v", code, env.Data)
	}
	if env, code, _ = yadm(t, "fails"); code != ExitError || !strings.Contains(env.Error.Message, "exited 3") {
		t.Fatalf("fails: exit %d %+v", code, env.Error)
	}
	out, _, code := yadmRaw(t, "lines")
	if code != 0 || out != "one\ntwo\n" {
		t.Fatalf("human output %q exit %d", out, code)
	}
}

func TestLegacyVerbs(t *testing.T) {
	hermetic(t)
	useMachine(t, t.TempDir(), "x")
	for _, v := range legacyVerbs {
		env, code, _ := yadm(t, v.name, "--some", "args")
		if code != ExitUsage || env.Command != v.name || len(env.Next) != 1 || env.Next[0] != v.replacement {
			t.Fatalf("%s: exit %d %+v", v.name, code, env)
		}
		_, stderr, code := yadmRaw(t, v.name)
		if code != ExitUsage || !strings.Contains(stderr, v.replacement) {
			t.Fatalf("%s human: exit %d %q", v.name, code, stderr)
		}
	}
}

func TestImport(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	useMachine(t, root, "x")
	legacy := filepath.Join(root, "legacy")
	git(t, root, "init", "-q", "-b", "main", legacy)
	writeFile(t, filepath.Join(legacy, ".config/app/settings##os.Linux"), "linux\n")
	writeFile(t, filepath.Join(legacy, ".config/app/settings##default"), "default\n")
	writeFile(t, filepath.Join(legacy, ".profile"), "export A=1\n")
	git(t, legacy, "add", "-A")
	git(t, legacy, "commit", "-q", "-m", "legacy")
	head := git(t, legacy, "rev-parse", "HEAD")

	env := yadmOK(t, "import", legacy, "--dry-run")
	rep := decode[importData](t, env.Data)
	if rep.Commit != "" || len(rep.Mappings) != 3 {
		t.Fatalf("dry run: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(root, "out")); err == nil {
		t.Fatal("dry run wrote output")
	}
	if _, code, _ := yadm(t, "import", legacy); code != ExitUsage {
		t.Fatalf("import without --output: exit %d", code)
	}
	out := filepath.Join(root, "out")
	env = yadmOK(t, "import", legacy, "--output", out)
	rep = decode[importData](t, env.Data)
	if rep.Commit == "" || rep.Machines == 0 && len(rep.Mappings) != 3 {
		t.Fatalf("import: %+v", rep)
	}
	if p := git(t, out, "rev-parse", string(rep.Commit)+"^"); p != head {
		t.Fatalf("import parent %s, want legacy head %s", p, head)
	}

	// A path the importer cannot convert: nothing is written, exit 1, problems listed.
	writeFile(t, filepath.Join(legacy, ".x##bogus.y"), "x\n")
	git(t, legacy, "add", "-A")
	git(t, legacy, "commit", "-q", "-m", "bad")
	env, code, _ := yadm(t, "import", legacy, "--output", filepath.Join(root, "out2"))
	if code != ExitError || env.Error.Details == nil {
		t.Fatalf("import with problems: exit %d %+v", code, env.Error)
	}
	if ps := decode[importData](t, env.Data).Problems; len(ps) == 0 {
		t.Fatalf("no problems listed: %+v", env.Data)
	}
	if _, err := os.Stat(filepath.Join(root, "out2", ".git")); err == nil {
		t.Fatal("import with problems wrote a repository")
	}

	// Sealing needs this machine's identity.
	t.Setenv("LEGACY_PW", "pw")
	if env, code, _ := yadm(t, "import", legacy, "--output", filepath.Join(root, "out3"), "--password-env", "LEGACY_PW"); code != ExitError || len(env.Next) == 0 {
		t.Fatalf("import sealing without identity: exit %d %+v", code, env)
	}
	_ = importer.ErrProblems
}

func TestHumanOutput(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, e2eTree())
	useMachine(t, root, "a")
	if _, stderr, code := yadmRaw(t, "init", remote, "--machine", "host-a", "--no-schedule"); code != 0 {
		t.Fatalf("init: %d %s", code, stderr)
	}
	out, stderr, code := yadmRaw(t, "apply")
	if code != 0 || !strings.Contains(out, "write   .config/tool/config") {
		t.Fatalf("apply: exit %d out %q err %q", code, out, stderr)
	}
	out, _, code = yadmRaw(t, "version")
	if code != 0 || out != "yadm test\n" {
		t.Fatalf("version: %q", out)
	}
	_, stderr, code = yadmRaw(t, "nope-cmd")
	if code != ExitUsage || !strings.Contains(stderr, "unknown command") {
		t.Fatalf("unknown: %d %q", code, stderr)
	}
}
