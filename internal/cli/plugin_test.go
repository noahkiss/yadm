package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
)

// TestReservedNamesMatchCommands keeps manifest.ReservedNames equal to the
// command tree, so no plugin can take a built-in command's name.
func TestReservedNamesMatchCommands(t *testing.T) {
	a := &app{stdout: io.Discard, stderr: io.Discard}
	var got []string
	for _, c := range a.root().Commands() {
		got = append(got, c.Name())
		got = append(got, c.Aliases...)
	}
	got = append(got, "help")
	slices.Sort(got)
	got = slices.Compact(got)
	want := slices.Clone(manifest.ReservedNames)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("manifest.ReservedNames = %v\ncommand tree       = %v", want, got)
	}
}

const pluginManifest = `schema = 1

[[file]]
target = ".config/tool/config"

[plugins.greet]
command = ["bin/greet", "fixed"]
summary = "Greets with stdio passed through"

[plugins.elsewhere]
command = ["bin/elsewhere"]
when = "os:darwin"
`

func pluginTree() map[string]string {
	t := e2eTree()
	t["manifest.toml"] = pluginManifest
	return t
}

const greetScript = `#!/bin/sh
echo "args: $*"
echo "stdin: $(cat)"
echo "pwd: $(pwd)"
echo "kind: $YADM_KIND json: ${YADM_JSON:-unset}"
echo "state: $YADM_PLUGIN_STATE"
echo "on stderr" >&2
touch "$HOME/greet.ran"
exit 7
`

func writeExec(t *testing.T, path, body string) {
	t.Helper()
	writeFile(t, path, body)
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
}

// runWithStdin runs the CLI with stdin and returns exit code, stdout and
// stderr.
func runWithStdin(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	saved := hooks.stdin
	hooks.stdin = func() io.Reader { return strings.NewReader(stdin) }
	defer func() { hooks.stdin = saved }()
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb, "test")
	return code, out.String(), errb.String()
}

// TestPluginDispatchAndTrust: a manifest plugin runs only once allowed, with
// stdin, args (--json included), the caller's directory, stdout, stderr and
// its exit code passed through. A changed script or a changed definition
// pushed from another machine is refused (exit 6) and never falls through
// to a yadm-<name> on PATH.
func TestPluginDispatchAndTrust(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, pluginTree())
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a")
	yadmOK(t, "apply")
	exe := filepath.Join(a.Home, "bin/greet")
	ran := filepath.Join(a.Home, "greet.ran")

	// Missing executable: the plugin cannot run and says why.
	if env, code, _ := yadm(t, "greet"); code != ExitError || !strings.Contains(env.Error.Message, "bin/greet") {
		t.Fatalf("missing executable: exit %d %+v", code, env.Error)
	}
	writeExec(t, exe, greetScript)
	// A yadm-greet on PATH must never stand in for a refused plugin.
	bin := filepath.Join(root, "pathbin")
	writeExec(t, filepath.Join(bin, "yadm-greet"), "#!/bin/sh\ncat >/dev/null\ntouch \"$HOME/path.ran\"\n")
	writeExec(t, filepath.Join(bin, "yadm-elsewhere"), "#!/bin/sh\ncat >/dev/null\necho from-path\n")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	env, code, _ := yadm(t, "greet", "x")
	if code != ExitRefused || len(env.Next) != 1 || env.Next[0] != "yadm plugin allow greet" {
		t.Fatalf("before allow: exit %d %+v", code, env)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("a plugin ran before it was allowed")
	}
	if _, err := os.Stat(filepath.Join(a.Home, "path.ran")); err == nil {
		t.Fatal("a refused plugin fell through to yadm-<name> on PATH")
	}
	pl := decode[map[string][]pluginView](t, yadmOK(t, "plugin", "list").Data)["plugins"]
	if len(pl) != 2 || pl[1].Name != "greet" || pl[1].Allowed || !pl[1].Applies || pl[0].Applies {
		t.Fatalf("plugin list: %+v", pl)
	}
	if out, _, _ := yadmRaw(t, "--help"); strings.Contains(out, "Greets") {
		t.Fatalf("help lists a plugin that is not allowed:\n%s", out)
	}

	if got := decode[map[string][]string](t, yadmOK(t, "plugin", "allow").Data)["allowed"]; !slices.Equal(got, []string{"greet"}) {
		t.Fatalf("allow: %v", got)
	}
	if out, _, _ := yadmRaw(t, "--help"); !strings.Contains(out, "greet") || !strings.Contains(out, "Greets with stdio passed through") {
		t.Fatalf("help does not list the allowed plugin:\n%s", out)
	}

	cwd := filepath.Join(a.Home, "work")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(cwd)
	code, stdout, stderr := runWithStdin(t, "heredoc body\n", "greet", "x", "--json", "y z")
	if code != 7 {
		t.Fatalf("exit %d, want the plugin's 7\n%s\n%s", code, stdout, stderr)
	}
	for _, want := range []string{"args: fixed x --json y z\n", "stdin: heredoc body\n", "pwd: " + cwd + "\n", "kind: plugin json: 1\n",
		"state: " + filepath.Join(a.State, PluginStateDir, "greet") + "\n"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout)
		}
	}
	if stderr != "on stderr\n" {
		t.Errorf("stderr = %q, want the plugin's own", stderr)
	}
	if _, _, err := runWithStdin(t, "", "greet"); err != "on stderr\n" {
		t.Errorf("without --json, stderr = %q", err)
	}
	if code, stdout, _ = runWithStdin(t, "", "greet"); !strings.Contains(stdout, "json: unset") {
		t.Errorf("YADM_JSON set without --json:\n%s", stdout)
	}

	// The script changes (a peer pushed new bytes): refused until allowed again.
	os.Remove(ran)
	writeExec(t, exe, greetScript+"# changed\n")
	if env, code, _ := yadm(t, "greet"); code != ExitRefused || !strings.Contains(env.Error.Message, "bin/greet") {
		t.Fatalf("changed script: exit %d %+v", code, env.Error)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("a changed script ran without a new allow")
	}
	chk, _, _ := yadm(t, "check") // other checks fail on a fresh test machine
	if items := decode[map[string][]checkItem](t, chk.Data)["checks"]; !slices.ContainsFunc(items, func(c checkItem) bool {
		return c.Name == "plugin" && c.Warn && strings.Contains(c.Detail, "greet")
	}) {
		t.Errorf("check does not warn about the changed plugin: %+v", items)
	}
	yadmOK(t, "plugin", "allow", "greet")
	if code, _, _ := runWithStdin(t, "", "greet"); code != 7 {
		t.Fatalf("re-allowed plugin: exit %d", code)
	}

	// The definition changes in the source (as a pull from a peer would).
	writeFile(t, filepath.Join(a.Source, "manifest.toml"), strings.Replace(pluginManifest, `"bin/greet", "fixed"`, `"bin/greet", "other"`, 1))
	for _, args := range [][]string{{"git", "commit", "-q", "-am", "change plugin"}} {
		if _, stderr, code := yadmRaw(t, args...); code != 0 {
			t.Fatalf("yadm %v: exit %d %s", args, code, stderr)
		}
	}
	os.Remove(ran)
	if _, code, _ := yadm(t, "greet"); code != ExitRefused {
		t.Fatalf("changed definition: exit %d", code)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("a changed definition ran without a new allow")
	}

	// A plugin whose when is false here leaves the name to PATH.
	if out, _, code := yadmRaw(t, "elsewhere"); code != 0 || out != "from-path\n" {
		t.Fatalf("elsewhere: exit %d %q", code, out)
	}
}

// TestPluginNameRules: a plugin may not shadow a built-in command, and its
// executable is a path relative to $HOME.
func TestPluginNameRules(t *testing.T) {
	for _, c := range []struct{ toml, want string }{
		{"[plugins.status]\ncommand = [\"bin/x\"]\n", "built-in command"},
		{"[plugins.Bad]\ncommand = [\"bin/x\"]\n", "plugin name"},
		{"[plugins.x]\ncommand = [\"/usr/bin/x\"]\n", "relative to $HOME"},
		{"[plugins.x]\ncommand = [\"../x\"]\n", "relative to $HOME"},
		{"[plugins.x]\ncommand = [\"bin/x\"]\nnews = [\"/bin/sh\"]\n", "news"},
		{"[plugins.x]\ncommand = []\n", "command is empty"},
	} {
		_, err := manifest.Parse([]byte("schema = 1\n" + c.toml))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err %v, want %q", c.toml, err, c.want)
		}
	}
	if _, err := manifest.Parse([]byte("schema = 1\n[plugins.my-tool_2]\ncommand = [\"bin/x\", \"a\"]\nnews = [\"bin/y\"]\nwhen = \"os:linux\"\nschema = 1\nsummary = \"s\"\n")); err != nil {
		t.Fatal(err)
	}
}

const newsManifest = `schema = 1

[[file]]
target = ".config/tool/config"

[plugins.chatty]
command = ["bin/chatty"]
news = ["bin/chatty", "news"]

[plugins.slow]
command = ["bin/slow"]
news = ["bin/slow"]

[plugins.broken]
command = ["bin/broken"]
news = ["bin/broken"]

[plugins.json]
command = ["bin/json"]
news = ["bin/json"]

[plugins.unallowed]
command = ["bin/unallowed"]
news = ["bin/unallowed"]
`

// TestPluginNewsAtSessionStart: session-start adds each allowed plugin's
// news in order, bounded per plugin and in total; a slow plugin times out,
// a failing one gets one line, an unallowed one runs nothing, and the hook
// still exits 0 within its time budget.
func TestPluginNewsAtSessionStart(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := e2eTree()
	tree["manifest.toml"] = newsManifest
	remote := seedRemote(t, root, tree)
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a")
	yadmOK(t, "apply")
	long := strings.Repeat("x", 300)
	writeExec(t, filepath.Join(a.Home, "bin/chatty"), `#!/bin/sh
cat > "$HOME/chatty.req"
[ "$1" = news ] || exit 9
echo "session $YADM_SESSION kind $YADM_KIND"
echo zeta
echo alpha
echo alpha
echo "`+long+`"
echo six
echo seven
`)
	writeExec(t, filepath.Join(a.Home, "bin/slow"), "#!/bin/sh\nsleep 30\necho late\n")
	writeExec(t, filepath.Join(a.Home, "bin/broken"), "#!/bin/sh\necho oops >&2\nexit 4\n")
	writeExec(t, filepath.Join(a.Home, "bin/json"), `#!/bin/sh
echo '{"schema":1,"ok":true,"message":"two things","items":["b","a"]}'
`)
	writeExec(t, filepath.Join(a.Home, "bin/unallowed"), "#!/bin/sh\ntouch \"$HOME/unallowed.ran\"\necho never\n")
	yadmOK(t, "plugin", "allow", "chatty", "slow", "broken", "json")

	start := time.Now()
	code, stdout, stderr := hookRun(t, payload(payloadSessionStart, "session-n", a.Home, ""), HookSessionStart, "--format", "text")
	took := time.Since(start)
	if code != HookAllow {
		t.Fatalf("session-start: exit %d\n%s\n%s", code, stdout, stderr)
	}
	if took > NewsTimeout+6*time.Second {
		t.Errorf("session-start took %s with a plugin that sleeps 30s", took)
	}
	want := []string{
		"yadm: plugin(s) not allowed here: unallowed: yadm plugin list",
		"broken: news failed: exit 4",
		"chatty: session session-n kind news",
		"chatty: zeta",
		"chatty: alpha",
		"chatty: alpha",
		"chatty: xxxx",
		"chatty: 2 more",
		"json: two things",
		"yadm: 3 more news line(s)",
	}
	var news []string
	for _, l := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		if !strings.HasPrefix(l, "yadm: synced") && !strings.HasPrefix(l, "yadm: fleet:") {
			news = append(news, l)
		}
	}
	if len(news) != len(want) {
		t.Fatalf("news lines = %d, want %d:\n%s", len(news), len(want), stdout)
	}
	for i, w := range want {
		if !strings.HasPrefix(news[i], w) {
			t.Errorf("line %d = %q, want prefix %q", i, news[i], w)
		}
	}
	if n := len([]rune(news[6])); n > len("chatty: ")+NewsLineMaxRune {
		t.Errorf("a long line is not cut: %d runes", n)
	}
	if _, err := os.Stat(filepath.Join(a.Home, "unallowed.ran")); err == nil {
		t.Error("session-start ran an unallowed plugin's news")
	}
	if req := readFile(t, filepath.Join(a.Home, "chatty.req")); !strings.Contains(req, `"kind":"news"`) || !strings.Contains(req, `"session":"session-n"`) {
		t.Errorf("news request: %s", req)
	}

	// A changed script loses its news until allowed again; with fewer lines
	// the slow plugin's timeout line fits the budget.
	writeExec(t, filepath.Join(a.Home, "bin/chatty"), "#!/bin/sh\necho changed\n")
	code, stdout, _ = hookRun(t, payload(payloadSessionStart, "session-o", a.Home, ""), HookSessionStart, "--format", "text")
	if code != HookAllow || !strings.Contains(stdout, "slow: news timed out after 3s") ||
		!strings.Contains(stdout, "not allowed here: chatty, unallowed") || strings.Contains(stdout, "changed") {
		t.Fatalf("second session-start: exit %d\n%s", code, stdout)
	}
}

// TestPluginKeepsParentPID: `yadm <plugin>` run by another yadm (a task of
// a sync that holds the lock) passes that yadm's pid on as YADM_PARENT_PID,
// so a yadm the plugin runs fails at once on the parent's lock instead of
// waiting out its bound. Run directly, the plugin gets this yadm's pid.
func TestPluginKeepsParentPID(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, pluginTree())
	a := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a")
	yadmOK(t, "apply")
	writeExec(t, filepath.Join(a.Home, "bin/greet"), "#!/bin/sh\ncat >/dev/null\necho \"parent: $YADM_PARENT_PID\"\n")
	yadmOK(t, "plugin", "allow", "greet")
	if _, out, _ := runWithStdin(t, "", "greet"); out != fmt.Sprintf("parent: %d\n", os.Getpid()) {
		t.Fatalf("run directly: %q", out)
	}
	t.Setenv("YADM_PARENT_PID", "424242")
	if _, out, _ := runWithStdin(t, "", "greet"); out != "parent: 424242\n" {
		t.Fatalf("run by another yadm: %q, want its pid", out)
	}
}
