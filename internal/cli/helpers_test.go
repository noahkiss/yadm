package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/schedule"
	"github.com/noahkiss/yadm/internal/tasks"
)

// hermetic isolates git and the scheduler from the developer's machine for
// the whole test binary run of one test.
func hermetic(t *testing.T) {
	t.Helper()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	// The global excludes file ($XDG_CONFIG_HOME/git/ignore or
	// $HOME/.config/git/ignore) would hide fixture files from `git add`.
	neutral := t.TempDir()
	t.Setenv("HOME", neutral)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(neutral, ".config"))
	t.Setenv("GIT_AUTHOR_NAME", "Test User")
	t.Setenv("GIT_AUTHOR_EMAIL", "user@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Test User")
	t.Setenv("GIT_COMMITTER_EMAIL", "user@example.invalid")
	t.Setenv("USER", "user")
	t.Setenv(schedule.LiveEnv, "")
	t.Setenv(LockWaitEnv, "")
	for _, k := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	saved := hooks
	t.Cleanup(func() { hooks = saved })
	hooks.units = func() tasks.UnitReloader { return nopUnits{} }
	hooks.binary = func() string { return "/usr/local/bin/yadm" }
	// A scheduler that writes only under the current $HOME and runs no
	// service manager.
	hooks.scheduler = func() (schedule.Scheduler, error) {
		home, _ := os.UserHomeDir()
		return schedule.New("linux", schedule.Options{Home: home, ConfigHome: filepath.Join(home, ".config"), Commander: &fakeCommander{}, Live: true})
	}
}

type nopUnits struct{}

func (nopUnits) Reload(context.Context, manifest.Unit, string) error { return nil }

type fakeCommander struct{ calls [][]string }

func (f *fakeCommander) Run(_ context.Context, argv []string) ([]byte, error) {
	f.calls = append(f.calls, argv)
	if len(argv) > 2 && argv[len(argv)-2] == "is-active" {
		return []byte("inactive\n"), nil
	}
	return nil, nil
}

// machineDirs points $HOME and the XDG directories at one fake machine.
type machineDirs struct {
	Home string
	Paths
}

func useMachine(t *testing.T, root, name string) machineDirs {
	t.Helper()
	home := filepath.Join(root, name, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	p, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	return machineDirs{Home: home, Paths: p}
}

// yadm runs the CLI with --json and decodes the one envelope.
func yadm(t *testing.T, args ...string) (Envelope, int, []byte) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(append(args, "--json"), &out, &errb, "test")
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("yadm %v: stdout is not one JSON envelope: %v\n%s\nstderr: %s", args, err, out.String(), errb.String())
	}
	if dec.More() {
		t.Fatalf("yadm %v: stdout holds more than one JSON value:\n%s", args, out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("yadm %v: --json wrote to stderr: %q", args, errb.String())
	}
	checkInvariant(t, args, env, code)
	return env, code, out.Bytes()
}

// checkInvariant asserts the envelope contract: schema, ok and error agree
// with the exit code.
func checkInvariant(t *testing.T, args []string, env Envelope, code int) {
	t.Helper()
	if env.Schema != EnvelopeSchema || env.Next == nil {
		t.Fatalf("yadm %v: bad envelope %+v", args, env)
	}
	want := map[int]string{ExitError: CodeError, ExitUsage: CodeUsage, ExitLocked: CodeLocked, ExitNotImplemented: CodeNotImplemented, ExitRefused: CodeRefused}
	switch code {
	case ExitOK:
		if !env.OK || env.Error != nil {
			t.Fatalf("yadm %v: exit %d with ok=%v error=%+v", args, code, env.OK, env.Error)
		}
	case ExitAttention:
		if !env.OK || env.Error == nil || env.Error.Code != CodeAttention {
			t.Fatalf("yadm %v: exit %d with ok=%v error=%+v", args, code, env.OK, env.Error)
		}
	default:
		if env.OK || env.Error == nil || env.Error.Code != want[code] {
			t.Fatalf("yadm %v: exit %d with ok=%v error=%+v", args, code, env.OK, env.Error)
		}
	}
}

// yadmOK runs a command that must exit 0 or 3.
func yadmOK(t *testing.T, args ...string) Envelope {
	t.Helper()
	env, code, _ := yadm(t, args...)
	if code != ExitOK && code != ExitAttention {
		t.Fatalf("yadm %v: exit %d: %+v", args, code, env.Error)
	}
	return env
}

// yadmRaw runs the CLI without --json.
func yadmRaw(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb, "test")
	return out.String(), errb.String(), code
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// seedRemote creates a bare remote whose main holds the files in tree.
func seedRemote(t *testing.T, root string, tree map[string]string) string {
	t.Helper()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "seed")
	git(t, root, "init", "-q", "--bare", "-b", "main", remote)
	git(t, root, "init", "-q", "-b", "main", work)
	for p, c := range tree {
		writeFile(t, filepath.Join(work, p), c)
	}
	git(t, work, "add", "-A")
	git(t, work, "commit", "-q", "-m", "seed")
	git(t, work, "push", "-q", remote, "main")
	return remote
}

func decode[T any](t *testing.T, v any) T {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return out
}
