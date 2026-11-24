package extexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// script writes an executable shell script into dir and returns its path.
func script(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func testReq(home string) Request {
	return Request{
		Kind: KindCollector, Name: "packages",
		Machine: model.Machine{ID: "m-a1b2c3", Name: "host-a", Types: []model.TypeName{"personal", "work"},
			OS: "darwin", Arch: "arm64", Facts: map[string]string{"editor": "editor-one", "my-key.x": "v"}},
		Home: home, Source: filepath.Join(home, "src"), Commit: "abc123",
	}
}

func TestRunRequestEnvAndLines(t *testing.T) {
	home := t.TempDir()
	t.Setenv("YADM_STALE", "leak")
	p := script(t, t.TempDir(), "c", `cat > req.json; env > env.txt; pwd > pwd.txt; printf ' b \n\na\na\n'`)
	res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}, Timeout: 5 * time.Second}, testReq(home))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(res.Items, ","); got != "a,b" || res.Response != nil || res.ExitCode != 0 {
		t.Fatalf("items=%q resp=%v exit=%d", got, res.Response, res.ExitCode)
	}
	var req Request
	b, _ := os.ReadFile(filepath.Join(home, "req.json"))
	if err := json.Unmarshal(b, &req); err != nil {
		t.Fatal(err)
	}
	if req.Schema != Schema || req.Kind != KindCollector || req.Machine.ID != "m-a1b2c3" || req.Commit != "abc123" {
		t.Errorf("request = %+v", req)
	}
	env, _ := os.ReadFile(filepath.Join(home, "env.txt"))
	for _, want := range []string{"YADM_KIND=collector", "YADM_NAME=packages", "YADM_MACHINE=m-a1b2c3",
		"YADM_MACHINE_NAME=host-a", "YADM_TYPES=personal,work", "YADM_OS=darwin", "YADM_ARCH=arm64",
		"YADM_HOME=" + home, "YADM_COMMIT=abc123", "YADM_JSON=1", "YADM_FACT_EDITOR=editor-one", "YADM_FACT_MY_KEY_X=v",
		EnvParentPID + "=" + strconv.Itoa(os.Getpid())} {
		if !strings.Contains(string(env), want+"\n") {
			t.Errorf("env lacks %s", want)
		}
	}
	if strings.Contains(string(env), "YADM_STALE") {
		t.Error("inherited YADM_ variable reached the child")
	}
	if !strings.Contains(string(env), "PATH=") {
		t.Error("PATH not inherited")
	}
	pwd, _ := os.ReadFile(filepath.Join(home, "pwd.txt"))
	if got, _ := filepath.EvalSymlinks(strings.TrimSpace(string(pwd))); got != mustEval(t, home) {
		t.Errorf("cwd = %s, want home", pwd)
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRunJSONResponse(t *testing.T) {
	p := script(t, t.TempDir(), "c", `echo '  {"schema":1,"ok":true,"items":["z","a","z"],"data":{"k":1},"message":"m","next":["yadm x"]}'`)
	res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}}, testReq(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if res.Response == nil || !res.Response.OK || string(res.Response.Data) != `{"k":1}` || res.Response.Message != "m" {
		t.Fatalf("response = %+v", res.Response)
	}
	if strings.Join(res.Items, ",") != "a,z" {
		t.Errorf("items = %v", res.Items)
	}
}

func TestRunFailures(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body string
		want       error
	}{
		{"exit", "echo oops >&2; exit 3", ErrExit},
		{"badjson", "echo '{not json'", ErrBadResponse},
		{"trailing", `echo '{"ok":true} {"ok":true}'`, ErrBadResponse},
		{"notok", `echo '{"schema":1,"ok":false,"message":"nope"}'`, ErrNotOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := script(t, dir, c.name, c.body)
			res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}}, testReq(t.TempDir()))
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if c.name == "exit" {
				if res.ExitCode != 3 || !strings.Contains(res.Stderr, "oops") {
					t.Errorf("exit=%d stderr=%q", res.ExitCode, res.Stderr)
				}
				var ee *ExitError
				if !errors.As(err, &ee) || ee.Code != 3 || !strings.Contains(ee.Stderr, "oops") {
					t.Errorf("typed exit error: %#v", err)
				}
			}
			if c.name == "notok" && (res.Response == nil || res.Response.OK) {
				t.Errorf("response not kept: %+v", res.Response)
			}
		})
	}
}

func TestRunEmptyAndMissing(t *testing.T) {
	r := NewRunner()
	if _, err := r.Run(context.Background(), Spec{}, Request{}); !errors.Is(err, ErrNoCommand) {
		t.Errorf("empty argv: %v", err)
	}
	if _, err := r.Run(context.Background(), Spec{Argv: []string{filepath.Join(t.TempDir(), "absent")}}, Request{Home: t.TempDir()}); err == nil {
		t.Error("missing executable: want error")
	}
}

func TestRunStdoutLimitAndStderrTail(t *testing.T) {
	p := script(t, t.TempDir(), "c", `head -c 5000000 /dev/zero | tr '\0' 'a'; head -c 40000 /dev/zero | tr '\0' 'e' >&2; echo END >&2`)
	res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}, Timeout: 10 * time.Second}, testReq(t.TempDir()))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if len(res.Stderr) != MaxStderr || !strings.HasSuffix(res.Stderr, "END\n") {
		t.Errorf("stderr len=%d tail=%q", len(res.Stderr), res.Stderr[len(res.Stderr)-8:])
	}
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func readPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile(path)
		if err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no pid in %s", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for alive(pid) {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("grandchild %d survived", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A timeout kills the whole process group, including a backgrounded grandchild
// that holds stdout open.
func TestRunTimeoutKillsGroup(t *testing.T) {
	home := t.TempDir()
	p := script(t, t.TempDir(), "c", `sleep 30 & echo $! > gc.pid; sleep 30`)
	start := time.Now()
	res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}, Timeout: 300 * time.Millisecond}, testReq(home))
	if !errors.Is(err, ErrTimeout) || !res.TimedOut {
		t.Fatalf("err=%v timedOut=%v", err, res.TimedOut)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("Run took %s", d)
	}
	waitDead(t, readPID(t, filepath.Join(home, "gc.pid")))
}

// A command that exits 0 but leaves a descendant running does not hang Run,
// and the descendant is killed.
func TestRunExitLeavesNoDescendant(t *testing.T) {
	home := t.TempDir()
	p := script(t, t.TempDir(), "c", `sleep 30 & echo $! > gc.pid; echo item`)
	start := time.Now()
	res, err := NewRunner().Run(context.Background(), Spec{Argv: []string{p}, Timeout: 20 * time.Second}, testReq(home))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > killGrace+3*time.Second {
		t.Fatalf("Run took %s", d)
	}
	if strings.Join(res.Items, ",") != "item" {
		t.Errorf("items = %v", res.Items)
	}
	waitDead(t, readPID(t, filepath.Join(home, "gc.pid")))
}

func TestRunParentCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := script(t, t.TempDir(), "c", `sleep 30`)
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	res, err := NewRunner().Run(ctx, Spec{Argv: []string{p}, Timeout: 20 * time.Second}, testReq(t.TempDir()))
	if !errors.Is(err, context.Canceled) || res.TimedOut {
		t.Fatalf("err=%v timedOut=%v", err, res.TimedOut)
	}
}

func TestFindSubcommand(t *testing.T) {
	dir := t.TempDir()
	script(t, dir, "yadm-hello", "echo hi")
	if err := os.WriteFile(filepath.Join(dir, "yadm-noexec"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	p, err := FindSubcommand("hello")
	if err != nil || p != filepath.Join(dir, "yadm-hello") {
		t.Fatalf("FindSubcommand = %q, %v", p, err)
	}
	for _, bad := range []string{"", "missing", "noexec", "../hello", "-x", "a/b"} {
		if _, err := FindSubcommand(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("FindSubcommand(%q) = %v", bad, err)
		}
	}
}

func TestNormalize(t *testing.T) {
	if got := Normalize([]byte("b\r\n  a \n\n b\n")); strings.Join(got, "|") != "a|b" {
		t.Errorf("Normalize = %q", got)
	}
	if Normalize(nil) != nil {
		t.Error("Normalize(nil) should be nil")
	}
}
