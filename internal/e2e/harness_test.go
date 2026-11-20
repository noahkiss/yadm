package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	binOnce sync.Once
	binPath string
	binErr  error
)

// yadmBin returns the binary under test: $YADM_E2E_BIN, or ./cmd/yadm built
// once into a temp directory.
func yadmBin(t testing.TB) string {
	t.Helper()
	binOnce.Do(func() {
		if p := os.Getenv("YADM_E2E_BIN"); p != "" {
			binPath = p
			return
		}
		dir, err := os.MkdirTemp("", "yadm-e2e-bin-")
		if err != nil {
			binErr = err
			return
		}
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..")
		binPath = filepath.Join(dir, "yadm")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/yadm")
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			binErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if binErr != nil {
		t.Fatal(binErr)
	}
	return binPath
}

// World is a set of simulated machines sharing one bare remote.
type World struct {
	t      testing.TB
	Root   string
	Remote string
	Shim   string
	bin    string
	gitDir string
}

// NewWorld makes the temp root, the shim directory and an empty bare remote.
func NewWorld(t testing.TB) *World {
	t.Helper()
	root, err := os.MkdirTemp("", "yadm-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("YADM_E2E_KEEP") == "" {
		t.Cleanup(func() { _ = os.RemoveAll(root) })
	} else {
		t.Logf("keeping %s", root)
	}
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	w := &World{t: t, Root: root, Shim: filepath.Join(root, "shim"), Remote: filepath.Join(root, "remote.git"), bin: yadmBin(t), gitDir: filepath.Dir(git)}
	if err := os.MkdirAll(w.Shim, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"launchctl", "systemctl"} {
		script := "#!/bin/sh\necho \"" + c + " $*\" >> \"" + filepath.Join(w.Shim, "calls.log") + "\"\nexit 0\n"
		if err := os.WriteFile(filepath.Join(w.Shim, c), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	w.Git("", "init", "-q", "--bare", "-b", "main", w.Remote)
	return w
}

// baseEnv is the stripped environment every child process gets.
func (w *World) baseEnv() []string {
	path := w.Shim + string(os.PathListSeparator) + w.gitDir + string(os.PathListSeparator) + "/usr/bin:/bin:/usr/sbin:/sbin"
	env := []string{
		"PATH=" + path,
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"LANG=C",
		"TMPDIR=" + os.TempDir(),
	}
	return env
}

// Git runs plain git with the stripped environment and a neutral identity
// file, and fails the test on error. It returns trimmed stdout.
func (w *World) Git(dir string, args ...string) string {
	w.t.Helper()
	out, err := w.GitErr(dir, nil, args...)
	if err != nil {
		w.t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return out
}

// GitErr runs plain git; stdin may be nil.
func (w *World) GitErr(dir string, stdin []byte, args ...string) (string, error) {
	if dir != "" {
		args = append([]string{"-C", dir}, args...)
	}
	args = append([]string{"-c", "diff.cachetextconv=false"}, args...)
	cmd := exec.Command(filepath.Join(w.gitDir, "git"), args...)
	cmd.Env = append(w.baseEnv(), "HOME="+w.Root)
	cmd.Env = append(cmd.Env, gitIdentity()...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String()), fmt.Errorf("%v: %s", err, tail(errb.String(), 400))
	}
	return strings.TrimSpace(out.String()), nil
}

// gitIdentity gives plain git a neutral author for harness commits.
func gitIdentity() []string {
	who := []string{"AUTHOR", "COMMITTER"}
	var env []string
	for _, w := range who {
		env = append(env, "GIT_"+w+"_NAME=e2e", "GIT_"+w+"_EMAIL=e2e@example.invalid")
	}
	return env
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}

// UnitCalls returns the launchctl and systemctl calls the shim saw.
func (w *World) UnitCalls() []string {
	b, err := os.ReadFile(filepath.Join(w.Shim, "calls.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// Machine is one simulated machine.
type Machine struct {
	w      *World
	Name   string
	Root   string
	Home   string
	Source string
	State  string
	Config string
	User   string
	// ID, Recipient and SignKey come from init.
	ID        string
	Recipient string
	SignKey   string
}

// NewMachine makes a machine's directories. Nothing runs yet.
func (w *World) NewMachine(name, user string) *Machine {
	w.t.Helper()
	root := filepath.Join(w.Root, "m", name)
	home := filepath.Join(root, "home")
	m := &Machine{w: w, Name: name, Root: root, Home: home, User: user,
		Source: filepath.Join(root, "data", "yadm", "source"),
		State:  filepath.Join(root, "state", "yadm"),
		Config: filepath.Join(root, "config", "yadm")}
	if err := os.MkdirAll(home, 0o755); err != nil {
		w.t.Fatal(err)
	}
	return m
}

// env is the machine's environment. State, data and config live beside
// $HOME, not in it, so a scan of $HOME sees only targets.
func (m *Machine) env() []string {
	return append(m.w.baseEnv(),
		"HOME="+m.Home,
		"USER="+m.User,
		"LOGNAME="+m.User,
		"XDG_DATA_HOME="+filepath.Join(m.Root, "data"),
		"XDG_STATE_HOME="+filepath.Join(m.Root, "state"),
		"XDG_CONFIG_HOME="+filepath.Join(m.Root, "config"),
	)
}

// Result is one binary run.
type Result struct {
	Args   []string
	Code   int
	Stdout []byte
	Stderr string
	Env    Envelope
	Dur    time.Duration
}

// Envelope mirrors the cli output contract.
type Envelope struct {
	Schema  int             `json:"schema"`
	Command string          `json:"command"`
	OK      bool            `json:"ok"`
	Data    json.RawMessage `json:"data"`
	Next    []string        `json:"next"`
	Error   *struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Details json.RawMessage `json:"details"`
	} `json:"error"`
}

// Err is a one-line, content-free summary of a failed run: exit code, error
// code and the first part of the message.
func (r Result) Err() string {
	s := fmt.Sprintf("exit %d", r.Code)
	if r.Env.Error != nil {
		s += " " + r.Env.Error.Code + ": " + clip(r.Env.Error.Message, 300)
	} else if r.Stderr != "" {
		s += ": " + clip(r.Stderr, 300)
	}
	return s
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " | ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Run runs yadm --json with args on this machine.
func (m *Machine) Run(args ...string) Result {
	return m.RunIn(nil, args...)
}

// RunIn runs yadm --json with stdin.
func (m *Machine) RunIn(stdin []byte, args ...string) Result {
	m.w.t.Helper()
	return m.RunEnv(nil, stdin, args...)
}

// RunEnv runs yadm with extra environment entries.
func (m *Machine) RunEnv(extra []string, stdin []byte, args ...string) Result {
	m.w.t.Helper()
	full := append(append([]string{}, args...), "--json")
	if len(args) > 0 && args[0] == "hook" {
		full = args // hooks print a verdict, not an envelope
	}
	cmd := exec.Command(m.w.bin, full...)
	cmd.Env = append(m.env(), extra...)
	cmd.Dir = m.Home
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	r := Result{Args: args, Stdout: out.Bytes(), Stderr: errb.String(), Dur: time.Since(start)}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			r.Code = ee.ExitCode()
		} else {
			m.w.t.Fatalf("%s: yadm %s: %v", m.Name, strings.Join(args, " "), err)
		}
	}
	if args[0] != "hook" && args[0] != "git" {
		_ = json.Unmarshal(out.Bytes(), &r.Env)
	}
	return r
}

// OK runs a command and fails the test unless it exits 0 or 3 (attention).
func (m *Machine) OK(args ...string) Result {
	m.w.t.Helper()
	r := m.Run(args...)
	if r.Code != 0 && r.Code != 3 {
		m.w.t.Fatalf("%s: yadm %s: %s", m.Name, strings.Join(args, " "), r.Err())
	}
	return r
}

// Decode unmarshals the envelope data into v.
func (r Result) Decode(v any) error {
	if len(r.Env.Data) == 0 {
		return fmt.Errorf("no data")
	}
	return json.Unmarshal(r.Env.Data, v)
}

// Init runs yadm init against the world's remote and records the identity.
func (m *Machine) Init(machineArg string) Result {
	m.w.t.Helper()
	r := m.Run("init", m.w.Remote, "--machine", machineArg, "--no-schedule")
	if r.Code != 0 && r.Code != 3 {
		return r
	}
	var d struct {
		Machine   string `json:"machine"`
		Recipient string `json:"recipient"`
		SignKey   string `json:"sign_key"`
	}
	if err := r.Decode(&d); err != nil {
		m.w.t.Fatalf("%s: init data: %v", m.Name, err)
	}
	m.ID, m.Recipient, m.SignKey = d.Machine, d.Recipient, d.SignKey
	return r
}

// Hold is the subset of a hold object the harness reads.
type Hold struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	Task   string `json:"task"`
	Scope  string `json:"scope"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

// Holds lists this machine's holds.
func (m *Machine) Holds() []Hold {
	m.w.t.Helper()
	r := m.Run("hold", "list")
	var d struct {
		Holds []Hold `json:"holds"`
	}
	if err := r.Decode(&d); err != nil {
		m.w.t.Fatalf("%s: hold list: %s", m.Name, r.Err())
	}
	return d.Holds
}

// Main is this machine's local main, read with plain git.
func (m *Machine) Main() string {
	out, err := m.w.GitErr(m.Source, nil, "rev-parse", "-q", "--verify", "refs/heads/main")
	if err != nil {
		return ""
	}
	return out
}

// RemoteMain is the bare remote's main.
func (w *World) RemoteMain() string {
	out, err := w.GitErr(w.Remote, nil, "rev-parse", "-q", "--verify", "refs/heads/main")
	if err != nil {
		return ""
	}
	return out
}

// WriteHome writes a target under $HOME with a past mtime, so a quiet period
// has passed.
func (m *Machine) WriteHome(target string, b []byte, age time.Duration) {
	m.w.t.Helper()
	p := filepath.Join(m.Home, filepath.FromSlash(target))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		m.w.t.Fatal(err)
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(p); err == nil {
		mode = st.Mode().Perm()
		if mode&0o200 == 0 {
			_ = os.Chmod(p, mode|0o200)
		}
	}
	tmp := p + ".e2e-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		m.w.t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		m.w.t.Fatal(err)
	}
	if age > 0 {
		ts := time.Now().Add(-age)
		_ = os.Chtimes(p, ts, ts)
	}
}

// ReadHome reads a target; ok is false when it is missing.
func (m *Machine) ReadHome(target string) ([]byte, bool) {
	b, err := os.ReadFile(filepath.Join(m.Home, filepath.FromSlash(target)))
	return b, err == nil
}
