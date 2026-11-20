package extexec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// Schema is the version of Request and Response.
const Schema = 1

// Kind says why the tool runs an executable.
type Kind string

// Kinds of external execution.
const (
	KindSubcommand Kind = "subcommand"
	KindCollector  Kind = "collector"
	KindTask       Kind = "task"
	KindCheck      Kind = "check"
	KindNotify     Kind = "notify"
	KindBusy       Kind = "busy"
)

// Request is written to the executable's stdin as one JSON object.
type Request struct {
	Schema  int                     `json:"schema"`
	Kind    Kind                    `json:"kind"`
	Name    string                  `json:"name"` // subcommand, collector or task name
	Machine model.Machine           `json:"machine"`
	Home    string                  `json:"home"`
	Source  string                  `json:"source"` // source clone directory
	Commit  model.CommitID          `json:"commit,omitempty"`
	Changed []model.Target          `json:"changed,omitempty"` // tasks: targets written; checks: targets staged
	Removed []model.Target          `json:"removed,omitempty"` // tasks: targets removed on this apply
	Staged  map[model.Target]string `json:"staged,omitempty"`  // checks: target -> path of a temp file with the staged plaintext (0600, deleted after)
	Trigger string                  `json:"trigger,omitempty"` // tasks: "paths", "remove" or "first-apply"
	Args    []string                `json:"args,omitempty"`    // subcommands
	JSON    bool                    `json:"json"`              // the caller asked for --json
	Event   map[string]any          `json:"event,omitempty"`   // notify: the event being reported
}

// Response is the optional JSON object an executable prints on stdout.
type Response struct {
	Schema  int             `json:"schema"`
	OK      bool            `json:"ok"`
	Items   []string        `json:"items,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
	Message string          `json:"message,omitempty"`
	Next    []string        `json:"next,omitempty"`
}

// Spec is what to run.
type Spec struct {
	Argv    []string
	Timeout time.Duration
}

// Env returns the environment variables every external execution gets:
// YADM_KIND, YADM_NAME, YADM_MACHINE (id), YADM_MACHINE_NAME, YADM_TYPES
// (comma-separated), YADM_OS, YADM_ARCH, YADM_HOME, YADM_SOURCE,
// YADM_COMMIT, YADM_JSON=1, and YADM_FACT_<KEY> for each declared fact (key
// upper-cased, non-alphanumerics as "_").
func Env(req Request) []string {
	m := req.Machine
	types := make([]string, len(m.Types))
	for i, t := range m.Types {
		types[i] = string(t)
	}
	env := []string{
		"YADM_KIND=" + string(req.Kind),
		"YADM_NAME=" + req.Name,
		"YADM_MACHINE=" + string(m.ID),
		"YADM_MACHINE_NAME=" + m.Name,
		"YADM_TYPES=" + strings.Join(types, ","),
		"YADM_OS=" + m.OS,
		"YADM_ARCH=" + m.Arch,
		"YADM_HOME=" + req.Home,
		"YADM_SOURCE=" + req.Source,
		"YADM_COMMIT=" + string(req.Commit),
		"YADM_JSON=1",
	}
	keys := make([]string, 0, len(m.Facts))
	for k := range m.Facts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		env = append(env, "YADM_FACT_"+envKey(k)+"="+m.Facts[k])
	}
	return env
}

func envKey(k string) string {
	b := []byte(strings.ToUpper(k))
	for i, c := range b {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}

// Result is what the runner observed. Response is nil when stdout was not JSON;
// Items then holds the normalized lines. When Response is set, Items holds its
// items, normalized.
type Result struct {
	ExitCode int
	Duration time.Duration
	Response *Response
	Items    []string
	Stderr   string // bounded tail
	TimedOut bool
}

// Runner runs external executables under the contract above.
type Runner interface {
	Run(ctx context.Context, spec Spec, req Request) (Result, error)
}

// ErrNotFound is returned by FindSubcommand when no yadm-<name> is on PATH.
var ErrNotFound = errors.New("external subcommand not found")

// FindSubcommand looks up yadm-<name> on PATH. A name that is empty, starts
// with "-" or holds a path separator never matches.
func FindSubcommand(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "/\\\x00") {
		return "", ErrNotFound
	}
	p, err := exec.LookPath("yadm-" + name)
	if err != nil {
		return "", ErrNotFound
	}
	return p, nil
}

// Normalize turns line output into the collector form: trimmed, non-empty,
// sorted, unique.
func Normalize(stdout []byte) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(string(stdout), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// DefaultTimeout applies when Spec.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Output bounds. Stdout beyond MaxStdout is a failure; stderr keeps only its
// last MaxStderr bytes.
const (
	MaxStdout = 4 << 20
	MaxStderr = 16 << 10
)

// killGrace is how long Run waits for the pipes to close after the process
// group was killed, or after the command exited while a descendant still
// holds its stdout.
const killGrace = 2 * time.Second

// Failure causes. Run wraps one of them in its error, so a caller can tell a
// timeout from a non-zero exit with errors.Is.
var (
	ErrNoCommand   = errors.New("empty command")
	ErrExit        = errors.New("non-zero exit")
	ErrTimeout     = errors.New("timed out")
	ErrBadResponse = errors.New("invalid JSON response")
	ErrNotOK       = errors.New("response ok=false")
	ErrTooLarge    = errors.New("stdout exceeds limit")
)

// ExitError is the error of a run that exited non-zero. It matches ErrExit
// with errors.Is, so callers that only test the cause keep working; callers
// that need the code or the stderr tail use errors.As.
type ExitError struct {
	Name   string // argv[0]
	Code   int
	Stderr string // bounded tail, never parsed
}

func (e *ExitError) Error() string { return fmt.Sprintf("%s: %v %d", e.Name, ErrExit, e.Code) }

// Is reports ErrExit as the cause.
func (e *ExitError) Is(target error) bool { return target == ErrExit }

// NewRunner returns the process runner.
func NewRunner() Runner { return runner{} }

type runner struct{}

// Run runs spec.Argv under the contract. It returns a non-nil error for an
// empty command, a start failure, a non-zero exit, a timeout, oversize stdout,
// invalid JSON or a response with ok=false. The Result is filled as far as
// the run got, so a caller can record the exit code, stderr and any response.
// On timeout, and after every run, the command's whole process group is
// killed.
func (runner) Run(ctx context.Context, spec Spec, req Request) (Result, error) {
	if len(spec.Argv) == 0 || spec.Argv[0] == "" {
		return Result{ExitCode: -1}, ErrNoCommand
	}
	if req.Schema == 0 {
		req.Schema = Schema
	}
	stdin, err := json.Marshal(req)
	if err != nil {
		return Result{ExitCode: -1}, fmt.Errorf("encode request: %w", err)
	}
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name := spec.Argv[0]
	cmd := exec.CommandContext(rctx, name, spec.Argv[1:]...)
	cmd.Dir = req.Home
	cmd.Env = append(parentEnv(), Env(req)...)
	cmd.Stdin = bytes.NewReader(stdin)
	stdout := &headBuffer{max: MaxStdout}
	stderr := &tailBuffer{max: MaxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killGroup(cmd) }
	cmd.WaitDelay = killGrace

	start := time.Now()
	runErr := cmd.Run()
	res := Result{Duration: time.Since(start), Stderr: stderr.String(), ExitCode: -1}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	// The command may have exited while a descendant kept running. The tool
	// never leaves anything behind, so kill the rest of the group either way.
	if cmd.Process != nil {
		_ = killGroup(cmd)
	}
	if rctx.Err() != nil && (runErr != nil || ctx.Err() != nil) {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		res.TimedOut = true
		return res, fmt.Errorf("%s: %w after %s", name, ErrTimeout, timeout)
	}
	if runErr != nil {
		var ee *exec.ExitError
		switch {
		case errors.As(runErr, &ee):
			return res, &ExitError{Name: name, Code: res.ExitCode, Stderr: res.Stderr}
		case errors.Is(runErr, exec.ErrWaitDelay) && res.ExitCode == 0:
			// Exited 0, but a descendant held stdout open past killGrace.
			// The group is killed above; the output read so far stands.
		default:
			return res, fmt.Errorf("%s: %w", name, runErr)
		}
	}
	if stdout.over {
		return res, fmt.Errorf("%s: %w (%d bytes)", name, ErrTooLarge, MaxStdout)
	}
	out := stdout.buf.Bytes()
	if t := bytes.TrimLeft(out, " \t\r\n"); len(t) > 0 && t[0] == '{' {
		var r Response
		dec := json.NewDecoder(bytes.NewReader(t))
		if err := dec.Decode(&r); err != nil {
			return res, fmt.Errorf("%s: %w: %v", name, ErrBadResponse, err)
		}
		if dec.More() {
			return res, fmt.Errorf("%s: %w: trailing data", name, ErrBadResponse)
		}
		res.Response = &r
		res.Items = normalizeItems(r.Items)
		if !r.OK {
			msg := r.Message
			if msg == "" {
				msg = "no message"
			}
			return res, fmt.Errorf("%s: %w: %s", name, ErrNotOK, msg)
		}
		return res, nil
	}
	res.Items = Normalize(out)
	return res, nil
}

// parentEnv is the tool's environment without any inherited YADM_ variable,
// so a nested run never sees a stale context.
func parentEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "YADM_") {
			out = append(out, kv)
		}
	}
	return out
}

func normalizeItems(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	return Normalize([]byte(strings.Join(items, "\n")))
}

// headBuffer keeps the first max bytes and notes overflow.
type headBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *headBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room < len(p) {
		b.over = true
		if room > 0 {
			b.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return b.buf.Write(p)
}

// tailBuffer keeps the last max bytes.
type tailBuffer struct {
	buf []byte
	max int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.max {
		b.buf = append(b.buf[:0], b.buf[len(b.buf)-b.max:]...)
	}
	return len(p), nil
}

func (b *tailBuffer) String() string { return string(b.buf) }
