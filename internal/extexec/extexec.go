package extexec

import (
	"context"
	"encoding/json"
	"errors"
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
// Items then holds the normalized lines.
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

// FindSubcommand looks up yadm-<name> on PATH.
func FindSubcommand(name string) (string, error) {
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

// NewRunner returns the process runner.
func NewRunner() Runner { return runner{} }

type runner struct{}

func (runner) Run(ctx context.Context, spec Spec, req Request) (Result, error) {
	return Result{}, model.ErrNotImplemented
}
