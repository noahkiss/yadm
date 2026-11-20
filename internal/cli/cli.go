package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/sync"
)

// EnvelopeSchema is the version of the JSON envelope.
const EnvelopeSchema = 1

// Exit codes. They are a stable contract.
const (
	ExitOK             = 0 // success, nothing needs attention
	ExitError          = 1 // the command failed
	ExitUsage          = 2 // bad flags or arguments
	ExitAttention      = 3 // the command succeeded but holds or conflicts exist (Data lists them)
	ExitLocked         = 4 // another yadm process holds the lock; retry later
	ExitNotImplemented = 5
	ExitRefused        = 6 // refused for secrecy or trust: non-member, unsigned key change, untrusted task
)

// Error codes in ErrorBody.Code.
const (
	CodeError          = "error"
	CodeUsage          = "usage"
	CodeLocked         = "locked"
	CodeNotImplemented = "not_implemented"
	CodeRefused        = "refused"
	CodeAttention      = "attention"
)

// Envelope is the one JSON object a command prints under --json.
type Envelope struct {
	Schema  int        `json:"schema"`
	Command string     `json:"command"`
	OK      bool       `json:"ok"`
	Data    any        `json:"data"`
	Next    []string   `json:"next"`
	Error   *ErrorBody `json:"error"`
}

// ErrorBody describes a failure.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// ErrAttention wraps a successful result that has holds; it maps to
// ExitAttention. The envelope stays ok (the command did its work) and its
// error carries code "attention"; data lists what needs attention.
var ErrAttention = errors.New("holds need attention")

// ErrRefused marks a secrecy or trust refusal; it maps to ExitRefused.
var ErrRefused = errors.New("refused")

// refusals are the errors of other packages that mean "refused for secrecy
// or trust" (exit 6).
var refusals = []error{
	ErrRefused,
	crypt.ErrInvalidLog,
	crypt.ErrNotPinned,
	crypt.ErrBadSignature,
	crypt.ErrBrokenChain,
	crypt.ErrNotMember,
}

// classify maps an error to an exit code and an error code.
func classify(err error) (int, string) {
	if err == nil {
		return ExitOK, ""
	}
	switch {
	case errors.Is(err, ErrAttention):
		return ExitAttention, CodeAttention
	case errors.Is(err, errUsage):
		return ExitUsage, CodeUsage
	case errors.Is(err, sync.ErrLocked):
		return ExitLocked, CodeLocked
	}
	for _, r := range refusals {
		if errors.Is(err, r) {
			return ExitRefused, CodeRefused
		}
	}
	if errors.Is(err, model.ErrNotImplemented) {
		return ExitNotImplemented, CodeNotImplemented
	}
	return ExitError, CodeError
}

var errUsage = errors.New("usage")

// usagef returns a usage error (exit 2).
func usagef(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

// Paths are the tool's directories on this machine.
type Paths struct {
	Source string `json:"source"` // the source clone
	State  string `json:"state"`  // state DB, private indexes, identity, pins, backups, lock
	Config string `json:"config"` // machine.toml
}

// DefaultPaths follows the XDG base directory variables with the usual fallbacks.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" && filepath.IsAbs(v) {
			return v
		}
		return filepath.Join(home, def)
	}
	return Paths{
		Source: filepath.Join(env("XDG_DATA_HOME", ".local/share"), "yadm", "source"),
		State:  filepath.Join(env("XDG_STATE_HOME", ".local/state"), "yadm"),
		Config: filepath.Join(env("XDG_CONFIG_HOME", ".config"), "yadm"),
	}, nil
}

// result is what a command body returns.
type result struct {
	data    any
	next    []string
	text    string // human output; empty means a short default
	details any    // ErrorBody.Details on failure
}

type runFunc func(cmd *cobra.Command, args []string) (result, error)

// app carries per-invocation state.
type app struct {
	json    bool
	stdout  io.Writer
	stderr  io.Writer
	version string
	code    int
	emitted bool
}

func (a *app) wrap(name string, fn runFunc) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		res, err := fn(cmd, args)
		a.emit(name, res, err)
		return nil
	}
}

func (a *app) emit(name string, res result, err error) {
	if a.emitted {
		return
	}
	a.emitted = true
	code, ecode := classify(err)
	a.code = code
	if a.json {
		env := Envelope{Schema: EnvelopeSchema, Command: name, OK: err == nil || code == ExitAttention, Data: res.data, Next: res.next}
		if env.Next == nil {
			env.Next = []string{}
		}
		if err != nil {
			env.Error = &ErrorBody{Code: ecode, Message: err.Error(), Details: res.details}
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(env)
		return
	}
	if res.text != "" {
		fmt.Fprintln(a.stdout, strings.TrimRight(res.text, "\n"))
	} else if res.data != nil && err == nil {
		// No human rendering: print the data as indented JSON.
		b, _ := json.MarshalIndent(res.data, "", "  ")
		fmt.Fprintln(a.stdout, string(b))
	}
	if err != nil && code != ExitAttention {
		fmt.Fprintf(a.stderr, "yadm %s: %v\n", name, err)
	}
	for _, n := range res.next {
		fmt.Fprintf(a.stderr, "next: %s\n", n)
	}
}

// NewRoot builds the command tree.
func NewRoot(version string) *cobra.Command {
	a := &app{stdout: os.Stdout, stderr: os.Stderr, version: version}
	return a.root()
}

func (a *app) root() *cobra.Command {
	root := &cobra.Command{
		Use:           "yadm",
		Short:         "Dotfiles on every machine, kept in sync",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&a.json, "json", false, "print one JSON envelope on stdout")
	root.PersistentFlags().Bool("interactive", false, "allow prompts (no command prompts without it)")
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return fmt.Errorf("%w: %v", errUsage, err)
	})
	root.CompletionOptions.DisableDefaultCmd = true

	defHelp := root.HelpFunc()
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if !a.json {
			defHelp(c, args)
			return
		}
		var subs []string
		for _, s := range c.Commands() {
			if !s.Hidden {
				subs = append(subs, s.CommandPath())
			}
		}
		a.emit(strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "yadm")), result{data: map[string]any{
			"usage": c.UseLine(), "short": c.Short, "commands": subs, "flags": c.Flags().FlagUsages(),
		}}, nil)
	})

	a.register(root)
	return root
}

// leaf adds a command whose envelope name is its path below the root.
func (a *app) leaf(parent *cobra.Command, use, short string, fn runFunc) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short}
	name := use
	if i := strings.IndexByte(use, ' '); i > 0 {
		name = use[:i]
	}
	if parent.HasParent() {
		name = strings.TrimSpace(strings.TrimPrefix(parent.CommandPath(), "yadm")) + " " + name
	}
	c.RunE = a.wrap(name, fn)
	parent.AddCommand(c)
	return c
}

// group adds a command that needs a subcommand.
func (a *app) group(root *cobra.Command, use, short string) *cobra.Command {
	c := &cobra.Command{Use: use, Short: short, Args: cobra.ArbitraryArgs}
	c.RunE = a.needSub(use)
	root.AddCommand(c)
	return c
}

func (a *app) needSub(name string) func(*cobra.Command, []string) error {
	return a.wrap(name, func(c *cobra.Command, args []string) (result, error) {
		var subs []string
		for _, s := range c.Commands() {
			if !s.Hidden {
				subs = append(subs, s.CommandPath())
			}
		}
		if len(args) > 0 {
			return result{next: subs}, usagef("%q has no subcommand %q", c.CommandPath(), args[0])
		}
		return result{next: subs}, usagef("%q needs a subcommand", c.CommandPath())
	})
}

func (a *app) cmdVersion(cmd *cobra.Command, args []string) (result, error) {
	data := map[string]string{
		"version": a.version,
		"go":      runtime.Version(),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	}
	return result{data: data, text: "yadm " + a.version}, nil
}

func (a *app) cmdWhere(cmd *cobra.Command, args []string) (result, error) {
	p, err := DefaultPaths()
	if err != nil {
		return result{}, err
	}
	return result{data: p, text: fmt.Sprintf("source %s\nstate  %s\nconfig %s", p.Source, p.State, p.Config)}, nil
}

// Main runs the CLI and returns the exit code.
func Main(args []string, stdout, stderr io.Writer, version string) int {
	a := &app{stdout: stdout, stderr: stderr, version: version}
	root := a.root()

	if name, rest, ok := externalName(root, args); ok {
		a.json = hasJSONFlag(args)
		res, err := a.runExternal(name, rest)
		a.emit(name, res, err)
		return a.code
	}

	root.SetArgs(args)
	// Cobra prints nothing itself (SilenceErrors); capture anything it might
	// write so --json keeps stdout to one envelope.
	var spill bytes.Buffer
	if hasJSONFlag(args) {
		root.SetOut(&spill)
		root.SetErr(&spill)
	}
	if err := root.Execute(); err != nil {
		a.json = a.json || hasJSONFlag(args)
		if !errors.Is(err, errUsage) {
			err = fmt.Errorf("%w: %v", errUsage, err)
		}
		a.emit(commandName(root, args), result{next: []string{"yadm --help"}}, err)
	}
	if !a.emitted {
		// Help or another cobra path that ran no command body.
		a.emit(commandName(root, args), result{}, nil)
	}
	return a.code
}

// externalName reports the first argument when it names no built-in command,
// with the arguments after it (minus --json).
func externalName(root *cobra.Command, args []string) (string, []string, bool) {
	for i, s := range args {
		if s == "" || s[0] == '-' {
			continue
		}
		for _, c := range root.Commands() {
			if c.Name() == s || c.HasAlias(s) {
				return "", nil, false
			}
		}
		if s == "help" {
			return "", nil, false
		}
		var rest []string
		for _, r := range args[i+1:] {
			if r != "--json" && r != "--json=true" {
				rest = append(rest, r)
			}
		}
		return s, rest, true
	}
	return "", nil, false
}

func hasJSONFlag(args []string) bool {
	for _, s := range args {
		if s == "--" {
			return false
		}
		if s == "--json" || s == "--json=true" {
			return true
		}
	}
	return false
}

// commandName is the envelope name for args that failed before a command body
// ran: the path of the deepest command cobra finds.
func commandName(root *cobra.Command, args []string) string {
	if c, _, err := root.Find(args); err == nil && c != nil && c != root {
		return strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), "yadm"))
	}
	for _, s := range args {
		if s != "" && s[0] != '-' {
			return s
		}
	}
	return ""
}
