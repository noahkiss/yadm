package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/extexec"
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

// ErrAttention wraps a successful result that has holds; it maps to ExitAttention.
var ErrAttention = errors.New("holds need attention")

// ErrRefused marks a secrecy or trust refusal; it maps to ExitRefused.
var ErrRefused = errors.New("refused")

// classify maps an error to an exit code and an error code.
func classify(err error) (int, string) {
	switch {
	case err == nil:
		return ExitOK, ""
	case errors.Is(err, ErrAttention):
		return ExitAttention, CodeAttention
	case errors.Is(err, model.ErrNotImplemented):
		return ExitNotImplemented, CodeNotImplemented
	case errors.Is(err, sync.ErrLocked):
		return ExitLocked, CodeLocked
	case errors.Is(err, ErrRefused):
		return ExitRefused, CodeRefused
	case errors.Is(err, errUsage):
		return ExitUsage, CodeUsage
	default:
		return ExitError, CodeError
	}
}

var errUsage = errors.New("usage")

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
	data any
	next []string
	text string // human output; empty means a short default
}

type runFunc func(cmd *cobra.Command, args []string) (result, error)

// app carries per-invocation state.
type app struct {
	json    bool
	stdout  io.Writer
	stderr  io.Writer
	version string
	code    int
}

func (a *app) wrap(name string, fn runFunc) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		res, err := fn(cmd, args)
		a.emit(name, res, err)
		return nil
	}
}

func (a *app) emit(name string, res result, err error) {
	code, ecode := classify(err)
	a.code = code
	if a.json {
		env := Envelope{Schema: EnvelopeSchema, Command: name, OK: err == nil || code == ExitAttention, Data: res.data, Next: res.next}
		if env.Next == nil {
			env.Next = []string{}
		}
		if err != nil {
			env.Error = &ErrorBody{Code: ecode, Message: err.Error()}
		}
		enc := json.NewEncoder(a.stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(env)
		return
	}
	if res.text != "" {
		fmt.Fprintln(a.stdout, res.text)
	}
	if err != nil {
		fmt.Fprintf(a.stderr, "yadm %s: %v\n", name, err)
	}
	for _, n := range res.next {
		fmt.Fprintf(a.stderr, "next: %s\n", n)
	}
}

func notImplemented(cmd *cobra.Command, args []string) (result, error) {
	return result{}, model.ErrNotImplemented
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
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return fmt.Errorf("%w: %v", errUsage, err)
	})

	leaf := func(parent *cobra.Command, use, short string, fn runFunc) *cobra.Command {
		c := &cobra.Command{Use: use, Short: short}
		name := use
		if i := indexSpace(use); i > 0 {
			name = use[:i]
		}
		if parent != root {
			name = parent.Name() + " " + name
		}
		c.RunE = a.wrap(name, fn)
		parent.AddCommand(c)
		return c
	}
	needSub := func(name string) func(*cobra.Command, []string) error {
		return a.wrap(name, func(c *cobra.Command, args []string) (result, error) {
			var subs []string
			for _, s := range c.Commands() {
				subs = append(subs, c.CommandPath()+" "+s.Name())
			}
			return result{next: subs}, fmt.Errorf("%w: %q needs a subcommand", errUsage, c.CommandPath())
		})
	}
	root.RunE = needSub("")
	root.Args = cobra.ArbitraryArgs
	group := func(use, short string) *cobra.Command {
		c := &cobra.Command{Use: use, Short: short, Args: cobra.ArbitraryArgs}
		c.RunE = needSub(use)
		root.AddCommand(c)
		return c
	}
	ni := notImplemented

	leaf(root, "version", "Print the version", a.cmdVersion)
	leaf(root, "where", "Print the source, state and config directories", a.cmdWhere)
	leaf(root, "machine", "Show this machine: id, name, types, facts", ni)
	leaf(root, "why <path>", "Explain how the manifest treats a path", ni)
	leaf(root, "managed <path>", "Report whether a path is managed on this machine", ni)
	leaf(root, "explain <command>", "Describe what a command would do here, step by step", ni)

	in := leaf(root, "init <remote>", "Clone the source, create this machine's identity, install the schedule", ni)
	in.Flags().String("machine", "", "machine id or name from the fleet file")
	in.Flags().Bool("allow-tasks", false, "allow every current task, check and collector definition")
	in.Flags().Bool("no-schedule", false, "do not install the sync schedule")

	leaf(root, "status", "Show drift, holds, pending commits and sync state", ni)
	ap := leaf(root, "apply [path...]", "Write changed targets for this machine", ni)
	ap.Flags().Bool("dry-run", false, "plan only")
	leaf(root, "capture [path...]", "Capture drifted targets into the source without committing", ni)
	leaf(root, "diff [path...]", "Show plaintext differences between targets and the source", ni)
	cm := leaf(root, "commit [path...]", "Capture, gate and commit now, one commit per scope", ni)
	cm.Flags().StringP("message", "m", "", "commit subject")
	sy := leaf(root, "sync", "Capture, commit by policy, fetch, replay, apply and push", ni)
	sy.Flags().Bool("auto", false, "timer mode: auto-commit by policy")
	sy.Flags().Bool("no-push", false, "do not push")
	leaf(root, "log [path]", "Show history with plaintext for enclaves this machine opens", ni)
	rt := leaf(root, "retag <path> <type>[,<type>...]", "Change which types receive a path, resealing as needed", ni)
	rt.Flags().String("enclave", "", "seal for this enclave; empty stores plaintext")
	bi := leaf(root, "bisect", "Bisect by rendering commits for a machine into a sandbox", ni)
	bi.Flags().String("as", "", "machine to render for")
	leaf(root, "collect", "Run collectors now and show observed facts", ni)
	leaf(root, "check", "Self-check: keys, key logs, schedule, last sync age, holds, secrecy config", ni)

	fl := group("fleet", "Machines, their status refs and observed facts")
	leaf(fl, "list", "List machines with last sync and hold counts", ni)
	leaf(fl, "show <machine>", "Show one machine's registry entry and status", ni)
	leaf(fl, "diff <collector>", "Compare an observed fact across machines", ni)

	en := group("enclave", "Enclave keys and membership")
	leaf(en, "list", "List enclaves, epochs and members", ni)
	leaf(en, "create <type>", "Create an enclave key log for a type", ni)
	leaf(en, "add <machine>", "Wrap the enclave keys to a machine (members only)", ni)
	rm := leaf(en, "remove <machine>", "Remove a member and start a new epoch", ni)
	rm.Flags().Bool("confirm", false, "required: removal is not reversible")
	jn := leaf(en, "join <enclave>", "Pin an enclave's key log on this machine", ni)
	jn.Flags().String("expect", "", "fingerprint of the key log entry that added this machine")
	leaf(en, "verify", "Verify every key log against the local pins", ni)

	rv := group("review", "Review auto-commits per scope")
	leaf(rv, "list [scope]", "List unreviewed commits with plaintext diffs", ni)
	leaf(rv, "ok <scope> <commit>", "Advance the reviewed ref", ni)
	leaf(rv, "revert <commit>", "Revert a commit with a new commit", ni)

	hd := group("hold", "Held files, tasks and conflicts")
	leaf(hd, "list", "List holds", ni)
	leaf(hd, "show <id>", "Show one hold with its three sides", ni)
	rs := leaf(hd, "resolve <id>", "Resolve a hold", ni)
	rs.Flags().String("take", "", "source, target, or a path to merged content")

	ls := group("lease", "Agent leases that pause auto-commit for paths")
	tk := leaf(ls, "take <path...>", "Take a lease", ni)
	tk.Flags().String("holder", "", "lease holder name")
	tk.Flags().Duration("ttl", 0, "lease lifetime")
	leaf(ls, "release <holder>", "Release a holder's leases", ni)
	leaf(ls, "list", "List leases", ni)

	ts := group("task", "On-change tasks, checks and collectors")
	leaf(ts, "list", "List definitions and whether this machine allows them", ni)
	leaf(ts, "allow [name...]", "Allow current definitions on this machine", ni)
	leaf(ts, "run <name>", "Run one task now", ni)

	sc := group("schedule", "The sync schedule (launchd or systemd)")
	leaf(sc, "install", "Install and load the schedule", ni)
	leaf(sc, "uninstall", "Unload and remove the schedule", ni)
	leaf(sc, "status", "Show whether the schedule is loaded and when it last ran", ni)

	im := leaf(root, "import <legacy-repo>", "Convert an upstream-yadm repository once", ni)
	im.Flags().String("machines", "", "machines table (TSV)")
	im.Flags().String("password-env", "", "env var holding the transcrypt password")
	im.Flags().StringToString("class-enclave", nil, "legacy class=enclave")
	im.Flags().String("default-enclave", "", "enclave for encrypted files with no class")
	im.Flags().String("output", "", "directory for the converted repository")
	ad := leaf(root, "adopt", "Switch this machine: take over identical files, hold differing ones", ni)
	ad.Flags().Bool("dry-run", false, "plan only")
	ad.Flags().Bool("allow-tasks", false, "allow every current task, check and collector definition")
	ad.Flags().Bool("no-schedule", false, "do not install the sync schedule")

	gt := &cobra.Command{
		Use:                "git [args...]",
		Short:              "Run git on the source clone",
		DisableFlagParsing: true,
	}
	gt.RunE = a.wrap("git", ni)
	root.AddCommand(gt)

	return root
}

func indexSpace(s string) int {
	for i, r := range s {
		if r == ' ' {
			return i
		}
	}
	return -1
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

	if name, ok := externalName(root, args); ok {
		a.json = hasJSONFlag(args)
		_, err := extexec.FindSubcommand(name)
		if err == nil {
			err = model.ErrNotImplemented // dispatch through extexec.Runner once it exists
		} else {
			err = fmt.Errorf("%w: unknown command %q and no yadm-%s on PATH", errUsage, name, name)
		}
		a.emit(name, result{}, err)
		return a.code
	}

	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		a.json = a.json || hasJSONFlag(args)
		if !errors.Is(err, errUsage) {
			err = fmt.Errorf("%w: %v", errUsage, err)
		}
		a.emit(commandName(args), result{}, err)
	}
	return a.code
}

// externalName reports the first argument when it names no built-in command.
func externalName(root *cobra.Command, args []string) (string, bool) {
	for _, s := range args {
		if s == "" || s[0] == '-' {
			continue
		}
		for _, c := range root.Commands() {
			if c.Name() == s || c.HasAlias(s) {
				return "", false
			}
		}
		if s == "help" || s == "completion" {
			return "", false
		}
		return s, true
	}
	return "", false
}

func hasJSONFlag(args []string) bool {
	for _, s := range args {
		if s == "--json" || s == "--json=true" {
			return true
		}
	}
	return false
}

func commandName(args []string) string {
	for _, s := range args {
		if s != "" && s[0] != '-' {
			return s
		}
	}
	return ""
}
