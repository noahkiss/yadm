package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	gosync "sync"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/sync"
	"github.com/noahkiss/yadm/internal/tasks"
)

// Plugin news bounds at session start (docs/hooks.md).
const (
	NewsTimeout     = 3 * time.Second // per plugin; all plugins run at once
	NewsLines       = 5               // per plugin
	NewsTotalLines  = 10              // across plugins, the trust line included
	NewsLineMaxRune = 200
)

// PluginStateDir is the directory under the state directory that holds
// one private directory per plugin ($YADM_PLUGIN_STATE).
const PluginStateDir = "plugins"

// pluginView is one plugin as `yadm plugin list` reports it.
type pluginView struct {
	Name    string             `json:"name"`
	Applies bool               `json:"applies"` // its when matches this machine
	Allowed bool               `json:"allowed"` // this definition and these executables were allowed here
	Hash    string             `json:"hash,omitempty"`
	Error   string             `json:"error,omitempty"` // why it cannot run: a missing executable, an unknown schema
	Def     manifest.PluginDef `json:"definition"`
}

// pluginState judges one plugin on this machine: its trust hash, whether
// that hash is allowed, and why it cannot run.
func (m *machineEnv) pluginState(name string, def manifest.PluginDef) pluginView {
	v := pluginView{Name: name, Def: def}
	if m.snap != nil && m.snap.Plan != nil {
		_, v.Applies = m.snap.Plan.Plugins[name]
	}
	if err := pluginSchemaErr(name, def); err != nil {
		v.Error = err.Error()
		return v
	}
	h, err := tasks.PluginHash(m.home, def)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Hash = h
	v.Allowed = m.allow.Allowed(extexec.KindPlugin, name, h)
	return v
}

func pluginSchemaErr(name string, def manifest.PluginDef) error {
	if def.Schema > extexec.Schema {
		return fmt.Errorf("plugin %s speaks exec contract schema %d; this yadm speaks %d: upgrade yadm", name, def.Schema, extexec.Schema)
	}
	return nil
}

// plugins returns every manifest plugin, sorted by name.
func (m *machineEnv) plugins() []pluginView {
	if m.snap == nil || m.snap.Manifest == nil {
		return nil
	}
	names := make([]string, 0, len(m.snap.Manifest.Plugins))
	for n := range m.snap.Manifest.Plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]pluginView, 0, len(names))
	for _, n := range names {
		out = append(out, m.pluginState(n, m.snap.Manifest.Plugins[n]))
	}
	return out
}

// pluginArgs returns the arguments after the command name in args, as
// given: a plugin gets --json and every other flag unchanged.
func pluginArgs(root *cobra.Command, args []string) []string {
	if i := commandIndex(root, args); i >= 0 {
		return append([]string{}, args[i+1:]...)
	}
	return nil
}

// runPlugin runs `yadm <name> args...` when the manifest declares plugin
// name. It reports false when no plugin answers, so the caller looks for
// yadm-<name> on PATH. A plugin that applies here but is not allowed, or
// cannot run, is refused; it never falls through to PATH.
// asJSON is whether --json appears anywhere on the command line: it picks
// the envelope of a refusal and sets YADM_JSON for the plugin.
func (a *app) runPlugin(name string, args []string, asJSON bool) bool {
	ctx := context.Background()
	m, err := open(ctx)
	if err != nil {
		return false
	}
	if _, err := m.load(ctx); err != nil || m.snap == nil || m.snap.Manifest == nil {
		return false
	}
	def, ok := m.snap.Manifest.Plugins[name]
	if !ok {
		return false
	}
	refuse := func(next []string, err error) bool {
		a.json = asJSON
		a.emit(name, result{next: next}, err)
		return true
	}
	v := m.pluginState(name, def)
	switch {
	case !v.Applies:
		if _, err := extexec.FindSubcommand(name); err == nil {
			return false
		}
		return refuse([]string{"yadm plugin list"}, usagef("plugin %s does not apply on this machine (when = %q)", name, def.When))
	case v.Error != "":
		return refuse([]string{"yadm plugin list"}, errors.New(v.Error))
	case !v.Allowed:
		return refuse([]string{"yadm plugin allow " + model.ShellQuote(name)},
			fmt.Errorf("%w: plugin %s is not allowed on this machine: its definition or the bytes of %s are new or changed since the last allow", ErrRefused, name, strings.Join(tasks.PluginExecutables(def), ", ")))
	}
	req := m.request(extexec.KindPlugin, name, asJSON)
	req.Args = args
	env, err := m.pluginEnv(name, req)
	if err != nil {
		return refuse(nil, err)
	}
	argv := append([]string{filepath.Join(m.home, filepath.FromSlash(def.Command[0]))}, def.Command[1:]...)
	argv = append(argv, args...)
	// The plugin may run yadm itself (a commit, a query): hold nothing.
	closeRepos()
	code, err := extexec.Passthrough(ctx, extexec.PassSpec{Argv: argv, Env: env, Stdin: hooks.stdin(), Stdout: a.stdout, Stderr: a.stderr})
	if err != nil {
		return refuse(nil, err)
	}
	a.emitted, a.code = true, code
	return true
}

// pluginEnv is a plugin's environment: the exec contract's variables, plus
// YADM_ENCLAVES (enclaves this machine applies), YADM_ON_DEMAND (enclaves it
// reads on demand only) and YADM_PLUGIN_STATE (a private directory, 0700).
// An inherited YADM_PARENT_PID passes through: the dispatcher holds no lock.
func (m *machineEnv) pluginEnv(name string, req extexec.Request) ([]string, error) {
	dir := filepath.Join(m.paths.State, PluginStateDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	env := append(extexec.PassEnv(req), "YADM_PLUGIN_STATE="+dir)
	if pid := os.Getenv(extexec.EnvParentPID); pid != "" {
		// This yadm runs under another one (a task, check or collector of
		// a sync that holds the lock) and holds no lock itself: a yadm the
		// plugin runs must see that holder as its own (sync.ErrSelfLocked),
		// not wait out its bound on it.
		for i, kv := range env {
			if strings.HasPrefix(kv, extexec.EnvParentPID+"=") {
				env[i] = extexec.EnvParentPID + "=" + pid
			}
		}
	}
	if m.snap != nil && m.snap.Fleet != nil {
		s := enclavesOf(m.snap)
		env = append(env, "YADM_ENCLAVES="+joinEnclaves(s.Opened), "YADM_ON_DEMAND="+joinEnclaves(s.OnDemand))
	}
	return env, nil
}

func joinEnclaves(es []model.EnclaveName) string {
	s := make([]string, len(es))
	for i, e := range es {
		s[i] = string(e)
	}
	return strings.Join(s, ",")
}

func (a *app) registerPlugins(root *cobra.Command) {
	pl := a.group(root, "plugin", "Manifest plugins: `yadm <name>` runs one with stdio passed through")
	pl.Long = "Manifest plugins: `yadm <name>` runs one with stdio passed through.\n\n" + pluginHelp
	a.leaf(pl, "list", "List plugins and whether this machine allows them", a.cmdPluginList)
	al := a.leaf(pl, "allow [name...]", "Allow plugins as they are now: definition and executable bytes (all that apply here when no name is given)", a.cmdPluginAllow)
	al.Long = "Allow plugins as they are now.\n\n" + pluginHelp
}

const pluginHelp = `A [plugins.<name>] manifest table declares a plugin. Its command is a path
relative to $HOME plus arguments; ` + "`yadm <name> args...`" + ` runs it with the args
appended, in the caller's directory, with stdin, stdout, stderr and the
terminal passed through and its exit code as yadm's.

A plugin runs only after ` + "`yadm plugin allow <name>`" + ` on this machine. The allow
records a hash of the definition and of the bytes of each executable it
names, so a changed definition or a changed script from any machine is
refused (exit 6) until it is allowed again. A plugin may not take a
built-in command's name.`

func (a *app) cmdPluginList(cmd *cobra.Command, args []string) (result, error) {
	m, err := openLoaded(cmd.Context())
	if err != nil {
		return notInit(err), err
	}
	ps := m.plugins()
	var b strings.Builder
	var next []string
	for _, p := range ps {
		state := fmt.Sprintf("allowed=%v applies=%v", p.Allowed, p.Applies)
		if p.Error != "" {
			state += " error: " + p.Error
		}
		fmt.Fprintf(&b, "%-20s %s\n", p.Name, state)
		if p.Applies && !p.Allowed && p.Error == "" {
			next = append(next, "yadm plugin allow "+model.ShellQuote(p.Name))
		}
	}
	if ps == nil {
		ps = []pluginView{}
	}
	return result{data: map[string]any{"plugins": ps}, text: b.String(), next: next}, nil
}

func (a *app) cmdPluginAllow(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	var done []string
	var failed []string
	// The allow list is state a sync reads: write it under the lock, from
	// the definitions at main once the lock is held.
	err = m.locked(ctx, func() error {
		if _, err := m.reload(ctx); err != nil {
			return err
		}
		want := map[string]bool{}
		for _, n := range args {
			want[n] = true
		}
		for _, p := range m.plugins() {
			if len(args) > 0 && !want[p.Name] || len(args) == 0 && !p.Applies {
				continue
			}
			delete(want, p.Name)
			if p.Error != "" {
				failed = append(failed, p.Error)
				continue
			}
			if err := m.allow.Allow(extexec.KindPlugin, p.Name, p.Hash); err != nil {
				return err
			}
			done = append(done, p.Name)
		}
		if len(want) > 0 {
			var missing []string
			for n := range want {
				missing = append(missing, n)
			}
			sort.Strings(missing)
			return usagef("no plugin named %s in manifest.toml", strings.Join(missing, ", "))
		}
		return nil
	})
	if done == nil {
		done = []string{}
	}
	data := map[string]any{"allowed": done}
	if errors.Is(err, sync.ErrLocked) {
		return lockedResult(err), err
	}
	if err == nil && len(failed) > 0 {
		err = fmt.Errorf("not allowed: %s", strings.Join(failed, "; "))
	}
	return result{data: data, text: "allowed: " + strings.Join(done, ", ")}, err
}

// pluginHelpLines lists the plugins `yadm <name>` runs here: allowed, and
// their when true on this machine. A machine that is not set up has none.
func pluginHelpLines() []pluginView {
	ctx := context.Background()
	m, err := open(ctx)
	if err != nil {
		return nil
	}
	defer closeRepos()
	if _, err := m.load(ctx); err != nil {
		return nil
	}
	var out []pluginView
	for _, p := range m.plugins() {
		if p.Applies && p.Allowed {
			out = append(out, p)
		}
	}
	return out
}

// pluginCheck warns about each plugin that applies here but cannot run.
func (m *machineEnv) pluginChecks() []checkItem {
	var out []checkItem
	for _, p := range m.plugins() {
		switch {
		case !p.Applies:
		case p.Error != "":
			out = append(out, checkItem{Name: "plugin", OK: true, Warn: true, Detail: p.Error})
		case !p.Allowed:
			out = append(out, checkItem{Name: "plugin", OK: true, Warn: true,
				Detail: fmt.Sprintf("%s is new or changed and not allowed here: yadm plugin allow %s", p.Name, model.ShellQuote(p.Name))})
		}
	}
	return out
}

// pluginNews runs the news query of each plugin that applies here and is
// allowed, all at once, each bounded by NewsTimeout, and returns at most
// NewsTotalLines lines: NewsLines per plugin, each cut to NewsLineMaxRune
// runes. Plugins that apply but are not allowed get one line together. A
// failing or slow plugin gets one line; nothing here fails the hook.
func (m *machineEnv) pluginNews(ctx context.Context, session string) []string {
	if m.snap == nil || m.snap.Manifest == nil {
		return nil
	}
	var untrusted []string
	type job struct {
		name string
		argv []string
		out  []string
	}
	var jobs []*job
	for _, p := range m.plugins() {
		switch {
		case !p.Applies:
		case !p.Allowed || p.Error != "":
			untrusted = append(untrusted, p.Name)
		case len(p.Def.News) > 0:
			argv := append([]string{filepath.Join(m.home, filepath.FromSlash(p.Def.News[0]))}, p.Def.News[1:]...)
			jobs = append(jobs, &job{name: p.Name, argv: argv})
		}
	}
	runner := m.exec
	var wg gosync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j *job) {
			defer wg.Done()
			req := m.request(extexec.KindNews, j.name, true)
			req.Session = session
			res, err := runner.Run(ctx, extexec.Spec{Argv: j.argv, Timeout: NewsTimeout, KeepOrder: true}, req)
			var ee *extexec.ExitError
			switch {
			case errors.As(err, &ee):
				j.out = []string{fmt.Sprintf("%s: news failed: exit %d", j.name, ee.Code)}
			case res.TimedOut:
				j.out = []string{fmt.Sprintf("%s: news timed out after %s", j.name, NewsTimeout)}
			case err != nil:
				j.out = []string{fmt.Sprintf("%s: news failed: %s", j.name, oneLine(err.Error()))}
			default:
				items := res.Items
				if r := res.Response; r != nil && r.Message != "" {
					items = append([]string{r.Message}, items...)
				}
				for i, it := range items {
					if i == NewsLines {
						j.out = append(j.out, fmt.Sprintf("%s: %d more", j.name, len(items)-NewsLines))
						break
					}
					j.out = append(j.out, j.name+": "+cutRunes(oneLine(it), NewsLineMaxRune))
				}
			}
		}(j)
	}
	wg.Wait()
	var lines []string
	if len(untrusted) > 0 {
		lines = append(lines, fmt.Sprintf("yadm: plugin(s) not allowed here: %s: yadm plugin list", strings.Join(untrusted, ", ")))
	}
	for _, j := range jobs {
		lines = append(lines, j.out...)
	}
	if len(lines) > NewsTotalLines {
		lines = append(lines[:NewsTotalLines-1], fmt.Sprintf("yadm: %d more news line(s)", len(lines)-NewsTotalLines+1))
	}
	return lines
}

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}
