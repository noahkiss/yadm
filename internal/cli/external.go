package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/extexec"
)

// SubcommandTimeout bounds an external yadm-<name> subcommand.
const SubcommandTimeout = 30 * time.Minute

// runExternal runs yadm-<name> from PATH under the exec contract.
func (a *app) runExternal(name string, args []string) (result, error) {
	path, err := extexec.FindSubcommand(name)
	if err != nil {
		return result{next: []string{"yadm --help"}}, usagef("unknown command %q and no yadm-%s on PATH", name, name)
	}
	ctx := context.Background()
	req := extexec.Request{Schema: extexec.Schema, Kind: extexec.KindSubcommand, Name: name, Args: args, JSON: a.json}
	if m, err := open(ctx); err == nil {
		if _, err := m.load(ctx); err != nil {
			m.snap = nil
		}
		r := m.request(extexec.KindSubcommand, name, a.json)
		r.Args = args
		req = r
	} else if home, _, herr := homeAndUser(); herr == nil {
		req.Home = home
	}
	res, err := hooks.exec().Run(ctx, extexec.Spec{Argv: append([]string{path}, args...), Timeout: SubcommandTimeout}, req)
	if err != nil {
		return result{}, err
	}
	out := result{}
	if r := res.Response; r != nil {
		out.next = r.Next
		var data any
		if len(r.Data) > 0 {
			data = json.RawMessage(r.Data)
		}
		out.data = map[string]any{"items": nonNil(res.Items), "data": data, "message": r.Message}
		out.text = r.Message
		if len(res.Items) > 0 {
			out.text = strings.TrimSpace(out.text + "\n" + strings.Join(res.Items, "\n"))
		}
	} else {
		out.data = map[string]any{"items": nonNil(res.Items)}
		out.text = strings.Join(res.Items, "\n")
	}
	switch {
	case res.TimedOut:
		return out, fmt.Errorf("yadm-%s timed out after %s", name, SubcommandTimeout)
	case res.ExitCode != 0:
		out.details = map[string]any{"exit_code": res.ExitCode, "stderr": res.Stderr}
		return out, fmt.Errorf("yadm-%s exited %d", name, res.ExitCode)
	case res.Response != nil && !res.Response.OK:
		return out, fmt.Errorf("yadm-%s: %s", name, res.Response.Message)
	}
	return out, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// runGit runs git in the source clone with the secrecy overrides. Output and
// exit code pass through; --json is not interpreted.
func (a *app) runGit(cmd *cobra.Command, args []string) error {
	a.emitted = true
	p, err := DefaultPaths()
	if err != nil {
		fmt.Fprintf(a.stderr, "yadm git: %v\n", err)
		a.code = ExitError
		return nil
	}
	if _, err := os.Stat(p.Source); err != nil {
		fmt.Fprintf(a.stderr, "yadm git: %v\n", errNotInitialized)
		a.code = ExitError
		return nil
	}
	c := exec.CommandContext(cmd.Context(), "git", append(append([]string{"-C", p.Source}, gitSecrecyArgs...), args...)...)
	c.Env = gitEnv()
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, a.stdout, a.stderr
	err = c.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		a.code = ExitOK
	case errors.As(err, &ee):
		a.code = ee.ExitCode()
	default:
		fmt.Fprintf(a.stderr, "yadm git: %v\n", err)
		a.code = ExitError
	}
	return nil
}

// legacyVerbs are upstream yadm commands this tool replaces.
var legacyVerbs = []struct{ name, replacement string }{
	{"alt", "alternates are manifest entries with a `when` condition; `yadm apply` writes them"},
	{"bootstrap", "a manifest task with first_apply = true runs on the first apply; `yadm task run <name>` runs it now"},
	{"encrypt", "files of an enclave type are sealed automatically; `yadm enclave create <type>` starts an enclave"},
	{"decrypt", "member machines open sealed files on `yadm apply`; `yadm enclave join` pins a key log"},
	{"enter", "`yadm git <args>` runs git on the source clone"},
	{"perms", "set `mode` on a manifest entry; `yadm apply` writes it"},
	{"introspect", "`yadm --help`, `yadm explain <command>`, `yadm why <path>`, `yadm managed <path>`"},
	{"gitconfig", "`yadm git config <args>`"},
	{"upgrade", "`yadm import <legacy-repo>` converts an upstream yadm repository once"},
}

func (a *app) registerLegacy(root *cobra.Command) {
	for _, v := range legacyVerbs {
		v := v
		c := &cobra.Command{Use: v.name, Short: "Removed: " + v.replacement, Hidden: true, DisableFlagParsing: true}
		c.RunE = func(cmd *cobra.Command, args []string) error {
			a.json = a.json || hasJSONFlag(args)
			a.emit(v.name, result{
				data: map[string]any{"removed": v.name, "replacement": v.replacement},
				next: []string{v.replacement},
			}, usagef("`yadm %s` is not a command of this tool: %s", v.name, v.replacement))
			return nil
		}
		root.AddCommand(c)
	}
}
