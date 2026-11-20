package tasks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Staged is one file about to be committed, as a check sees it.
type Staged struct {
	Target    model.Target
	Scope     model.Scope
	Plaintext []byte // written to a 0600 temp file for the check, removed afterwards
}

// Verdict is the commit gate's answer for one target.
type Verdict struct {
	Target model.Target `json:"target"`
	Check  string       `json:"check"`
	Pass   bool         `json:"pass"`
	Detail string       `json:"detail,omitempty"`
}

// Gate is the fail-closed commit gate. Every commit, manual or automatic,
// passes through it. A target fails when any matching check exits non-zero,
// times out, returns ok=false, or is not allowed on this machine.
type Gate interface {
	Check(ctx context.Context, staged []Staged, req extexec.Request) (pass []model.Target, holds []model.Hold, verdicts []Verdict)
}

// NewGate returns the gate for the checks a plan selected, with no staging
// directory: a check that matches a staged target fails closed. Use
// NewGateIn with the state directory to run checks.
func NewGate(checks map[string]manifest.CheckDef, r extexec.Runner, allow AllowList) Gate {
	return NewGateIn(checks, r, allow, "")
}

// NewGateIn is NewGate with the directory that holds staged plaintext while
// a check runs: the state directory, never a shared temp directory. Each
// check gets a fresh 0700 subdirectory, removed when the check returns, on
// every path. An empty dir stages nothing: every check that matches a
// staged target holds it as check_failed.
//
// The gate fails closed:
//   - a nil AllowList or Runner holds every staged target;
//   - a check with an invalid glob holds every staged target;
//   - a check that is not allowed holds its targets as task_untrusted;
//   - a check that errors, exits non-zero, times out, returns invalid JSON or
//     ok=false holds its targets as check_failed;
//   - a failure to write the temp files, or no staging directory, holds the
//     check's targets.
//
// A target that no check matches passes. One hold is made per failing
// target; its reason is that of the first failing check in name order, and
// its detail names every failing check.
func NewGateIn(checks map[string]manifest.CheckDef, r extexec.Runner, allow AllowList, dir string) Gate {
	return &gate{checks: checks, run: r, allow: allow, dir: dir}
}

type gate struct {
	checks map[string]manifest.CheckDef
	run    extexec.Runner
	allow  AllowList
	dir    string
}

type failure struct {
	reason model.HoldReason
	checks []string
}

func (g *gate) Check(ctx context.Context, staged []Staged, req extexec.Request) ([]model.Target, []model.Hold, []Verdict) {
	var verdicts []Verdict
	fails := map[model.Target]*failure{}
	fail := func(t model.Target, check string, reason model.HoldReason, detail string) {
		verdicts = append(verdicts, Verdict{Target: t, Check: check, Pass: false, Detail: detail})
		f := fails[t]
		if f == nil {
			f = &failure{reason: reason}
			fails[t] = f
		}
		f.checks = append(f.checks, check)
	}

	if g.allow == nil || g.run == nil {
		for _, s := range staged {
			fail(s.Target, "", model.HoldCheckFailed, "commit gate has no allow list or runner")
		}
		return g.finish(staged, fails, verdicts)
	}

	names := make([]string, 0, len(g.checks))
	for n := range g.checks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		def := g.checks[name]
		if err := validGlobs(def.Paths); err != nil {
			for _, s := range staged {
				fail(s.Target, name, model.HoldCheckFailed, "invalid check paths: "+err.Error())
			}
			continue
		}
		var matched []Staged
		for _, s := range staged {
			if len(def.Paths) == 0 || len(matchAny(def.Paths, []model.Target{s.Target})) > 0 {
				matched = append(matched, s)
			}
		}
		if len(matched) == 0 {
			continue
		}
		hash, err := DefinitionHash(def)
		if err != nil || !g.allow.Allowed(extexec.KindCheck, name, hash) {
			for _, s := range matched {
				fail(s.Target, name, model.HoldTaskUntrusted, "check definition is not allowed on this machine")
			}
			continue
		}
		if err := g.runCheck(ctx, name, def, matched, req); err != nil {
			for _, s := range matched {
				fail(s.Target, name, model.HoldCheckFailed, err.Error())
			}
			continue
		}
		for _, s := range matched {
			verdicts = append(verdicts, Verdict{Target: s.Target, Check: name, Pass: true})
		}
	}
	return g.finish(staged, fails, verdicts)
}

// runCheck writes the matched plaintext to private temp files, runs the
// check, and removes the files before it returns.
func (g *gate) runCheck(ctx context.Context, name string, def manifest.CheckDef, matched []Staged, req extexec.Request) (err error) {
	if g.dir == "" {
		return errors.New("staging: no state directory to stage plaintext in; refusing the system temp directory")
	}
	dir, err := os.MkdirTemp(g.dir, "yadm-check-")
	if err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	defer func() {
		if rerr := os.RemoveAll(dir); rerr != nil && err == nil {
			err = fmt.Errorf("removing staged files: %w", rerr)
		}
	}()
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("staging: %w", err)
	}
	q := req
	q.Kind = extexec.KindCheck
	q.Name = name
	q.Changed = nil
	q.Staged = map[model.Target]string{}
	for i, s := range matched {
		// The file name carries only the target's extension, so a linter can
		// pick a parser; a dotfile's whole name (".zshrc") is not an extension.
		p := filepath.Join(dir, strconv.Itoa(i)+stagedExt(string(s.Target)))
		if err := writePrivate(p, s.Plaintext); err != nil {
			return fmt.Errorf("staging: %w", err)
		}
		q.Changed = append(q.Changed, s.Target)
		q.Staged[s.Target] = p
	}
	timeout := def.Timeout.D()
	if timeout <= 0 {
		timeout = DefaultCheckTimeout
	}
	_, err = g.run.Run(ctx, extexec.Spec{Argv: def.Command, Timeout: timeout}, q)
	return err
}

// stagedExt returns the target's extension, or "" when the only dot starts
// the base name.
func stagedExt(target string) string {
	base := filepath.Base(target)
	ext := filepath.Ext(base)
	if ext == base {
		return ""
	}
	return ext
}

func writePrivate(p string, b []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

func (g *gate) finish(staged []Staged, fails map[model.Target]*failure, verdicts []Verdict) ([]model.Target, []model.Hold, []Verdict) {
	var pass []model.Target
	var holds []model.Hold
	done := map[model.Target]bool{}
	for _, s := range staged {
		if done[s.Target] {
			continue
		}
		done[s.Target] = true
		f, failed := fails[s.Target]
		if !failed {
			pass = append(pass, s.Target)
			continue
		}
		detail := "commit gate failed closed"
		var named []string
		for _, c := range f.checks {
			if c != "" {
				named = append(named, c)
			}
		}
		if len(named) > 0 {
			detail = "failed checks: " + strings.Join(named, ", ")
		}
		h := model.Hold{Target: s.Target, Scope: s.Scope, Reason: f.reason, Detail: detail}
		if f.reason == model.HoldTaskUntrusted {
			for _, c := range named {
				h.Next = append(h.Next, "yadm task allow "+model.ShellQuote(c))
			}
		}
		holds = append(holds, newHold(h))
	}
	return pass, holds, verdicts
}
