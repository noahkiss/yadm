package tasks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// Triggers recorded in model.TaskResult.Trigger.
const (
	TriggerPaths      = "paths"
	TriggerRemove     = "remove"
	TriggerFirstApply = "first-apply"
	TriggerUnit       = "unit"
)

// Default timeouts.
const (
	DefaultTaskTimeout  = 5 * time.Minute
	DefaultCheckTimeout = 30 * time.Second
)

// UnitTaskPrefix prefixes the task name of a built-in unit reload in
// model.TaskResult.Task: "unit:<target>".
const UnitTaskPrefix = "unit:"

// Event is what one apply changed.
type Event struct {
	Commit     model.CommitID
	Changed    []model.Target
	Removed    []model.Target
	Units      []manifest.Unit // changed unit targets
	FirstApply bool
}

// Selected is one task to run for an event.
type Selected struct {
	Name    string
	Trigger string
	Def     manifest.TaskDef
	Matched []model.Target
}

// Select returns the tasks an event triggers, in name order. defs must
// already be filtered by `when` (manifest.Plan.Tasks).
//
// A task runs at most once per apply. When several triggers fire, Trigger
// names the first of first-apply, paths, remove; Matched holds every
// matched target, written or removed, sorted. An invalid glob is an error
// and selects nothing.
func Select(defs map[string]manifest.TaskDef, ev Event) ([]Selected, error) {
	names := make([]string, 0, len(defs))
	for n := range defs {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Selected
	var errs []error
	for _, name := range names {
		def := defs[name]
		if err := validGlobs(def.On); err != nil {
			errs = append(errs, fmt.Errorf("task %s: on: %w", name, err))
			continue
		}
		if err := validGlobs(def.OnRemove); err != nil {
			errs = append(errs, fmt.Errorf("task %s: on_remove: %w", name, err))
			continue
		}
		written := matchAny(def.On, ev.Changed)
		removed := matchAny(def.OnRemove, ev.Removed)
		first := def.FirstApply && ev.FirstApply
		var trigger string
		switch {
		case first:
			trigger = TriggerFirstApply
		case len(written) > 0:
			trigger = TriggerPaths
		case len(removed) > 0:
			trigger = TriggerRemove
		default:
			continue
		}
		matched := append(append([]model.Target{}, written...), removed...)
		sort.Slice(matched, func(i, j int) bool { return matched[i] < matched[j] })
		out = append(out, Selected{Name: name, Trigger: trigger, Def: def, Matched: dedupe(matched)})
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

func dedupe(ts []model.Target) []model.Target {
	out := ts[:0]
	for i, t := range ts {
		if i == 0 || t != ts[i-1] {
			out = append(out, t)
		}
	}
	return out
}

// matchAny returns the targets that match any glob, in input order.
func matchAny(globs []string, targets []model.Target) []model.Target {
	var out []model.Target
	for _, t := range targets {
		for _, g := range globs {
			if MatchGlob(g, string(t)) {
				out = append(out, t)
				break
			}
		}
	}
	return out
}

func validGlobs(globs []string) error {
	for _, g := range globs {
		if g == "" {
			return errors.New("empty glob")
		}
		for _, seg := range strings.Split(g, "/") {
			if seg == "**" {
				continue
			}
			if _, err := path.Match(seg, ""); err != nil {
				return fmt.Errorf("glob %q: %w", g, err)
			}
		}
	}
	return nil
}

// MatchGlob matches a slash-separated target against a glob. "**" as a whole
// segment matches zero or more segments; other segments use path.Match, so
// "*" never crosses a "/". An invalid pattern matches nothing.
func MatchGlob(glob, target string) bool {
	return matchSegs(strings.Split(glob, "/"), strings.Split(target, "/"))
}

func matchSegs(g, t []string) bool {
	for len(g) > 0 {
		if g[0] == "**" {
			for i := len(t); i >= 0; i-- {
				if matchSegs(g[1:], t[i:]) {
					return true
				}
			}
			return false
		}
		if len(t) == 0 {
			return false
		}
		ok, err := path.Match(g[0], t[0])
		if err != nil || !ok {
			return false
		}
		g, t = g[1:], t[1:]
	}
	return len(t) == 0
}

// DefinitionHash is the hex SHA-256 of a task or collector definition's
// canonical JSON.
func DefinitionHash(def any) (string, error) {
	if def == nil {
		return "", errors.New("nil definition")
	}
	b, err := json.Marshal(def)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func newHold(h model.Hold) model.Hold {
	if h.Since.IsZero() {
		h.Since = now().UTC()
	}
	if h.Scope == "" {
		h.Scope = model.ScopeShared
	}
	h.ID = model.HoldID(h)
	return h
}

// now is the clock for results and holds.
var now = time.Now

// Runner runs selected tasks and unit reloads.
type Runner struct {
	Exec  extexec.Runner
	Allow AllowList
	Units UnitReloader
}

// Run runs each selected task once, in order, through the extexec contract.
// A task that is not allowed is not run and comes back as a Hold. A failed
// task never stops the others or the sync.
//
// After the tasks, Run reloads each changed unit in ev.Units through Units
// and records it as task "unit:<target>" with trigger "unit". Units are the
// built-in task and need no allow entry.
//
// req carries the shared context (machine, home, source); Run sets Kind,
// Name, Commit, Trigger, Changed and Removed for each task.
func (r *Runner) Run(ctx context.Context, ev Event, sel []Selected, req extexec.Request) ([]model.TaskResult, []model.Hold) {
	var results []model.TaskResult
	var holds []model.Hold
	changed := set(ev.Changed)
	removed := set(ev.Removed)
	for _, s := range sel {
		hash, err := DefinitionHash(s.Def)
		if err != nil || r.Allow == nil || !r.Allow.Allowed(extexec.KindTask, s.Name, hash) {
			holds = append(holds, newHold(model.Hold{
				Task: s.Name, Reason: model.HoldTaskUntrusted,
				Detail: "task definition is not allowed on this machine",
				Next:   []string{"yadm task allow " + s.Name},
			}))
			continue
		}
		q := req
		q.Kind = extexec.KindTask
		q.Name = s.Name
		q.Commit = ev.Commit
		q.Trigger = s.Trigger
		q.Changed, q.Removed = nil, nil
		for _, t := range s.Matched {
			if changed[t] {
				q.Changed = append(q.Changed, t)
			}
			if removed[t] {
				q.Removed = append(q.Removed, t)
			}
		}
		timeout := s.Def.Timeout.D()
		if timeout <= 0 {
			timeout = DefaultTaskTimeout
		}
		started := now().UTC()
		res := model.TaskResult{Task: s.Name, Trigger: s.Trigger, Commit: ev.Commit, Started: started, ExitCode: -1}
		if r.Exec == nil {
			res.Error = "no runner"
		} else {
			out, err := r.Exec.Run(ctx, extexec.Spec{Argv: s.Def.Command, Timeout: timeout}, q)
			res.Duration = out.Duration
			res.ExitCode = out.ExitCode
			if err != nil {
				res.Error = err.Error()
			}
		}
		results = append(results, res)
	}
	for _, u := range ev.Units {
		started := now().UTC()
		res := model.TaskResult{Task: UnitTaskPrefix + string(u.Target), Trigger: TriggerUnit, Commit: ev.Commit, Started: started}
		var err error
		if r.Units == nil {
			err = errors.New("no unit reloader")
		} else {
			err = r.Units.Reload(ctx, u, req.Home)
		}
		res.Duration = now().Sub(started)
		if why, skipped := IsSkip(err); skipped {
			res.Detail = "reload skipped: " + why
		} else if err != nil {
			res.ExitCode = -1
			res.Error = err.Error()
		}
		results = append(results, res)
	}
	return results, holds
}

func set(ts []model.Target) map[model.Target]bool {
	m := make(map[model.Target]bool, len(ts))
	for _, t := range ts {
		m[t] = true
	}
	return m
}
