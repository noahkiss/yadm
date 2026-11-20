package cli

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/model"
)

type refusedEnclave struct {
	Enclave model.EnclaveName `json:"enclave"`
	Error   string            `json:"error"`
}

type enclaveSummary struct {
	Opened  []model.EnclaveName `json:"opened"`
	Refused []refusedEnclave    `json:"refused"`
	Other   []model.EnclaveName `json:"other"` // verified, this machine is not a member
}

type machineData struct {
	model.Machine
	Observed map[string]model.ObservedFact `json:"observed"`
	Enclaves enclaveSummary                `json:"enclaves"`
}

func enclavesOf(s *apply.Snapshot) enclaveSummary {
	out := enclaveSummary{Opened: []model.EnclaveName{}, Refused: []refusedEnclave{}, Other: []model.EnclaveName{}}
	var names []model.EnclaveName
	for _, e := range s.Fleet.Enclaves() {
		names = append(names, e)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, e := range names {
		l, ok := s.Enclaves[e]
		switch {
		case ok && l.Err != nil:
			out.Refused = append(out.Refused, refusedEnclave{Enclave: e, Error: l.Err.Error()})
		case s.Keys != nil && s.Keys.CanOpen(e):
			out.Opened = append(out.Opened, e)
		default:
			out.Other = append(out.Other, e)
		}
	}
	return out
}

func (a *app) cmdMachine(cmd *cobra.Command, args []string) (result, error) {
	m, err := openLoaded(cmd.Context())
	if err != nil {
		return notInit(err), err
	}
	s := m.snap
	d := machineData{Machine: s.Context.Machine, Observed: s.Context.Observed, Enclaves: enclavesOf(s)}
	if d.Observed == nil {
		d.Observed = map[string]model.ObservedFact{}
	}
	text := fmt.Sprintf("%s %s types=%s os=%s arch=%s opened=%v", d.ID, d.Name, joinTypes(d.Types), d.OS, d.Arch, d.Enclaves.Opened)
	var next []string
	for _, r := range d.Enclaves.Refused {
		next = append(next, "yadm enclave join "+string(r.Enclave)+" --expect <fingerprint>")
	}
	return result{data: d, text: text, next: next}, nil
}

func joinTypes(ts []model.TypeName) string {
	s := make([]string, len(ts))
	for i, t := range ts {
		s[i] = string(t)
	}
	return strings.Join(s, ",")
}

func (a *app) cmdWhy(cmd *cobra.Command, args []string) (result, error) {
	m, err := openLoaded(cmd.Context())
	if err != nil {
		return notInit(err), err
	}
	t, err := target(m.home, args[0])
	if err != nil {
		return result{}, err
	}
	ex, err := m.snap.Plan.Why(t)
	if err != nil {
		return result{}, err
	}
	text := fmt.Sprintf("%s: managed=%v protected=%v", t, ex.Managed, ex.Protected)
	if ex.Resolved != nil {
		text += fmt.Sprintf(" source=%s entry=#%d", ex.Resolved.Source, ex.Resolved.Index)
		if ex.WhenExpanded != "" {
			text += fmt.Sprintf("\n  when %s = %s", ex.Resolved.Entry.When, ex.WhenExpanded)
		}
	}
	for _, r := range ex.Rejected {
		text += fmt.Sprintf("\n  entry #%d not applied: %s", r.Index, r.Reason)
		if r.Expanded != "" {
			text += fmt.Sprintf(" (= %s)", r.Expanded)
		}
	}
	return result{data: ex, text: text}, nil
}

type managedData struct {
	Target  model.Target     `json:"target"`
	Managed bool             `json:"managed"`
	Scope   model.Scope      `json:"scope,omitempty"`
	Source  model.SourcePath `json:"source,omitempty"`
}

func (a *app) cmdManaged(cmd *cobra.Command, args []string) (result, error) {
	m, err := openLoaded(cmd.Context())
	if err != nil {
		return notInit(err), err
	}
	t, err := target(m.home, args[0])
	if err != nil {
		return result{}, err
	}
	d := managedData{Target: t}
	if r, ok := m.snap.Plan.Targets[t]; ok {
		d.Managed, d.Scope, d.Source = true, r.Entry.Scope(), r.Source
	}
	return result{data: d, text: fmt.Sprintf("%s: managed=%v %s", t, d.Managed, d.Source)}, nil
}

// explainSteps lists, per command, the steps it takes. Steps that depend on
// this machine are filled in by cmdExplain.
var explainSteps = map[string][]string{
	"init": {
		"clone <remote> into the source directory",
		"look up --machine in fleet.toml; a name not in the fleet gets a new random machine id",
		"generate an age X25519 identity and an Ed25519 signing key, mode 0600, in the state directory",
		"write machine.toml (machine id and remote) in the config directory",
		"allow current task, check and collector definitions only with --allow-tasks",
		"install the sync schedule ({{schedule}}) unless --no-schedule",
		"print the machine id, recipient and signing key for `yadm enclave add` on a member",
	},
	"status": {"scan managed targets (stat pass, hash only on a stat change)", "list holds from the state", "count commits ahead of and behind origin/main", "read this machine's last published sync time"},
	"apply": {
		"load fleet.toml, manifest.toml and the key logs at main; verify each key log against the local pins",
		"resolve the manifest for this machine and render each target in memory",
		"skip targets whose bytes match; hold targets changed since the last write (drifted)",
		"write changed targets atomically, backing up replaced bytes for 30 days",
		"skip sealed files of enclaves this machine cannot open",
		"run triggered tasks that are allowed here, unit reloads, and first-apply tasks once",
	},
	"capture": {"scan for drift", "capture each drifted target into source changes (round-trip check, seal guard)", "commit nothing"},
	"diff":    {"scan for drift", "render each target's source in memory and diff it against the live file", "print plaintext only for enclaves this machine opens"},
	"commit":  {"scan and capture", "run the commit gate (allowed checks only)", "commit one commit per scope through a private index", "bypass quiet periods and leases, never the gate or the seal guard", "fetch, replay, apply and push in the same call unless --no-push"},
	"sync": {
		"take the lock in the state directory (wait at most 30s)",
		"with --quick or --auto: stop here unless the remote moved (ls-remote), a target drifted, the last full sync is 15m old, or the machine just woke",
		"scan and capture; with --auto, auto-commit by policy",
		"run allowed collectors",
		"fetch main and refs/yadm/*; replay local commits onto origin/main in memory",
		"compare-and-swap main, move the source worktree, apply",
		"publish this machine's status record; push main and the status ref atomically, never forced",
		"after a push that moved main, run yadm-nudge from PATH, if any, so peers sync now",
	},
	"hook": {
		"read the harness hook JSON on stdin",
		"post-edit: record the edited path for the session; commit and push it now if it is managed or in an owned root (lease-free, gate and protection kept)",
		"stop: commit and push the session's recorded paths; exit 2 while a decision it caused is open (yadm defer settles one for now)",
		"session-start: quick sync, then at most 10 lines on holds near the cwd, deferred decisions, unreviewed auto-commits and fleet drift",
	},
	"defer": {"find the hold", "record it with the reason in the state directory's review queue", "the hold stays; yadm review list shows it"},
	"adopt": {
		"verify the identity and that the source resolves for this machine",
		"materialize directory symlinks into real directories; record identical targets (symlinks and read-only renders become regular files), write missing ones, hold differing ones (drifted)",
		"run no tasks; --allow-tasks only records allows, and first-apply tasks run on the next apply",
		"install the sync schedule ({{schedule}}) unless --no-schedule",
	},
	"retag":   {"change the manifest entry's when and enclave", "move the source between files/ and sealed/<enclave>/, opening and resealing", "commit once on main (protected, manual only)"},
	"check":   {"verify identity keys and modes", "verify key logs against pins and fleet membership", "resolve the manifest (collisions)", "check the schedule and last sync age", "count holds and conflicts", "check git config for textconv caches, merge drivers and filters"},
	"collect": {"run every collector whose when matches and whose definition is allowed here", "store results in local state"},
	"import":  {"read the legacy repository's head tree; never run upstream yadm", "convert alternates, templates and transcrypt files", "write one commit in --output whose parent is the legacy head", "commit nothing on any problem; never push"},
	"enclave": {"read the key log at main", "verify it against the local pin", "append a signed entry and commit it on main (protected)", "pin the new entry"},
	"git":     {"run git in the source clone with -c diff.cachetextconv=false and hooks disabled"},
}

func (a *app) cmdExplain(cmd *cobra.Command, args []string) (result, error) {
	name := args[0]
	if name == "clone" {
		name = "init"
	}
	steps, ok := explainSteps[name]
	if !ok {
		root := cmd.Root()
		if c, _, err := root.Find([]string{name}); err == nil && c != root {
			steps = []string{c.Short}
		} else {
			return result{next: []string{"yadm --help"}}, usagef("unknown command %q", args[0])
		}
	}
	sched := "a systemd user timer"
	if runtime.GOOS == "darwin" {
		sched = "a launchd user agent"
	}
	out := make([]string, len(steps))
	for i, s := range steps {
		out[i] = strings.ReplaceAll(s, "{{schedule}}", sched)
	}
	var b strings.Builder
	for i, s := range out {
		fmt.Fprintf(&b, "%d. %s\n", i+1, s)
	}
	data := map[string]any{"command": args[0], "steps": out}
	// For apply and adopt on a set-up machine, add the actions apply plans here.
	if name == "apply" || name == "adopt" {
		if m, err := openLoaded(cmd.Context()); err == nil {
			if acts, err := m.eng.Plan(cmd.Context(), m.snap.Commit); err == nil {
				if acts == nil {
					acts = []apply.Action{}
				}
				data["actions"] = acts
				for _, x := range acts {
					fmt.Fprintf(&b, "   %-7s %s\n", x.Kind, x.Target)
				}
			}
		}
	}
	return result{data: data, text: b.String()}, nil
}

// snapVocab is the snapshot's condition vocabulary: the fleet's names plus
// the manifest's named conditions. A manifest whose conditions do not
// define cleanly yields the fleet's names alone, so a `cond:` term then
// fails to parse.
func snapVocab(snap *apply.Snapshot) cond.Vocabulary {
	v := snap.Fleet.Vocabulary()
	if snap.Manifest == nil {
		return v
	}
	if nv, err := snap.Manifest.Vocabulary(v); err == nil {
		return nv
	}
	return v
}
