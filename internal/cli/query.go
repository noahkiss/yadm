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
	// OnDemand lists the enclaves this machine holds keys for but reads on
	// demand only: never applied here. They are not in Opened.
	OnDemand []model.EnclaveName `json:"on_demand,omitempty"`
}

type machineData struct {
	model.Machine
	Observed map[string]model.ObservedFact `json:"observed"`
	Enclaves enclaveSummary                `json:"enclaves"`
	// Recipient and SignKey are this machine's public keys, for a member's
	// `enclave add`. Absent when the state directory holds no identity.
	Recipient string `json:"recipient,omitempty"`
	SignKey   string `json:"sign_key,omitempty"`
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
		case s.IsOnDemand(e) && s.CanRead(e):
			out.OnDemand = append(out.OnDemand, e)
		default:
			out.Other = append(out.Other, e)
		}
	}
	return out
}

// lines describes this machine's place in each enclave, one line each, in
// name order: "<enclave>: member", "member (on demand)", "not a member" or
// "refused: <why>".
func (s enclaveSummary) lines() []string {
	type row struct{ e, what string }
	var rows []row
	for _, e := range s.Opened {
		rows = append(rows, row{string(e), "member"})
	}
	for _, e := range s.OnDemand {
		rows = append(rows, row{string(e), "member (on demand)"})
	}
	for _, e := range s.Other {
		rows = append(rows, row{string(e), "not a member"})
	}
	for _, r := range s.Refused {
		rows = append(rows, row{string(r.Enclave), "refused: " + r.Error})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].e < rows[j].e })
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.e + ": " + r.what
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
	if m.id != nil {
		mem := m.id.Member()
		d.Recipient, d.SignKey = mem.Recipient, mem.SignKey
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s types=%s os=%s arch=%s\n", d.ID, d.Name, joinTypes(d.Types), d.OS, d.Arch)
	for _, l := range d.Enclaves.lines() {
		fmt.Fprintf(&b, "enclave %s\n", l)
	}
	if d.Recipient != "" {
		who := d.Name
		if who == "" {
			who = string(d.ID)
		}
		fmt.Fprintf(&b, "recipient %s\nsign_key  %s\n", d.Recipient, d.SignKey)
		fmt.Fprintf(&b, "to add this machine, on a member: yadm enclave add %s --enclave <enclave> --recipient %s --sign-key %s\n",
			model.ShellQuote(who), model.ShellQuote(d.Recipient), model.ShellQuote(d.SignKey))
	}
	text := strings.TrimRight(b.String(), "\n")
	var next []string
	for _, r := range d.Enclaves.Refused {
		next = append(next, "yadm enclave join "+model.ShellQuote(string(r.Enclave))+" --code <code> (or --expect <fingerprint>)")
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
		if ex.Resolved.Index == apply.RootIndex {
			text += fmt.Sprintf(" source=%s owned root", ex.Resolved.Source)
		} else {
			text += fmt.Sprintf(" source=%s entry=#%d", ex.Resolved.Source, ex.Resolved.Index)
		}
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
	"commit":  {"refuse a named path no entry, applying glob or owned root covers", "scan and capture; a named new file under an applying glob entry captures under that entry", "a named managed file deleted in $HOME commits its deletion: the source goes, and so does its own [[file]] entry", "run the commit gate (allowed checks only)", "commit one commit per scope through a private index", "bypass quiet periods and leases, never the gate or the seal guard", "fetch, replay, apply and push in the same call unless --no-push"},
	"sync": {
		"take the lock in the state directory (wait at most 30s)",
		"with --quick or --auto: stop here unless the remote moved (ls-remote), a target drifted, the last full sync is 15m old, or the machine just woke",
		"scan and capture; with --auto, auto-commit by policy",
		"run allowed collectors",
		"fetch main and refs/yadm/*; when another machine's signed fleet pause holds this one, only publish the status record (paused_until) and push it",
		"replay local commits onto origin/main in memory",
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
		"run each allowed path task whose `on` matches a target it took over, once; no unit reload or first-apply task (those run on the next apply)",
		"install the sync schedule ({{schedule}}) unless --no-schedule",
	},
	"retag":   {"pick the entry: the only one for the path, or the one --source names", "replace the type terms of its when, keeping every other term; refuse a when it cannot rewrite or an edit that makes two variants apply on one machine", "change the manifest entry's when and enclave", "move the source between files/ and sealed/<enclave>/, opening and resealing", "commit once on main (protected, manual only)"},
	"untrack": {"pick the entry: the only one for the path, the one --source names, or the one a source path names", "refuse a path no literal entry names, or an entry this machine cannot open every enclave of", "remove its [[file]] table, and its source unless another entry reads it", "commit both once on main (protected, manual only) and push", "stop managing the target here; the file stays on disk, and other machines remove an unchanged copy on their next apply"},
	"source":  {"mv: refuse a move between files/ and sealed/<enclave>/ (retag's job), a source no literal entry or a glob reads, and a destination that exists or that an entry would read", "open a sealed blob, sealed values and regions under the old path and seal them under the new one, in memory, current epoch only", "point each entry's source line at the new path, or drop it for the default path", "commit the manifest edit and the move once on main (protected, manual only) and push"},
	"track":   {"without --when or --enclave, capture a new file an applying glob entry matches under that entry, as commit <path> does", "refuse a path an entry or owned root covers, a glob-covered path with --when or --enclave, a directory, or an enclave this machine is not a member of", "append a [[file]] entry with when and enclave to manifest.toml", "add the file's bytes as its source, sealed under sealed/<enclave>/ for an enclave", "commit both once through the gate and push (--no-push: the next sync pushes)"},
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
