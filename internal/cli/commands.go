package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/schedule"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
	"github.com/noahkiss/yadm/internal/textmerge"
)

// register builds the whole command tree.
func (a *app) register(root *cobra.Command) {
	root.RunE = a.needSub("")
	root.Args = cobra.ArbitraryArgs
	leaf := a.leaf
	exact := func(c *cobra.Command, n int) *cobra.Command { c.Args = cobra.ExactArgs(n); return c }

	leaf(root, "version", "Print the version", a.cmdVersion)
	leaf(root, "where", "Print the source, state and config directories", a.cmdWhere)
	leaf(root, "machine", "Show this machine: fleet entry, observed facts, enclaves", a.cmdMachine)
	exact(leaf(root, "why <path>", "Explain how the manifest treats a path", a.cmdWhy), 1)
	exact(leaf(root, "managed <path>", "Report whether a path is managed on this machine", a.cmdManaged), 1)
	mf := leaf(root, "manifest", "Show the resolved manifest per machine (read-only)", a.cmdManifest)
	mf.Flags().String("as", "", "resolve for this fleet machine")
	mf.Flags().Bool("fleet", false, "resolve for every fleet machine")
	ev := exact(leaf(root, "eval <condition>", "Evaluate a condition for a machine", a.cmdEval), 1)
	ev.Flags().String("as", "", "evaluate for this fleet machine")
	exact(leaf(root, "explain <command>", "Describe what a command would do here, step by step", a.cmdExplain), 1)

	for _, use := range []string{"init <remote>", "clone <remote>"} {
		in := exact(leaf(root, use, "Clone the source, create this machine's identity, install the schedule", a.cmdInit), 1)
		in.Flags().String("machine", "", "machine id, name or nickname from the fleet file, or a new name")
		in.Flags().Bool("allow-tasks", false, "allow every current task, check and collector definition")
		in.Flags().Bool("no-schedule", false, "do not install the sync schedule")
	}

	leaf(root, "status", "Show drift, holds, pending commits and sync state", a.cmdStatus)
	ap := leaf(root, "apply [path...]", "Write changed targets for this machine", a.cmdApply)
	ap.Flags().Bool("dry-run", false, "plan only")
	leaf(root, "capture [path...]", "Capture drifted targets into the source without committing", a.cmdCapture)
	leaf(root, "diff [path...]", "Show plaintext differences between targets and the source", a.cmdDiff)
	cm := leaf(root, "commit [path...]", "Capture, gate and commit now, one commit per scope", a.cmdCommit)
	cm.Flags().StringP("message", "m", "", "commit subject")
	cm.Flags().String("why", "", "short intent; used as the subject when -m is not given")
	cm.Flags().Bool("no-push", false, "commit only; the next sync pushes")
	cm.Flags().Bool("dry-run", false, "plan only")
	sy := leaf(root, "sync", "Capture, commit by policy, fetch, replay, apply and push", a.cmdSync)
	sy.Flags().Bool("auto", false, "timer mode: auto-commit by policy; implies --quick unless --full")
	sy.Flags().Bool("quick", false, "check cheaply first (scan, ls-remote); sync in full only when something moved")
	sy.Flags().Bool("full", false, "never stop after the quick check")
	sy.Flags().Bool("no-push", false, "do not push")
	sy.Flags().Bool("dry-run", false, "plan only")
	lg := leaf(root, "log [path]", "Show history of the source", a.cmdLog)
	lg.Args = cobra.MaximumNArgs(1)
	lg.Flags().IntP("max-count", "n", 50, "show at most this many commits")
	lg.Flags().BoolP("patch", "p", false, "show plaintext diffs (not implemented)")
	rt := exact(leaf(root, "retag <path> <type>[,<type>...]", "Change which types receive a path, resealing as needed", a.cmdRetag), 2)
	rt.Flags().String("enclave", "", "seal for this enclave; empty stores plaintext")
	rt.Flags().Bool("dry-run", false, "plan only")
	bi := leaf(root, "bisect", "Bisect by rendering commits for a machine into a sandbox", a.cmdBisect)
	bi.Flags().String("as", "", "machine to render for")
	leaf(root, "collect", "Run collectors now and show observed facts", a.cmdCollect)
	leaf(root, "check", "Self-check: keys, key logs, schedule, last sync age, holds, secrecy config", a.cmdCheck)

	fl := a.group(root, "fleet", "Machines, their status refs and observed facts")
	leaf(fl, "list", "List machines with last sync and hold counts", a.cmdFleetList)
	leaf(fl, "status", "Alias of fleet list", a.cmdFleetList)
	exact(leaf(fl, "show <machine>", "Show one machine's registry entry and status", a.cmdFleetShow), 1)
	exact(leaf(fl, "diff <collector>", "Compare an observed fact across machines", a.cmdFleetDiff), 1)

	a.registerEnclave(root)
	a.registerHooks(root)

	pr := a.group(root, "protection", "Local allows for weakened protection of a target")
	exact(leaf(pr, "allow <target>", "Allow a target whose manifest entry lost sealing or protection", a.cmdProtectionAllow), 1)
	ro := a.group(root, "root", "Local allows for owned roots")
	exact(leaf(ro, "allow <path>", "Allow an owned root that is new, changed or removed here", a.cmdRootAllow), 1)

	rv := a.group(root, "review", "Review auto-commits per scope")
	rl := leaf(rv, "list [scope]", "List unreviewed commits with plaintext diffs", a.cmdReviewList)
	rl.Args = cobra.MaximumNArgs(1)
	exact(leaf(rv, "ok <scope> <commit>", "Advance the reviewed ref", a.cmdReviewOK), 2)
	exact(leaf(rv, "revert <commit>", "Revert a commit with a new commit", a.cmdReviewRevert), 1)
	rn := exact(leaf(rv, "note <commit>", "Attach a why note to a commit; sealed when the commit touches an enclave", a.cmdReviewNote), 1)
	rn.Flags().String("why", "", "the note text")
	rn.Flags().String("seal", "", "seal the note to this enclave")
	rn.Flags().Bool("paths-only", false, "write a note that names only the commit's paths")
	rn.Flags().Bool("no-push", false, "write the note only; the next sync pushes it")

	hd := a.group(root, "hold", "Held files, tasks and conflicts")
	hl := leaf(hd, "list", "List holds", a.cmdHoldList(""))
	hl.Flags().String("reason", "", "only holds with this reason")
	exact(leaf(hd, "show <id>", "Show one hold with its three sides", a.cmdHoldShow), 1)
	rs := exact(leaf(hd, "resolve <id>", "Resolve a hold", a.cmdHoldResolve), 1)
	rs.Flags().String("take", "", "source, target, or a path to merged content")
	exact(leaf(hd, "ignore <id>", "Leave a new file in an owned root untracked on purpose", a.cmdHoldIgnore), 1)
	hs := leaf(root, "holds", "List holds (same as hold list)", a.cmdHoldList(""))
	hs.Flags().String("reason", "", "only holds with this reason")
	leaf(root, "conflicts", "List conflict holds (same as hold list --reason conflict)", a.cmdHoldList(model.HoldConflict))

	ls := a.group(root, "lease", "Agent leases that pause auto-commit for paths")
	tk := leaf(ls, "take <path...>", "Take a lease", a.cmdLeaseTake)
	tk.Args = cobra.MinimumNArgs(1)
	tk.Flags().String("holder", "", "lease holder name")
	tk.Flags().Duration("ttl", time.Hour, "lease lifetime")
	exact(leaf(ls, "release <holder>", "Release a holder's leases", a.cmdLeaseRelease), 1)
	leaf(ls, "list", "List leases", a.cmdLeaseList)

	ts := a.group(root, "task", "On-change tasks, checks and collectors")
	leaf(ts, "list", "List definitions and whether this machine allows them", a.cmdTaskList)
	leaf(ts, "allow [name...]", "Allow current definitions on this machine", a.cmdTaskAllow)
	exact(leaf(ts, "run <name>", "Run one task now", a.cmdTaskRun), 1)

	sc := a.group(root, "schedule", "The sync schedule (launchd or systemd)")
	leaf(sc, "install", "Install and load the schedule", a.cmdScheduleInstall)
	leaf(sc, "uninstall", "Unload and remove the schedule", a.cmdScheduleUninstall)
	leaf(sc, "status", "Show whether the schedule is loaded and when it last ran", a.cmdScheduleStatus)

	im := exact(leaf(root, "import <legacy-repo>", "Convert an upstream-yadm repository once", a.cmdImport), 1)
	im.Flags().String("machines", "", "machines table (TSV)")
	im.Flags().String("password-env", "", "env var holding the transcrypt password")
	im.Flags().StringToString("class-enclave", nil, "legacy class=enclave")
	im.Flags().String("default-enclave", "", "enclave for encrypted files with no class")
	im.Flags().String("filters", "", "TOML file mapping legacy strip filters to keep, drop and volatile rules")
	im.Flags().String("machine", "", "machines-table row that is this machine; it keeps this machine's id")
	im.Flags().StringArray("crypt-filter", nil, "extra gitattributes filter name that marks transcrypt files (repeatable)")
	im.Flags().String("output", "", "directory for the converted repository")
	im.Flags().String("branch", "", "branch name in the output (default main)")
	im.Flags().Bool("dry-run", false, "convert in memory and report; write nothing")
	addRecoveryFlags(im)
	ad := leaf(root, "adopt", "Switch this machine: take over identical files, hold differing ones", a.cmdAdopt)
	ad.Flags().Bool("dry-run", false, "plan only")
	ad.Flags().Bool("allow-tasks", false, "allow every current task, check and collector definition")
	ad.Flags().Bool("no-schedule", false, "do not install the sync schedule")

	gt := &cobra.Command{
		Use:                "git [args...]",
		Short:              "Run git on the source clone",
		DisableFlagParsing: true,
	}
	gt.RunE = a.runGit
	root.AddCommand(gt)

	a.registerLegacy(root)
}

// ---- init, clone, adopt ----

type scheduleOutcome struct {
	Installed bool   `json:"installed"`
	Skipped   bool   `json:"skipped,omitempty"`
	Error     string `json:"error,omitempty"`
}

type initData struct {
	Machine   model.MachineID `json:"machine"`
	Name      string          `json:"name,omitempty"`
	InFleet   bool            `json:"in_fleet"`
	Recipient string          `json:"recipient"`
	SignKey   string          `json:"sign_key"`
	Source    string          `json:"source"`
	Allowed   []string        `json:"allowed,omitempty"`
	Schedule  scheduleOutcome `json:"schedule"`
}

func (a *app) cmdInit(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	remote := args[0]
	machineArg, _ := cmd.Flags().GetString("machine")
	allowTasks, _ := cmd.Flags().GetBool("allow-tasks")
	noSchedule, _ := cmd.Flags().GetBool("no-schedule")

	p, err := DefaultPaths()
	if err != nil {
		return result{}, err
	}
	if _, err := os.Stat(identityPath(p)); err == nil {
		return result{next: []string{"yadm status"}}, fmt.Errorf("this machine is already set up: %s exists", identityPath(p))
	}
	for _, f := range []string{crypt.AgeIdentityFile, crypt.SigningKeyFile} {
		if _, err := os.Stat(filepath.Join(p.State, f)); err == nil {
			return result{}, fmt.Errorf("refusing to overwrite the identity key %s", filepath.Join(p.State, f))
		}
	}
	if ents, err := os.ReadDir(p.Source); err == nil && len(ents) > 0 {
		return result{}, fmt.Errorf("the source directory %s is not empty", p.Source)
	}
	repo, err := store.Clone(ctx, remote, p.Source, p.State)
	if err != nil {
		return result{}, err
	}
	defer repo.Close()
	head, err := repo.ResolveRef(ctx, store.RefMain)
	if err != nil {
		return result{}, err
	}
	var fl *fleet.File
	var man *manifest.Manifest
	if head != "" {
		if b, err := repo.ReadPath(ctx, head, fleet.FileName); err == nil {
			if fl, err = fleet.Parse(b); err != nil {
				return result{}, err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return result{}, err
		}
		if b, err := repo.ReadPath(ctx, head, manifest.FileName); err == nil {
			if man, err = manifest.Parse(b); err != nil {
				return result{}, err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return result{}, err
		}
	}

	d := initData{Source: p.Source, Name: machineArg}
	if fl != nil && machineArg != "" {
		m, err := fl.Lookup(machineArg)
		switch {
		case err == nil:
			d.Machine, d.Name, d.InFleet = lookupID(fl, m), m.Name, true
		case errors.Is(err, fleet.ErrUnknownMachine):
		default:
			return result{}, err
		}
	}
	if d.Machine == "" {
		if d.Machine, err = fleet.NewMachineID(); err != nil {
			return result{}, err
		}
	}
	id, err := crypt.GenerateIdentity(d.Machine)
	if err != nil {
		return result{}, err
	}
	if err := id.Save(p.State); err != nil {
		return result{}, err
	}
	if err := fleet.SaveIdentity(identityPath(p), fleet.Identity{Machine: d.Machine, Remote: remote}); err != nil {
		return result{}, err
	}
	mem := id.Member()
	d.Recipient, d.SignKey = mem.Recipient, mem.SignKey

	if allowTasks && man != nil {
		if d.Allowed, err = allowDefinitions(newAllow(p.State), man, fl, nil); err != nil {
			return result{}, err
		}
	}
	d.Schedule = installSchedule(ctx, noSchedule)

	var next []string
	if !d.InFleet {
		name := machineArg
		if name == "" {
			name = "<name>"
		}
		next = append(next, fmt.Sprintf("add [machines.%s] with name = %q, types, os and arch to %s, then commit it", d.Machine, name, fleet.FileName))
	}
	if fl != nil && len(fl.Enclaves()) > 0 {
		next = append(next, fmt.Sprintf("on a member machine: yadm enclave add %s --enclave <enclave> --recipient %s --sign-key %s", d.Machine, d.Recipient, d.SignKey),
			"then here: yadm enclave join <enclave> --expect <fingerprint>")
	}
	next = append(next, "yadm adopt --dry-run", "yadm apply")
	if !d.Schedule.Installed && !d.Schedule.Skipped {
		next = append(next, "yadm schedule install")
	}
	text := fmt.Sprintf("machine   %s\nrecipient %s\nsign_key  %s\nsource    %s", d.Machine, d.Recipient, d.SignKey, d.Source)
	return result{data: d, next: next, text: text}, nil
}

// lookupID returns the fleet key of a machine Lookup returned.
func lookupID(fl *fleet.File, m model.Machine) model.MachineID {
	if m.ID != "" {
		return m.ID
	}
	for id, x := range fl.Machines {
		if x.Name == m.Name {
			return id
		}
	}
	return ""
}

func installSchedule(ctx context.Context, skip bool) scheduleOutcome {
	if skip {
		return scheduleOutcome{Skipped: true}
	}
	s, err := hooks.scheduler()
	if err == nil {
		err = s.Install(ctx, scheduleSpec())
	}
	if err != nil {
		return scheduleOutcome{Error: err.Error()}
	}
	return scheduleOutcome{Installed: true}
}

// ScheduleInterval is how often the timer runs `yadm sync --auto`. Each run
// starts with the quick check, so a tick where nothing moved costs one stat
// pass and one `git ls-remote`.
const ScheduleInterval = time.Minute

func scheduleSpec() schedule.Spec {
	return schedule.Spec{Binary: hooks.binary(), Interval: ScheduleInterval, Label: schedule.DefaultLabel}
}

// lockedResult suggests a retry when err is the lock timeout.
func lockedResult(err error) result {
	if errors.Is(err, sync.ErrLocked) {
		return result{next: []string{"retry in a moment: a sync is running"}}
	}
	return result{}
}

func (a *app) cmdAdopt(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	dry, _ := cmd.Flags().GetBool("dry-run")
	allowTasks, _ := cmd.Flags().GetBool("allow-tasks")
	noSchedule, _ := cmd.Flags().GetBool("no-schedule")
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	if m.id == nil {
		return result{next: []string{"yadm init <remote> --machine <name>"}}, fmt.Errorf("%w: this machine has no identity keys", ErrRefused)
	}
	if allowTasks && !dry {
		if _, err := allowDefinitions(m.allow, m.snap.Manifest, m.snap.Fleet, nil); err != nil {
			return result{}, err
		}
	}
	res, err := m.eng.Adopt(ctx, m.snap.Commit, apply.AdoptOptions{DryRun: dry, AllowTasks: allowTasks && !dry})
	if err != nil {
		return result{}, err
	}
	out := struct {
		apply.Result
		Schedule *scheduleOutcome `json:"schedule,omitempty"`
	}{Result: normResult(res)}
	if !dry {
		s := installSchedule(ctx, noSchedule)
		out.Schedule = &s
	}
	return result{data: out, text: actionsText(res)}, attention(res.Holds)
}

// ---- status, apply, capture, diff, commit, sync, log ----

type statusData struct {
	Machine  model.MachineID `json:"machine"`
	Applied  model.CommitID  `json:"applied"`
	Ahead    int             `json:"ahead"`
	Behind   int             `json:"behind"`
	Drift    []apply.Drift   `json:"drift"`
	Holds    []model.Hold    `json:"holds"`
	LastSync *time.Time      `json:"last_sync"`
	// Generated lists files a task writes (its `outputs`); they are never
	// captured or committed.
	Generated []model.Target `json:"generated,omitempty"`
}

func (a *app) cmdStatus(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	d := statusData{Machine: m.local.Machine}
	if d.Drift, err = m.eng.Scan(ctx, apply.ScanOptions{}); err != nil {
		return result{}, err
	}
	if d.Drift == nil {
		d.Drift = []apply.Drift{}
	}
	if d.Generated, err = m.eng.Generated(ctx); err != nil {
		return result{}, err
	}
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return result{}, err
	}
	d.Holds = withHoldNext(hs)
	if st, err := apply.FileStateDB(m.paths.State).Load(); err == nil && st != nil {
		d.Applied = st.Applied
	}
	h, _ := m.head(ctx)
	o, _ := m.repo.ResolveRef(ctx, store.RemoteMain)
	if h != "" && o != "" && h != o {
		if l, err := m.repo.Log(ctx, string(o)+".."+string(h), nil); err == nil {
			d.Ahead = len(l)
		}
		if l, err := m.repo.Log(ctx, string(h)+".."+string(o), nil); err == nil {
			d.Behind = len(l)
		}
	}
	if s := m.selfStatus(ctx); s != nil && !s.LastSync.IsZero() {
		t := s.LastSync
		d.LastSync = &t
	}
	var next []string
	if len(d.Drift) > 0 {
		next = append(next, "yadm diff", "yadm commit")
	}
	if len(d.Holds) > 0 {
		next = append(next, "yadm hold list")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "machine %s  applied %s  ahead %d  behind %d\n", d.Machine, short(d.Applied), d.Ahead, d.Behind)
	for _, x := range d.Drift {
		fmt.Fprintf(&b, "  %-10s %s\n", x.Kind, x.Target)
	}
	for _, t := range d.Generated {
		fmt.Fprintf(&b, "  %-10s %s\n", "generated", t)
	}
	for _, h := range d.Holds {
		fmt.Fprintf(&b, "  held %-8s %s %s\n", h.Reason, h.Target+model.Target(h.Task), h.ID[:min(12, len(h.ID))])
	}
	return result{data: d, next: next, text: b.String()}, attention(d.Holds)
}

func short(c model.CommitID) string {
	if len(c) > 12 {
		return string(c[:12])
	}
	if c == "" {
		return "-"
	}
	return string(c)
}

func normResult(r apply.Result) apply.Result {
	if r.Actions == nil {
		r.Actions = []apply.Action{}
	}
	r.Holds = withHoldNext(r.Holds)
	return r
}

func actionsText(r apply.Result) string {
	var b strings.Builder
	n := 0
	for _, x := range r.Actions {
		if x.Kind == apply.ActSkip {
			continue
		}
		n++
		fmt.Fprintf(&b, "%-7s %s\n", x.Kind, x.Target)
	}
	if n == 0 {
		b.WriteString("nothing to do\n")
	}
	for _, h := range r.Holds {
		fmt.Fprintf(&b, "held    %s (%s)\n", h.Target, h.Reason)
	}
	return b.String()
}

func (a *app) cmdApply(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	dry, _ := cmd.Flags().GetBool("dry-run")
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	paths, err := targets(m.home, args)
	if err != nil {
		return result{}, err
	}
	var res apply.Result
	run := func() error {
		var err error
		res, err = m.eng.Apply(ctx, m.snap.Commit, apply.ApplyOptions{DryRun: dry, Paths: paths})
		return err
	}
	if dry {
		err = run()
	} else {
		err = m.locked(ctx, run)
	}
	if err != nil {
		return lockedResult(err), err
	}
	res = normResult(res)
	return result{data: res, text: actionsText(res)}, attention(res.Holds)
}

func (a *app) cmdCapture(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	paths, err := targets(m.home, args)
	if err != nil {
		return result{}, err
	}
	var c apply.Capture
	if err := m.locked(ctx, func() error {
		drift, err := m.eng.Scan(ctx, apply.ScanOptions{Paths: paths})
		if err != nil {
			return err
		}
		c, err = m.eng.Capture(ctx, drift)
		return err
	}); err != nil {
		return lockedResult(err), err
	}
	if c.Paths == nil {
		c.Paths = []model.Target{}
	}
	c.Holds = withHoldNext(c.Holds)
	var next []string
	if len(c.Paths) > 0 {
		next = []string{"yadm commit"}
	}
	var b strings.Builder
	for _, p := range c.Paths {
		fmt.Fprintf(&b, "captured %s\n", p)
	}
	return result{data: map[string]any{"paths": c.Paths, "holds": c.Holds}, next: next, text: b.String()}, attention(c.Holds)
}

type fileDiff struct {
	Target  model.Target `json:"target"`
	Diff    string       `json:"diff"`
	Skipped string       `json:"skipped,omitempty"`
}

func (a *app) cmdDiff(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	paths, err := targets(m.home, args)
	if err != nil {
		return result{}, err
	}
	if len(paths) == 0 {
		drift, err := m.eng.Scan(ctx, apply.ScanOptions{})
		if err != nil {
			return result{}, err
		}
		for _, d := range drift {
			paths = append(paths, d.Target)
		}
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	files := []fileDiff{}
	var b strings.Builder
	for _, t := range paths {
		fd := m.diffOne(ctx, t)
		files = append(files, fd)
		if fd.Skipped != "" {
			fmt.Fprintf(&b, "# %s: %s\n", t, fd.Skipped)
		} else {
			b.WriteString(fd.Diff)
		}
	}
	return result{data: map[string]any{"files": files}, text: b.String()}, nil
}

// diffOne renders a target's source for this machine and diffs it against
// the live target, in memory.
func (m *machineEnv) diffOne(ctx context.Context, t model.Target) fileDiff {
	fd := fileDiff{Target: t}
	snap := m.snap
	if _, ok := snap.Plan.Targets[t]; !ok {
		fd.Skipped = "not managed on this machine"
		return fd
	}
	live, err := os.ReadFile(filepath.Join(m.home, filepath.FromSlash(string(t))))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		fd.Skipped = err.Error()
		return fd
	}
	want, err := m.eng.Render(ctx, snap, t, live)
	if err != nil {
		fd.Skipped = err.Error()
		return fd
	}
	d, err := textmerge.Diff("source/"+string(t), "target/"+string(t), want, live)
	if err != nil {
		fd.Skipped = err.Error()
		return fd
	}
	fd.Diff = d
	return fd
}

func reportData(r sync.Report) sync.Report {
	if r.Captured == nil {
		r.Captured = []model.Target{}
	}
	if r.Committed == nil {
		r.Committed = []model.CommitID{}
	}
	r.Holds = withHoldNext(r.Holds)
	return r
}

func (a *app) cmdCommit(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	msg, _ := cmd.Flags().GetString("message")
	why, _ := cmd.Flags().GetString("why")
	noPush, _ := cmd.Flags().GetBool("no-push")
	dry, _ := cmd.Flags().GetBool("dry-run")
	if msg == "" {
		msg = why
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	paths, err := targets(m.home, args)
	if err != nil {
		return result{}, err
	}
	_, _ = m.load(ctx) // the syncer reports a source that does not load
	rep, pushErr, err := m.commitThrough(ctx, a.version, sync.CommitOptions{Message: msg, Paths: paths, DryRun: dry, Push: !noPush && !dry})
	if err != nil {
		return result{}, err
	}
	rep = reportData(rep)
	data := map[string]any{"commits": rep.Committed, "holds": rep.Holds, "pushed": rep.Pushed}
	var next []string
	if pushErr != nil {
		data["push_error"] = pushErr.Error()
		next = []string{"yadm sync"}
	} else if noPush && len(rep.Committed) > 0 {
		next = []string{"yadm sync"}
	}
	return result{data: data, next: next}, attention(rep.Holds)
}

func (a *app) cmdSync(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	auto, _ := cmd.Flags().GetBool("auto")
	quick, _ := cmd.Flags().GetBool("quick")
	full, _ := cmd.Flags().GetBool("full")
	noPush, _ := cmd.Flags().GetBool("no-push")
	dry, _ := cmd.Flags().GetBool("dry-run")
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	_, _ = m.load(ctx)
	rep, err := m.syncer(a.version).Run(ctx, sync.Options{Auto: auto, Push: !noPush, DryRun: dry, MaxRetries: sync.DefaultMaxRetries, Quick: (quick || auto) && !full})
	if err != nil {
		if errors.Is(err, sync.ErrLocked) {
			return result{next: []string{"yadm sync"}}, err
		}
		return result{}, err
	}
	rep = reportData(rep)
	var next []string
	if len(rep.Holds) > 0 {
		next = []string{"yadm hold list"}
	}
	return result{data: rep, next: next}, attention(rep.Holds)
}

type logCommit struct {
	ID       model.CommitID     `json:"id"`
	Parents  []model.CommitID   `json:"parents"`
	Author   string             `json:"author"`
	When     time.Time          `json:"when"`
	Subject  string             `json:"subject"`
	Body     string             `json:"body,omitempty"`
	Trailers []store.Trailer    `json:"trailers,omitempty"`
	Paths    []model.SourcePath `json:"paths"`
	Note     *sync.Note         `json:"note,omitempty"` // the review note; a sealed one opens only for members
}

func (a *app) cmdLog(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	maxN, _ := cmd.Flags().GetInt("max-count")
	if p, _ := cmd.Flags().GetBool("patch"); p {
		return result{}, fmt.Errorf("log --patch: %w", model.ErrNotImplemented)
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	var paths []model.SourcePath
	if len(args) == 1 {
		t, err := target(m.home, args[0])
		if err != nil {
			return result{}, err
		}
		snap, err := m.load(ctx)
		if err != nil {
			return result{}, err
		}
		if r, ok := snap.Plan.Targets[t]; ok {
			paths = []model.SourcePath{r.Source}
		} else {
			paths = []model.SourcePath{model.SourcePath(t)}
		}
	}
	h, err := m.head(ctx)
	if err != nil {
		return result{}, err
	}
	commits := []logCommit{}
	if h != "" {
		cs, err := m.repo.Log(ctx, string(h), paths)
		if err != nil {
			return result{}, err
		}
		for i, c := range cs {
			if maxN > 0 && i >= maxN {
				break
			}
			commits = append(commits, logCommit{ID: c.ID, Parents: c.Parents, Author: c.Author, When: c.When,
				Subject: c.Message.Subject, Body: c.Message.Body, Trailers: c.Message.Trailers, Paths: c.Paths})
		}
	}
	if notes := m.notes(ctx); len(notes) > 0 {
		for i := range commits {
			if n, ok := notes[commits[i].ID]; ok {
				commits[i].Note = &n
			}
		}
	}
	var b strings.Builder
	for _, c := range commits {
		fmt.Fprintf(&b, "%s %s\n", short(c.ID), c.Subject)
		if c.Note != nil {
			fmt.Fprintf(&b, "    why: %s\n", c.Note.Text())
		}
	}
	return result{data: map[string]any{"commits": commits}, text: b.String()}, nil
}

// ---- retag, bisect, collect ----

func (a *app) cmdRetag(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	enclave, _ := cmd.Flags().GetString("enclave")
	dry, _ := cmd.Flags().GetBool("dry-run")
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	t, err := target(m.home, args[0])
	if err != nil {
		return result{}, err
	}
	var types []model.TypeName
	for _, s := range strings.Split(args[1], ",") {
		if s = strings.TrimSpace(s); s != "" {
			types = append(types, model.TypeName(s))
		}
	}
	if len(types) == 0 {
		return result{}, usagef("retag needs at least one type")
	}
	var c apply.Capture
	if err := m.locked(ctx, func() error {
		var err error
		c, err = m.eng.Retag(ctx, t, apply.RetagOptions{Types: types, Enclave: model.EnclaveName(enclave), DryRun: dry})
		return err
	}); err != nil {
		return result{}, err
	}
	removed := losers(m.snap, t, types)
	data := map[string]any{"commit": "", "removed_on": removed, "holds": withHoldNext(c.Holds)}
	if dry || len(c.Changes) == 0 {
		return result{data: data}, attention(c.Holds)
	}
	scope := model.ScopeShared
	if enclave != "" {
		scope = model.Scope(enclave)
	}
	// The last change is the target's new source: the gate reads the target.
	// The manifest edit and the old source's removal commit with it.
	last := len(c.Changes) - 1
	target := apply.Capture{Changes: c.Changes[last:], Paths: c.Paths, Scopes: c.Scopes}
	rep, pushErr, err := m.commitThrough(ctx, a.version, sync.CommitOptions{
		Message: fmt.Sprintf("retag %s: %s", t, args[1]), Capture: &target,
		Changes: c.Changes[:last], ChangesScope: scope, Push: true,
	})
	if pushErr != nil {
		data["push_error"] = pushErr.Error()
	}
	if err != nil {
		return result{data: data}, err
	}
	id, err := m.landed(ctx, rep, manifest.FileName)
	data["commit"] = id
	holds := append([]model.Hold(nil), c.Holds...)
	for _, h := range rep.Holds {
		if h.Target == t {
			holds = append(holds, h) // other holds on this machine are not the retag's
		}
	}
	data["holds"] = withHoldNext(holds)
	if err != nil {
		return result{data: data}, err
	}
	return result{data: data, text: "committed " + short(id)}, attention(holds)
}

func (a *app) cmdProtectionAllow(cmd *cobra.Command, args []string) (result, error) {
	return a.allowOne(cmd, args[0], func(m *machineEnv, rev model.CommitID, t model.Target) error {
		return m.eng.AllowProtection(cmd.Context(), rev, t)
	})
}

func (a *app) cmdRootAllow(cmd *cobra.Command, args []string) (result, error) {
	return a.allowOne(cmd, args[0], func(m *machineEnv, rev model.CommitID, t model.Target) error {
		return m.eng.AllowRoot(cmd.Context(), rev, t)
	})
}

// allowRev is the source an allow reads. While a fetched source is refused
// (a manifest-guard hold), the allow names that fetched source, so the next
// sync takes it; otherwise local main.
func (m *machineEnv) allowRev(ctx context.Context) model.CommitID {
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return m.snap.Commit
	}
	for _, h := range hs {
		if h.Target == "" && h.Task == sync.HoldTaskGuard {
			if r, err := m.repo.ResolveRef(ctx, store.RemoteMain); err == nil && r != "" {
				return r
			}
		}
	}
	return m.snap.Commit
}

// allowOne records one local allow under the lock, then applies so the
// allowed target or root takes effect now. While a fetched source is
// refused, the allow names that source; the next sync then takes it.
func (a *app) allowOne(cmd *cobra.Command, arg string, allow func(*machineEnv, model.CommitID, model.Target) error) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	t, err := target(m.home, arg)
	if err != nil {
		return result{}, err
	}
	var res apply.Result
	fetched := false
	if err := m.locked(ctx, func() error {
		rev := m.allowRev(ctx)
		fetched = rev != m.snap.Commit
		if err := allow(m, rev, t); err != nil {
			if rev == m.snap.Commit {
				return err
			}
			// Not in the fetched source: it may be one local main weakens.
			if err2 := allow(m, m.snap.Commit, t); err2 != nil {
				return err
			}
			fetched = false
		}
		var err error
		res, err = m.eng.Apply(ctx, m.snap.Commit, apply.ApplyOptions{})
		return err
	}); err != nil {
		return lockedResult(err), err
	}
	res = normResult(res)
	out := result{data: map[string]any{"allowed": t, "apply": res}, text: "allowed " + string(t)}
	if fetched {
		out.next = []string{"yadm sync"} // takes the refused source now
	}
	return out, attention(res.Holds)
}

func (a *app) cmdBisect(cmd *cobra.Command, args []string) (result, error) {
	as, _ := cmd.Flags().GetString("as")
	if as == "" {
		return result{}, usagef("bisect needs --as <machine> -- <cmd>")
	}
	return result{}, fmt.Errorf("bisect: %w", model.ErrNotImplemented)
}

func (a *app) cmdCollect(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	snap := m.snap
	allowed := func(name string, def fleet.CollectorDef) bool {
		h, err := definitionHash(def)
		return err == nil && m.allow.Allowed(extexec.KindCollector, name, h)
	}
	base := m.request(extexec.KindCollector, "", a.json)
	var obs map[string]model.ObservedFact
	var skipped []string
	if err := m.locked(ctx, func() error {
		var err error
		obs, skipped, err = fleet.CollectWith(ctx, snap.Fleet, snap.Context, m.exec, allowed, base)
		if err != nil {
			return err
		}
		db := apply.FileStateDB(m.paths.State)
		st, err := db.Load()
		if err != nil {
			return err
		}
		if st.Observed == nil {
			st.Observed = map[string]model.ObservedFact{}
		}
		for k, v := range obs {
			st.Observed[k] = v
		}
		return db.Save(st)
	}); err != nil {
		return lockedResult(err), err
	}
	if obs == nil {
		obs = map[string]model.ObservedFact{}
	}
	if skipped == nil {
		skipped = []string{}
	}
	var next []string
	if len(skipped) > 0 {
		next = []string{"yadm task allow " + strings.Join(skipped, " ")}
	}
	return result{data: map[string]any{"observed": obs, "skipped": skipped}, next: next}, nil
}

// losers lists the fleet machines that receive t now (its entry's `when`
// holds for them) and have none of the new types. Conditions on observed
// facts see no observed facts for other machines.
func losers(snap *apply.Snapshot, t model.Target, types []model.TypeName) []model.MachineID {
	when := ""
	for _, e := range snap.Manifest.Entries {
		if e.Target == t {
			when = e.When
		}
	}
	expr := cond.Always()
	if when != "" {
		x, err := cond.Parse(when, snapVocab(snap))
		if err != nil {
			return []model.MachineID{}
		}
		expr = x
	}
	out := []model.MachineID{}
	for id, mc := range snap.Fleet.Machines {
		mc.ID = id
		keep := false
		for _, ty := range types {
			if mc.HasType(ty) {
				keep = true
			}
		}
		if !keep && expr.Eval(model.Context{Machine: mc}) {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
