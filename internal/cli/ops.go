package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
	"github.com/noahkiss/yadm/internal/tasks"
)

// ---- fleet ----

func (a *app) cmdFleetList(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	if err != nil {
		return result{}, err
	}
	rows := fleet.List(m.snap.Fleet, all, hooks.now())
	if rows == nil {
		rows = []fleet.Summary{}
	}
	var b strings.Builder
	for _, r := range rows {
		last := "never"
		held := 0
		if r.Status != nil {
			last = r.Status.LastSync.UTC().Format(time.RFC3339)
			held = r.Status.Held
		}
		stale := ""
		if r.Stale {
			stale = " STALE"
		}
		fmt.Fprintf(&b, "%-10s %-14s last %s held %d%s\n", r.Machine.ID, r.Machine.Name, last, held, stale)
	}
	return result{data: map[string]any{"machines": rows}, text: b.String()}, nil
}

func (a *app) cmdFleetShow(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	mc, err := m.snap.Fleet.Lookup(args[0])
	if err != nil {
		return result{next: []string{"yadm fleet list"}}, usagef("%v", err)
	}
	id := lookupID(m.snap.Fleet, mc)
	mc.ID = id
	all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	if err != nil {
		return result{}, err
	}
	var st *model.Status
	if s, ok := all[id]; ok {
		st = &s
	}
	stale := st == nil || hooks.now().Sub(st.LastSync) > fleet.StaleAfter
	return result{data: fleet.Summary{Machine: mc, Status: st, Stale: stale}}, nil
}

func (a *app) cmdFleetDiff(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	if _, ok := m.snap.Fleet.Collectors[args[0]]; !ok {
		return result{}, usagef("no collector %q in fleet.toml", args[0])
	}
	all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	if err != nil {
		return result{}, err
	}
	d, err := fleet.DiffObserved(all, args[0])
	if err != nil {
		return result{}, err
	}
	if d.Union == nil {
		d.Union = []string{}
	}
	if d.Missing == nil {
		d.Missing = map[model.MachineID][]string{}
	}
	if d.Unknown == nil {
		d.Unknown = []model.MachineID{}
	}
	var b strings.Builder
	ids := make([]string, 0, len(d.Missing))
	for id := range d.Missing {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&b, "%s lacks %s\n", id, strings.Join(d.Missing[model.MachineID(id)], ", "))
	}
	for _, id := range d.Unknown {
		fmt.Fprintf(&b, "%s: no value\n", id)
	}
	return result{data: d, text: b.String()}, nil
}

// ---- review ----

func (a *app) cmdReviewList(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	scopes := []model.Scope{model.ScopeShared}
	for _, e := range m.snap.Fleet.Enclaves() {
		scopes = append(scopes, model.Scope(e))
	}
	if len(args) == 1 {
		scopes = []model.Scope{model.Scope(args[0])}
	}
	items := []sync.ReviewItem{}
	for _, s := range scopes {
		it, err := sync.Unreviewed(ctx, m.repo, m.snap.Keys, s)
		if err != nil {
			return result{}, err
		}
		items = append(items, it...)
	}
	return result{data: map[string]any{"items": items}}, nil
}

func (a *app) cmdReviewOK(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	c, err := m.repo.ResolveRef(ctx, args[1])
	if err != nil {
		return result{}, err
	}
	if c == "" {
		return result{}, usagef("unknown commit %q", args[1])
	}
	if err := sync.Ack(ctx, m.repo, model.Scope(args[0]), c); err != nil {
		return result{}, err
	}
	return result{data: map[string]any{"scope": args[0], "reviewed": c}}, nil
}

func (a *app) cmdReviewRevert(cmd *cobra.Command, args []string) (result, error) {
	return result{}, fmt.Errorf("review revert: %w", model.ErrNotImplemented)
}

// ---- holds ----

func (a *app) cmdHoldList(fixed model.HoldReason) runFunc {
	return func(cmd *cobra.Command, args []string) (result, error) {
		ctx := cmd.Context()
		reason := fixed
		if f := cmd.Flags().Lookup("reason"); f != nil && f.Value.String() != "" {
			reason = model.HoldReason(f.Value.String())
		}
		m, err := open(ctx)
		if err != nil {
			return notInit(err), err
		}
		hs, err := m.eng.Holds(ctx)
		if err != nil {
			return result{}, err
		}
		var keep []model.Hold
		for _, h := range hs {
			if reason == "" || h.Reason == reason {
				keep = append(keep, h)
			}
		}
		keep = withHoldNext(keep)
		sort.SliceStable(keep, func(i, j int) bool { return keep[i].Since.Before(keep[j].Since) })
		var b strings.Builder
		for _, h := range keep {
			fmt.Fprintf(&b, "%s %-14s %s%s\n", h.ID[:min(12, len(h.ID))], h.Reason, h.Target, h.Task)
		}
		if len(keep) == 0 {
			b.WriteString("no holds\n")
		}
		return result{data: map[string]any{"holds": keep}, text: b.String()}, attention(keep)
	}
}

// findHold returns the hold whose id equals or starts with key.
func findHold(hs []model.Hold, key string) (model.Hold, error) {
	var found []model.Hold
	for _, h := range withHoldNext(hs) {
		if h.ID == key {
			return h, nil
		}
		if len(key) >= 6 && strings.HasPrefix(h.ID, key) {
			found = append(found, h)
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return model.Hold{}, usagef("no hold %q", key)
	}
	return model.Hold{}, usagef("hold id %q is ambiguous", key)
}

type holdSide struct {
	Blob    string `json:"blob"`
	Content string `json:"content,omitempty"`
	Sealed  bool   `json:"sealed,omitempty"` // this machine cannot open it
	Binary  bool   `json:"binary,omitempty"`
}

func (a *app) cmdHoldShow(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return result{}, err
	}
	h, err := findHold(hs, args[0])
	if err != nil {
		return result{}, err
	}
	snap, _ := m.load(ctx)
	enc := model.EnclaveName("")
	if h.Scope != model.ScopeShared {
		enc = model.EnclaveName(h.Scope)
	}
	side := func(blob string) *holdSide {
		if blob == "" {
			return nil
		}
		s := &holdSide{Blob: blob}
		b, err := m.repo.ReadBlob(ctx, blob)
		if err != nil {
			s.Content = ""
			return s
		}
		if crypt.IsSealedFile(b) {
			if snap == nil || enc == "" || snap.Crypto == nil || !(refusingSealer{snap}).ok(enc) {
				s.Sealed = true
				return s
			}
			if b, err = snap.Crypto.OpenFile(enc, b); err != nil {
				s.Sealed = true
				return s
			}
		}
		if isBinary(b) {
			s.Binary = true
			return s
		}
		s.Content = string(b)
		return s
	}
	data := map[string]any{"hold": h, "base": side(h.Base), "ours": side(h.Ours), "theirs": side(h.Theirs)}
	text := fmt.Sprintf("%s %s %s%s since %s\n%s", h.ID, h.Reason, h.Target, h.Task, h.Since.UTC().Format(time.RFC3339), h.Detail)
	return result{data: data, next: h.Next, text: text}, nil
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

func (a *app) cmdHoldResolve(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	take, _ := cmd.Flags().GetString("take")
	if take == "" {
		return result{next: []string{"yadm hold resolve " + args[0] + " --take source", "yadm hold resolve " + args[0] + " --take target"}},
			usagef("--take source|target|<file> is required")
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return result{}, err
	}
	h, err := findHold(hs, args[0])
	if err != nil {
		return result{}, err
	}
	res, err := m.eng.ResolveHold(ctx, h.ID, apply.ResolveOptions{Take: take})
	if err != nil {
		return result{}, err
	}
	res = normResult(res)
	var next []string
	if res.Capture != nil && len(res.Capture.Paths) > 0 {
		var ps []string
		for _, p := range res.Capture.Paths {
			ps = append(ps, string(p))
		}
		next = []string{"yadm commit " + strings.Join(ps, " ")}
	}
	return result{data: map[string]any{"resolved": h.ID, "result": res}, next: next, text: actionsText(res)}, attention(res.Holds)
}

// ---- leases ----

func (a *app) cmdLeaseTake(cmd *cobra.Command, args []string) (result, error) {
	holder, _ := cmd.Flags().GetString("holder")
	ttl, _ := cmd.Flags().GetDuration("ttl")
	if holder == "" {
		return result{}, usagef("--holder is required")
	}
	if ttl <= 0 {
		return result{}, usagef("--ttl must be positive")
	}
	p, err := DefaultPaths()
	if err != nil {
		return result{}, err
	}
	l := sync.Lease{Holder: holder, Paths: args, Expires: hooks.now().Add(ttl).UTC()}
	if err := sync.FileLeases(p.State).Take(l); err != nil {
		return result{}, err
	}
	return result{data: l}, nil
}

func (a *app) cmdLeaseRelease(cmd *cobra.Command, args []string) (result, error) {
	p, err := DefaultPaths()
	if err != nil {
		return result{}, err
	}
	if err := sync.FileLeases(p.State).Release(args[0]); err != nil {
		return result{}, err
	}
	return result{data: map[string]any{"released": args[0]}}, nil
}

func (a *app) cmdLeaseList(cmd *cobra.Command, args []string) (result, error) {
	p, err := DefaultPaths()
	if err != nil {
		return result{}, err
	}
	ls, err := sync.FileLeases(p.State).List()
	if err != nil {
		return result{}, err
	}
	if ls == nil {
		ls = []sync.Lease{}
	}
	return result{data: map[string]any{"leases": ls}}, nil
}

// ---- tasks ----

func newAllow(stateDir string) tasks.AllowList { return tasks.FileAllowList(stateDir) }

func definitionHash(def any) (string, error) { return tasks.DefinitionHash(def) }

type definition struct {
	Kind    extexec.Kind `json:"kind"`
	Name    string       `json:"name"`
	Hash    string       `json:"hash"`
	Allowed bool         `json:"allowed"`
	Applies bool         `json:"applies"` // its when matches this machine
	Def     any          `json:"definition"`
}

// definitions lists every task, check and collector definition, sorted.
func definitions(allow tasks.AllowList, man *manifest.Manifest, fl *fleet.File, plan *manifest.Plan) ([]definition, error) {
	var out []definition
	add := func(kind extexec.Kind, name string, def any, applies bool) error {
		h, err := definitionHash(def)
		if err != nil {
			return err
		}
		out = append(out, definition{Kind: kind, Name: name, Hash: h, Allowed: allow.Allowed(kind, name, h), Applies: applies, Def: def})
		return nil
	}
	if man != nil {
		for n, d := range man.Tasks {
			_, ok := planHas(plan, n, true)
			if err := add(extexec.KindTask, n, d, ok); err != nil {
				return nil, err
			}
		}
		for n, d := range man.Checks {
			_, ok := planHas(plan, n, false)
			if err := add(extexec.KindCheck, n, d, ok); err != nil {
				return nil, err
			}
		}
	}
	if fl != nil {
		for n, d := range fl.Collectors {
			if err := add(extexec.KindCollector, n, d, true); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func planHas(p *manifest.Plan, name string, task bool) (any, bool) {
	if p == nil {
		return nil, true
	}
	if task {
		d, ok := p.Tasks[name]
		return d, ok
	}
	d, ok := p.Checks[name]
	return d, ok
}

// allowDefinitions allows the named definitions (all when names is empty)
// and returns "kind:name" for each one allowed.
func allowDefinitions(allow tasks.AllowList, man *manifest.Manifest, fl *fleet.File, names []string) ([]string, error) {
	defs, err := definitions(allow, man, fl, nil)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var done []string
	for _, d := range defs {
		if len(names) > 0 && !want[d.Name] {
			continue
		}
		delete(want, d.Name)
		if err := allow.Allow(d.Kind, d.Name, d.Hash); err != nil {
			return done, err
		}
		done = append(done, string(d.Kind)+":"+d.Name)
	}
	if len(want) > 0 {
		var missing []string
		for n := range want {
			missing = append(missing, n)
		}
		sort.Strings(missing)
		return done, usagef("no task, check or collector named %s", strings.Join(missing, ", "))
	}
	if done == nil {
		done = []string{}
	}
	return done, nil
}

func (a *app) cmdTaskList(cmd *cobra.Command, args []string) (result, error) {
	m, err := openLoaded(cmd.Context())
	if err != nil {
		return notInit(err), err
	}
	defs, err := definitions(m.allow, m.snap.Manifest, m.snap.Fleet, m.snap.Plan)
	if err != nil {
		return result{}, err
	}
	if defs == nil {
		defs = []definition{}
	}
	var b strings.Builder
	var next []string
	for _, d := range defs {
		fmt.Fprintf(&b, "%-10s %-20s allowed=%v applies=%v\n", d.Kind, d.Name, d.Allowed, d.Applies)
		if !d.Allowed {
			next = append(next, "yadm task allow "+d.Name)
		}
	}
	return result{data: map[string]any{"definitions": defs}, text: b.String(), next: next}, nil
}

func (a *app) cmdTaskAllow(cmd *cobra.Command, args []string) (result, error) {
	m, err := openLoaded(cmd.Context())
	if err != nil {
		return notInit(err), err
	}
	done, err := allowDefinitions(m.allow, m.snap.Manifest, m.snap.Fleet, args)
	return result{data: map[string]any{"allowed": done}}, err
}

func (a *app) cmdTaskRun(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	def, ok := m.snap.Manifest.Tasks[args[0]]
	if !ok {
		return result{next: []string{"yadm task list"}}, usagef("no task %q in manifest.toml", args[0])
	}
	h, err := definitionHash(def)
	if err != nil {
		return result{}, err
	}
	if !m.allow.Allowed(extexec.KindTask, args[0], h) {
		return result{next: []string{"yadm task allow " + args[0]}}, fmt.Errorf("%w: task %s is not allowed on this machine", ErrRefused, args[0])
	}
	runner := &tasks.Runner{Exec: m.exec, Allow: m.allow}
	req := m.request(extexec.KindTask, args[0], a.json)
	results, holds := runner.Run(ctx, tasks.Event{Commit: m.snap.Commit}, []tasks.Selected{{Name: args[0], Trigger: "manual", Def: def}}, req)
	if results == nil {
		results = []model.TaskResult{}
	}
	data := map[string]any{"tasks": results, "holds": withHoldNext(holds)}
	for _, r := range results {
		if r.ExitCode != 0 || r.Error != "" {
			return result{data: data}, fmt.Errorf("task %s failed: exit %d %s", r.Task, r.ExitCode, r.Error)
		}
	}
	return result{data: data}, attention(holds)
}

// ---- schedule ----

func (a *app) cmdScheduleInstall(cmd *cobra.Command, args []string) (result, error) {
	s, err := hooks.scheduler()
	if err != nil {
		return result{}, err
	}
	if err := s.Install(cmd.Context(), scheduleSpec()); err != nil {
		return result{}, err
	}
	st, err := s.Status(cmd.Context())
	return result{data: st}, err
}

func (a *app) cmdScheduleUninstall(cmd *cobra.Command, args []string) (result, error) {
	s, err := hooks.scheduler()
	if err != nil {
		return result{}, err
	}
	if err := s.Uninstall(cmd.Context()); err != nil {
		return result{}, err
	}
	st, err := s.Status(cmd.Context())
	return result{data: st}, err
}

func (a *app) cmdScheduleStatus(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	s, err := hooks.scheduler()
	if err != nil {
		return result{}, err
	}
	st, err := s.Status(ctx)
	if err != nil {
		return result{}, err
	}
	if st.LastRun.IsZero() {
		if m, err := open(ctx); err == nil {
			if self := m.selfStatus(ctx); self != nil {
				st.LastRun = self.LastSync
			}
		}
	}
	var next []string
	if !st.Installed {
		next = []string{"yadm schedule install"}
	}
	return result{data: st, next: next}, nil
}
