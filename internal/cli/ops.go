package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	for i := range rows {
		openSummary(m, &rows[i])
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
		paused := ""
		if r.Status != nil && r.Status.PausedUntil != nil && r.Status.PausedUntil.After(hooks.now()) {
			paused = " paused until " + clock(*r.Status.PausedUntil)
			if !r.Status.PauseVerified {
				paused += " (unverified)"
			}
		}
		fmt.Fprintf(&b, "%-10s %-14s last %s held %d%s%s\n", r.Machine.ID, r.Machine.Name, last, held, stale, paused)
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
	row := fleet.Summary{Machine: mc, Status: st, Stale: stale}
	openSummary(m, &row)
	return result{data: row}, nil
}

// openSummary adds the sealed observed facts this machine can open to a
// fleet row. Status stays the raw published record, so a non-member's row is
// unchanged.
func openSummary(m *machineEnv, row *fleet.Summary) {
	if row.Status == nil {
		return
	}
	opened, problems := fleet.OpenAll(m.snap.Fleet, *row.Status, m.snap.Readable())
	row.SealedObserved = opened
	for _, p := range problems {
		row.SealedErrors = append(row.SealedErrors, p.Error())
	}
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
	// A member compares the sealed collectors it can open; a non-member sees
	// the plain facts only, as published.
	visible, _ := fleet.WithVisible(m.snap.Fleet, all, m.snap.Readable())
	d, err := fleet.DiffObserved(visible, args[0])
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
		it, err := sync.Unreviewed(ctx, m.repo, m.snap.Readable(), s)
		if err != nil {
			return result{}, err
		}
		items = append(items, it...)
	}
	if notes := m.notes(ctx); len(notes) > 0 {
		for i := range items {
			if n, ok := notes[items[i].Commit.ID]; ok {
				items[i].Note = &n
			}
		}
	}
	// Decisions agents deferred wait here too, while their holds are open.
	var deferred []Deferred
	if hs, err := m.eng.Holds(ctx); err == nil {
		deferred = openDeferred(m.paths.State, hs, m.managedTargets())
	}
	if deferred == nil {
		deferred = []Deferred{}
	}
	var next []string
	for _, d := range deferred {
		next = append(next, "yadm hold show "+d.ID)
	}
	return result{data: map[string]any{"items": items, "deferred": deferred}, next: next}, nil
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
			if snap == nil || enc == "" || !snap.CanRead(enc) {
				s.Sealed = true
				return s
			}
			// Hold sides are old content: read them with every epoch's key.
			if b, err = apply.SetCrypto(snap.Readable().History()).OpenFile(enc, holdSource(snap, h, enc), b); err != nil {
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

// holdSource is the source path a hold's blobs were sealed under: the
// hold's own, the plan's, or the default sealed path.
func holdSource(snap *apply.Snapshot, h model.Hold, enc model.EnclaveName) model.SourcePath {
	if h.Source != "" {
		return h.Source
	}
	if snap.Plan != nil {
		if r, ok := snap.Plan.Targets[h.Target]; ok {
			return r.Source
		}
	}
	return model.SourcePath("sealed/" + string(enc) + "/" + string(h.Target))
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

// cmdHoldIgnore records the file of a hold as intentionally untracked on
// this machine. It applies to unmanaged files in owned roots (the
// baseline files that predate a root, and new files a hook held).
func (a *app) cmdHoldIgnore(cmd *cobra.Command, args []string) (result, error) {
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
	if h.Target == "" {
		return result{}, usagef("hold %s names no file; only a file can be ignored", args[0])
	}
	snap, _ := m.load(ctx) // nil when the source does not load: state alone decides
	if err := m.locked(ctx, func() error { return m.eng.Ignore(ctx, snap, h.Target) }); err != nil {
		if errors.Is(err, apply.ErrManaged) || errors.Is(err, apply.ErrNotIgnorable) {
			return result{}, usagef("%v", err)
		}
		return lockedResult(err), err
	}
	return result{data: map[string]any{"ignored": h.Target, "hold": h.ID},
		next: []string{"yadm commit " + model.ShellQuote(string(h.Target))},
		text: "ignored " + string(h.Target) + " on this machine; `yadm commit " + string(h.Target) + "` tracks it again"}, nil
}

func (a *app) cmdHoldResolve(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	take, _ := cmd.Flags().GetString("take")
	if take == "" {
		return result{next: []string{"yadm hold resolve " + model.ShellQuote(args[0]) + " --take source", "yadm hold resolve " + model.ShellQuote(args[0]) + " --take target"}},
			usagef("--take source|target|<file> is required")
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	if res, err := m.refuseHeld(ctx); err != nil {
		return res, err
	}
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return result{}, err
	}
	h, err := findHold(hs, args[0])
	if err != nil {
		return result{}, err
	}
	if h.Reason == model.HoldConflict && h.Target != "" {
		return a.resolveConflict(ctx, m, h, take)
	}
	var res apply.Result
	if err := m.locked(ctx, func() error {
		var err error
		res, err = m.eng.ResolveHold(ctx, h.ID, apply.ResolveOptions{Take: take})
		return err
	}); err != nil {
		return lockedResult(err), err
	}
	res = normResult(res)
	data := map[string]any{"resolved": h.ID, "result": res}
	if res.Capture == nil || len(res.Capture.Paths) == 0 {
		return result{data: data, text: actionsText(res)}, attention(res.Holds)
	}
	// Taking the target (or a merged file) captured it: commit it now, over
	// the current source when it settles a conflict, and push.
	_, _ = m.load(ctx)
	rep, pushErr, err := m.commitThrough(ctx, a.version, sync.CommitOptions{
		Paths: res.Capture.Paths, Resolve: h.Reason == model.HoldConflict, Push: true,
		Message: "resolve " + string(h.Target) + " (" + string(h.Reason) + ")",
	})
	if err != nil {
		return result{data: data, next: []string{"yadm commit " + model.ShellQuote(string(h.Target))}}, err
	}
	rep = reportData(rep)
	data["commits"] = rep.Committed
	if pushErr != nil {
		data["push_error"] = pushErr.Error()
	}
	holds := append(res.Holds, rep.Holds...)
	data["holds"] = withHoldNext(holds)
	text := actionsText(res)
	if len(rep.Committed) > 0 {
		text = fmt.Sprintf("resolved %s: committed %s", h.Target, short(rep.Committed[len(rep.Committed)-1]))
	}
	return result{data: data, text: text}, attention(holds)
}

// resolveConflict settles a conflict hold sync raised. Taking the target (or
// a merged file, written to the target first) commits this machine's file
// over the current source and pushes it. Taking the source drops the hold
// and rewrites the target from the source; the replaced bytes are backed up.
func (a *app) resolveConflict(ctx context.Context, m *machineEnv, h model.Hold, take string) (result, error) {
	abs := filepath.Join(m.home, filepath.FromSlash(string(h.Target)))
	if err := apply.InsideHome(m.home, abs); err != nil {
		return result{}, fmt.Errorf("%s: %w", h.Target, err)
	}
	data := map[string]any{"resolved": h.ID}
	switch take {
	case "source":
		var res apply.Result
		err := m.locked(ctx, func() error {
			if err := dropConflict(m.paths.State, h.Target); err != nil {
				return err
			}
			snap, err := m.load(ctx)
			if err != nil {
				return err
			}
			if _, err := m.eng.Apply(ctx, snap.Commit, apply.ApplyOptions{Paths: []model.Target{h.Target}}); err != nil {
				return err
			}
			// The target differs from the last write, so apply held it as
			// drifted; taking the source settles that hold.
			hs, err := m.eng.Holds(ctx)
			if err != nil {
				return err
			}
			for _, d := range withHoldNext(hs) {
				if d.Target == h.Target && d.Reason == model.HoldDrifted {
					res, err = m.eng.ResolveHold(ctx, d.ID, apply.ResolveOptions{Take: "source"})
					return err
				}
			}
			return nil
		})
		if err != nil {
			return lockedResult(err), err
		}
		res = normResult(res)
		data["result"] = res
		return result{data: data, text: actionsText(res)}, attention(res.Holds)
	case "target":
	default:
		b, err := os.ReadFile(take)
		if err != nil {
			return result{}, err
		}
		mode := os.FileMode(0o644)
		if info, err := os.Stat(abs); err == nil {
			mode = info.Mode().Perm()
		}
		if err := writeFileAtomic(abs, b, mode); err != nil {
			return result{}, err
		}
	}
	_, _ = m.load(ctx)
	rep, pushErr, err := m.commitThrough(ctx, a.version, sync.CommitOptions{
		Paths: []model.Target{h.Target}, Resolve: true, Push: true,
		Message: "resolve " + string(h.Target) + " (conflict)",
	})
	if err != nil {
		return result{data: data}, err
	}
	rep = reportData(rep)
	data["commits"] = rep.Committed
	if pushErr != nil {
		data["push_error"] = pushErr.Error()
	}
	var holds []model.Hold
	for _, x := range rep.Holds {
		if x.Target == h.Target {
			holds = append(holds, x)
		}
	}
	data["holds"] = withHoldNext(holds)
	return result{data: data, text: fmt.Sprintf("resolved %s: %d commit(s)", h.Target, len(rep.Committed))}, attention(holds)
}

// dropConflict removes t's conflict holds from the state.
func dropConflict(stateDir string, t model.Target) error {
	db := apply.FileStateDB(stateDir)
	st, err := db.Load()
	if err != nil {
		return err
	}
	out := st.Holds[:0]
	for _, x := range st.Holds {
		if !(x.Target == t && x.Reason == model.HoldConflict) {
			out = append(out, x)
		}
	}
	st.Holds = out
	return db.Save(st)
}

// writeFileAtomic writes b to p through a temp file and a rename.
func writeFileAtomic(p string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".yadm-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	return os.Rename(tmp, p)
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
	if err := sync.FileLeases(p.State).Release(args[0], args[1:]...); err != nil {
		return result{}, err
	}
	data := map[string]any{"released": args[0]}
	if len(args) > 1 {
		data["paths"] = args[1:]
	}
	return result{data: data}, nil
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
// mctx is this machine's context; nil (no snapshot) counts every collector as
// applying.
func definitions(allow tasks.AllowList, man *manifest.Manifest, fl *fleet.File, plan *manifest.Plan, mctx *model.Context) ([]definition, error) {
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
			applies := mctx == nil || fl.CollectorApplies(n, *mctx)
			if err := add(extexec.KindCollector, n, d, applies); err != nil {
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
	defs, err := definitions(allow, man, fl, nil, nil)
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
	defs, err := definitions(m.allow, m.snap.Manifest, m.snap.Fleet, m.snap.Plan, &m.snap.Context)
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
		if !d.Allowed && d.Applies {
			next = append(next, "yadm task allow "+model.ShellQuote(d.Name))
		}
	}
	return result{data: map[string]any{"definitions": defs}, text: b.String(), next: next}, nil
}

func (a *app) cmdTaskAllow(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	// The allow list is state a sync reads: write it under the lock, from
	// the definitions at main once the lock is held.
	var done []string
	if err := m.locked(ctx, func() error {
		if _, err := m.reload(ctx); err != nil {
			return err
		}
		done, err = allowDefinitions(m.allow, m.snap.Manifest, m.snap.Fleet, args)
		return err
	}); err != nil {
		if errors.Is(err, sync.ErrLocked) {
			return lockedResult(err), err
		}
		return result{data: map[string]any{"allowed": done}}, err
	}
	return result{data: map[string]any{"allowed": done}}, nil
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
		return result{next: []string{"yadm task allow " + model.ShellQuote(args[0])}}, fmt.Errorf("%w: task %s is not allowed on this machine", ErrRefused, args[0])
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
		if p, err := DefaultPaths(); err == nil {
			st.LastRun = lastScheduledRun(p.State)
		}
	}
	if st.LastRun.IsZero() {
		if m, err := open(ctx); err == nil {
			if self := m.selfStatus(ctx); self != nil {
				st.LastRun = self.LastSync
			}
		}
	}
	var next []string
	if !st.Installed || st.Broken() != "" {
		next = []string{"yadm schedule install"}
	}
	return result{data: st, next: next}, nil
}

// notes reads the review notes this machine may see: sealed ones open only
// for members. A failure reads as no notes.
func (m *machineEnv) notes(ctx context.Context) map[model.CommitID]sync.Note {
	var keys *crypt.Set
	if snap, err := m.load(ctx); err == nil {
		keys = snap.Readable()
	}
	n, err := sync.ReadNotes(ctx, m.repo, keys)
	if err != nil {
		return nil
	}
	return n
}

type noteData struct {
	Note      sync.Note `json:"note"`
	Pushed    bool      `json:"pushed"`
	PushError string    `json:"push_error,omitempty"`
}

func (a *app) cmdReviewNote(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	why, _ := cmd.Flags().GetString("why")
	seal, _ := cmd.Flags().GetString("seal")
	pathsOnly, _ := cmd.Flags().GetBool("paths-only")
	noPush, _ := cmd.Flags().GetBool("no-push")
	if pathsOnly == (why != "") {
		return result{}, usagef("give exactly one of --why or --paths-only")
	}
	if pathsOnly && seal != "" {
		return result{}, usagef("--paths-only writes no text to seal")
	}
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	var d noteData
	err = m.locked(ctx, func() error {
		n, err := sync.WriteNote(ctx, m.repo, m.snap, sync.NoteOptions{
			Commit: model.CommitID(args[0]), Why: why, PathsOnly: pathsOnly, Seal: model.EnclaveName(seal),
			Machine: m.local.Machine, Now: hooks.now(),
		})
		if err != nil {
			return err
		}
		d.Note = n
		return nil
	})
	if err == nil && !noPush {
		// The push runs after the sync lock is released, under the
		// network lock. Its fetch moves origin/main, so a machine with no
		// accepted record records its start first.
		var start model.CommitID
		var holds []model.Hold
		if start, err = m.repo.ResolveRef(ctx, store.RemoteMain); err == nil {
			if holds, err = m.eng.Holds(ctx); err == nil {
				_, err = sync.SeedStart(ctx, m.repo, m.paths.State, holds, start)
			}
		}
		if err == nil {
			d.Pushed, err = sync.PushNotes(ctx, m.repo, m.lock(0), sync.FileNetLock(m.paths.State))
		}
		if err != nil {
			d.PushError = err.Error()
		}
		err = nil
	}
	if errors.Is(err, sync.ErrNoteNeedsSeal) {
		return result{next: []string{"yadm review note " + model.ShellQuote(args[0]) + " --paths-only"}}, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if err != nil {
		return result{}, err
	}
	text := fmt.Sprintf("noted %s: %s", short(d.Note.Commit), d.Note.Text())
	var next []string
	if !d.Pushed && !noPush {
		next = []string{"yadm sync"}
	}
	return result{data: d, text: text, next: next}, nil
}
