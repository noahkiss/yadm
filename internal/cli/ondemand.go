package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

type showData struct {
	Machine  model.MachineID   `json:"machine"`
	Name     string            `json:"name,omitempty"`
	Target   model.Target      `json:"target"`
	Source   model.SourcePath  `json:"source"`
	Enclave  model.EnclaveName `json:"enclave,omitempty"`
	Content  string            `json:"content"`
	Encoding string            `json:"encoding"` // "utf-8", or "base64" for bytes that are not UTF-8
}

// cmdShow prints a target as a fleet machine receives it: the same render
// pipeline apply runs, with that machine's plan and condition context. It
// opens an enclave only when that machine is a member of its pinned key
// log and this machine holds the key, on demand or not. The plaintext goes
// to stdout only; nothing is written to $HOME, backups or the state.
func (a *app) cmdShow(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	t, err := target(m.home, args[0])
	if err != nil {
		return result{}, err
	}
	ids, err := pickMachines(cmd, m)
	if err != nil {
		return result{}, err
	}
	id := ids[0]
	self := id == m.local.Machine
	mctx, _ := machineCtx(m, statuses(ctx, m), id)
	plan := m.snap.Plan
	if !self {
		paths := make([]model.SourcePath, 0, len(m.snap.Tree))
		for p := range m.snap.Tree {
			paths = append(paths, p)
		}
		sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
		if plan, err = m.snap.Manifest.Resolve(mctx, paths, snapVocab(m.snap)); err != nil {
			return result{}, err
		}
		apply.ExpandRoots(m.snap.Manifest, plan, paths, nil) // another machine's allows are not known here
	}
	who := string(id)
	if mctx.Machine.Name != "" {
		who = mctx.Machine.Name
	}
	r, ok := plan.Targets[t]
	if !ok {
		return result{}, fmt.Errorf("%s is not delivered to %s", t, who)
	}
	// That machine opens what its pinned key log lists it in; this machine
	// can show only what it also holds the key for.
	member := func(e model.EnclaveName) bool {
		l, ok := m.snap.Enclaves[e]
		return ok && l.Err == nil && slices.ContainsFunc(l.Head.Members, func(x crypt.Member) bool { return x.Machine == id })
	}
	held := m.snap.Readable()
	var missing []model.EnclaveName
	for _, e := range m.snap.Fleet.Enclaves() {
		if member(e) && !m.snap.CanRead(e) {
			missing = append(missing, e)
		}
	}
	if enc := r.Entry.Enclave; enc != "" {
		if !member(enc) {
			return result{}, fmt.Errorf("%s is sealed for %s, and %s is not a member: it never receives it", t, enc, who)
		}
		if !m.snap.CanRead(enc) {
			return result{}, fmt.Errorf("%w: %s is sealed for %s, which this machine cannot open", ErrRefused, t, enc)
		}
	}
	for _, e := range r.Entry.Seal {
		if slices.Contains(missing, e) {
			return result{}, fmt.Errorf("%w: %s holds values sealed for %s, which this machine cannot open", ErrRefused, t, e)
		}
	}
	if r.Entry.Regions && len(missing) > 0 {
		return result{}, fmt.Errorf("%w: %s may hold regions of %v, which this machine cannot open", ErrRefused, t, missing)
	}
	keys := held.Only(member)
	view := *m.snap
	view.Plan, view.Context = plan, mctx
	view.Keys, view.ReadKeys, view.OnDemand = keys, keys, nil
	view.Crypto = apply.SetCrypto(keys)
	var live []byte
	if self {
		// keep rules merge into the live target, as apply does here.
		live, _ = os.ReadFile(filepath.Join(m.home, filepath.FromSlash(string(t))))
	}
	out, err := m.eng.Render(ctx, &view, t, live)
	if err != nil {
		return result{}, err
	}
	d := showData{Machine: id, Name: mctx.Machine.Name, Target: t, Source: r.Source, Enclave: r.Entry.Enclave, Content: string(out), Encoding: "utf-8"}
	if !utf8.Valid(out) {
		d.Content, d.Encoding = base64.StdEncoding.EncodeToString(out), "base64"
	}
	if out == nil {
		out = []byte{}
	}
	return result{data: d, raw: out}, nil
}

// cmdEnclaveOnDemand marks an enclave on demand on this machine, or clears
// the mark with --off, in machine.toml. It writes no key log and no commit.
func (a *app) cmdEnclaveOnDemand(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	off, _ := cmd.Flags().GetBool("off")
	e := model.EnclaveName(args[0])
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	if !off {
		// Refuse a name that is no enclave: it would protect nothing.
		snap, err := m.load(ctx)
		if err != nil {
			return result{}, err
		}
		if !slices.Contains(snap.Fleet.Enclaves(), e) {
			return result{}, usagef("fleet.toml declares no enclave %q", e)
		}
	}
	local := m.local
	list := slices.DeleteFunc(slices.Clone(local.OnDemand), func(x model.EnclaveName) bool { return x == e })
	if !off {
		list = append(list, e)
	}
	slices.Sort(list)
	local.OnDemand = list
	if len(list) == 0 {
		local.OnDemand = nil
	}
	if err := fleet.SaveIdentity(identityPath(m.paths), local); err != nil {
		return result{}, err
	}
	state := "on demand"
	if off {
		state = "delivered when this machine's types and membership say so"
	}
	data := map[string]any{"enclave": e, "on_demand": !off, "machine_toml": identityPath(m.paths)}
	return result{data: data, next: []string{"yadm apply"}, text: fmt.Sprintf("%s: %s on this machine; the next apply takes effect", e, state)}, nil
}

// onDemandClaims maps each enclave to the machines that read it on demand
// only: this machine from machine.toml, every other machine from the
// on_demand list of its status record. A peer's entry is self-reported.
func onDemandClaims(ctx context.Context, m *machineEnv) map[model.EnclaveName]map[model.MachineID]bool {
	out := map[model.EnclaveName]map[model.MachineID]bool{}
	put := func(e model.EnclaveName, id model.MachineID) {
		if out[e] == nil {
			out[e] = map[model.MachineID]bool{}
		}
		out[e][id] = true
	}
	if all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx); err == nil {
		for id, st := range all {
			if id == m.local.Machine {
				continue // machine.toml wins over this machine's last record
			}
			for _, e := range st.OnDemand {
				put(e, id)
			}
		}
	}
	for _, e := range m.local.OnDemand {
		put(e, m.local.Machine)
	}
	return out
}

// membership compares the fleet's machines of an enclave type with the
// members of the pinned key-log head. detail lists every member with its
// role: "type" (the fleet gives it the enclave's type), "on demand" (it
// says it reads the enclave on demand only) or "no type". diff is empty
// when they agree; a member that reads on demand is no disagreement.
func membership(f *fleet.File, e model.EnclaveName, head crypt.LogEntry, onDemand map[model.MachineID]bool) (detail, diff string) {
	inLog := map[model.MachineID]bool{}
	var roles []string
	for _, mb := range head.Members {
		inLog[mb.Machine] = true
		mc, ok := f.Machines[mb.Machine]
		var role []string
		if ok && mc.HasType(model.TypeName(e)) {
			role = append(role, "type")
		}
		if onDemand[mb.Machine] {
			role = append(role, "on demand")
		}
		if len(role) == 0 {
			role = append(role, "no type")
		}
		name := string(mb.Machine)
		if ok && mc.Name != "" {
			name += " " + mc.Name
		}
		roles = append(roles, name+" ("+strings.Join(role, ", ")+")")
	}
	sort.Strings(roles)
	var onlyFleet, onlyLog []string
	for id, mc := range f.Machines {
		if mc.HasType(model.TypeName(e)) && !inLog[id] {
			onlyFleet = append(onlyFleet, string(id))
		}
	}
	for id := range inLog {
		mc, ok := f.Machines[id]
		if (!ok || !mc.HasType(model.TypeName(e))) && !onDemand[id] {
			onlyLog = append(onlyLog, string(id))
		}
	}
	sort.Strings(onlyFleet)
	sort.Strings(onlyLog)
	var parts []string
	if len(onlyFleet) > 0 {
		parts = append(parts, "typed in the fleet but not key-log members: "+strings.Join(onlyFleet, ","))
	}
	if len(onlyLog) > 0 {
		parts = append(parts, "key-log members without the type in the fleet and not on demand: "+strings.Join(onlyLog, ","))
	}
	detail = fmt.Sprintf("%s: pinned seq %d, epoch %d; members: %s", e, head.Seq, head.Epoch, strings.Join(roles, ", "))
	return detail, strings.Join(parts, "; ")
}

// onDemandCheck reports one enclave that machine.toml marks on demand. A
// name that is not an enclave fails: it protects nothing, and a typo would
// leave the intended enclave delivered.
func onDemandCheck(snap *apply.Snapshot, e model.EnclaveName) checkItem {
	it := checkItem{Name: "on_demand", OK: true}
	l, loaded := snap.Enclaves[e]
	switch {
	case !slices.Contains(snap.Fleet.Enclaves(), e):
		it.OK = false
		it.Detail = fmt.Sprintf("machine.toml marks %s on demand, but fleet.toml declares no such enclave; fix the name", e)
	case loaded && l.Err != nil:
		it.Detail = fmt.Sprintf("%s: on demand; key log refused, nothing opens", e)
	case snap.CanRead(e):
		it.Detail = fmt.Sprintf("%s: on demand; member at pinned seq %d; never applied, captured or backed up here", e, l.Head.Seq)
	default:
		it.Detail = fmt.Sprintf("%s: on demand; this machine holds no key for it", e)
	}
	return it
}
