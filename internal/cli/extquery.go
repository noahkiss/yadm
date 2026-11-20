package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// Schemas of the read-only queries extensions rely on (docs/extensions.md).
// Fields are only added within a schema version.
const (
	ManifestQuerySchema = 1
	EvalQuerySchema     = 1
)

// Where a query's observed facts come from.
const (
	observedLocal     = "local"     // this machine's own local state
	observedPublished = "published" // another machine's collectors published plain
	observedNone      = "none"      // another machine that published none
)

type rulesSummary struct {
	Format   manifest.Format              `json:"format,omitempty"`
	Keep     []string                     `json:"keep,omitempty"`
	Drop     []string                     `json:"drop,omitempty"`
	Volatile []string                     `json:"volatile,omitempty"`
	Seal     map[string]model.EnclaveName `json:"seal,omitempty"` // key path -> enclave; never a value
	Regions  bool                         `json:"regions,omitempty"`
}

type manifestEntry struct {
	Target       model.Target      `json:"target"`
	Source       model.SourcePath  `json:"source"`
	Index        int               `json:"index"`
	When         string            `json:"when"`
	WhenExpanded string            `json:"when_expanded"`
	Mode         string            `json:"mode"`
	Enclave      model.EnclaveName `json:"enclave,omitempty"`
	Scope        model.Scope       `json:"scope"`
	Merge        string            `json:"merge"`
	Template     bool              `json:"template,omitempty"`
	Review       bool              `json:"review,omitempty"`
	Rules        *rulesSummary     `json:"rules,omitempty"`
	Unit         *manifest.Unit    `json:"unit,omitempty"`
}

type manifestMachine struct {
	Machine  model.MachineID  `json:"machine"`
	Name     string           `json:"name"`
	Types    []model.TypeName `json:"types"`
	Observed string           `json:"observed"`
	Error    string           `json:"error,omitempty"`
	Entries  []manifestEntry  `json:"entries"`
	Roots    []manifest.Root  `json:"roots"`
	Tasks    []string         `json:"tasks"`
}

type manifestQuery struct {
	Schema   int               `json:"schema"`
	Commit   model.CommitID    `json:"commit"`
	Outputs  []string          `json:"outputs"`
	Machines []manifestMachine `json:"machines"`
}

// machineCtx builds the condition Context of fleet machine id. This machine
// uses its own observed facts; another uses only what it published plain.
func machineCtx(m *machineEnv, published map[model.MachineID]model.Status, id model.MachineID) (model.Context, string) {
	if id == m.local.Machine {
		return m.snap.Context, observedLocal
	}
	mc := m.snap.Fleet.Machines[id]
	mc.ID = id
	ctx := model.Context{Machine: mc}
	if st, ok := published[id]; ok && len(st.Observed) > 0 {
		ctx.Observed = st.Observed
		return ctx, observedPublished
	}
	return ctx, observedNone
}

// statuses reads every status ref; a failure reads as none published.
func statuses(ctx context.Context, m *machineEnv) map[model.MachineID]model.Status {
	all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	if err != nil {
		return nil
	}
	return all
}

// pickMachines returns the machine ids a query covers: --fleet gives every
// fleet machine, --as one, and neither this machine.
func pickMachines(cmd *cobra.Command, m *machineEnv) ([]model.MachineID, error) {
	as, _ := cmd.Flags().GetString("as")
	all, _ := cmd.Flags().GetBool("fleet")
	switch {
	case all && as != "":
		return nil, usagef("--as and --fleet exclude each other")
	case all:
		ids := make([]model.MachineID, 0, len(m.snap.Fleet.Machines))
		for id := range m.snap.Fleet.Machines {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		return ids, nil
	case as != "":
		mc, err := m.snap.Fleet.Lookup(as)
		if err != nil {
			return nil, usagef("%v", err)
		}
		return []model.MachineID{lookupID(m.snap.Fleet, mc)}, nil
	}
	return []model.MachineID{m.local.Machine}, nil
}

func (a *app) cmdManifest(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	ids, err := pickMachines(cmd, m)
	if err != nil {
		return result{}, err
	}
	pub := statuses(ctx, m)
	q := manifestQuery{Schema: ManifestQuerySchema, Commit: m.snap.Commit, Outputs: m.snap.Manifest.Outputs(), Machines: []manifestMachine{}}
	if q.Outputs == nil {
		q.Outputs = []string{}
	}
	var b strings.Builder
	for _, id := range ids {
		mm := resolveFor(m, pub, id)
		q.Machines = append(q.Machines, mm)
		fmt.Fprintf(&b, "%s %s: %d entries, %d roots", mm.Machine, mm.Name, len(mm.Entries), len(mm.Roots))
		if mm.Error != "" {
			fmt.Fprintf(&b, " (error: %s)", mm.Error)
		}
		b.WriteString("\n")
	}
	return result{data: q, text: b.String()}, nil
}

// resolveFor resolves the loaded manifest for one fleet machine. It reads
// no file content, so no enclave plaintext can reach the output.
func resolveFor(m *machineEnv, pub map[model.MachineID]model.Status, id model.MachineID) manifestMachine {
	mctx, obs := machineCtx(m, pub, id)
	mm := manifestMachine{Machine: id, Name: mctx.Machine.Name, Types: mctx.Machine.Types, Observed: obs, Entries: []manifestEntry{}, Roots: []manifest.Root{}, Tasks: []string{}}
	if mm.Types == nil {
		mm.Types = []model.TypeName{}
	}
	paths := make([]model.SourcePath, 0, len(m.snap.Tree))
	for p := range m.snap.Tree {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return paths[i] < paths[j] })
	plan, err := m.snap.Manifest.Resolve(mctx, paths, snapVocab(m.snap))
	if err != nil {
		mm.Error = err.Error()
		return mm
	}
	targets := make([]model.Target, 0, len(plan.Targets))
	for t := range plan.Targets {
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	for _, t := range targets {
		r := plan.Targets[t]
		e := r.Entry
		exec := m.snap.Tree[r.Source].Mode&0o111 != 0
		me := manifestEntry{
			Target: t, Source: r.Source, Index: r.Index, When: e.When, WhenExpanded: e.When,
			Mode: fmt.Sprintf("%04o", uint32(r.FileMode(exec))), Enclave: e.Enclave, Scope: e.Scope(),
			Merge: string(e.Merge), Template: e.Template, Review: e.Review, Unit: r.Unit,
		}
		if x := plan.When(r.Index); x != nil && e.When != "" {
			me.WhenExpanded = cond.Expand(x)
		}
		if me.Merge == "" {
			me.Merge = string(manifest.MergeText)
		}
		if e.Format != manifest.FormatWhole || len(e.Keep)+len(e.Drop)+len(e.Volatile)+len(e.Seal) > 0 || e.Regions {
			me.Rules = &rulesSummary{Format: e.Format, Keep: e.Keep, Drop: e.Drop, Volatile: e.Volatile, Seal: e.Seal, Regions: e.Regions}
		}
		mm.Entries = append(mm.Entries, me)
	}
	mm.Roots = append(mm.Roots, plan.Roots...)
	for name := range plan.Tasks {
		mm.Tasks = append(mm.Tasks, name)
	}
	sort.Strings(mm.Tasks)
	return mm
}

type evalQuery struct {
	Schema    int             `json:"schema"`
	Machine   model.MachineID `json:"machine"`
	Name      string          `json:"name"`
	Condition string          `json:"condition"`
	Expanded  string          `json:"expanded"`
	Names     []string        `json:"names"`
	Result    bool            `json:"result"`
	Observed  string          `json:"observed"`
	// Unavailable lists the collectors the condition reads that this query
	// could not see: another machine's collectors that were not published
	// plain. Their observed: terms evaluate to false.
	Unavailable []string `json:"unavailable"`
	Note        string   `json:"note,omitempty"`
}

func (a *app) cmdEval(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := openLoaded(ctx)
	if err != nil {
		return notInit(err), err
	}
	ids, err := pickMachines(cmd, m)
	if err != nil {
		return result{}, err
	}
	x, err := cond.Parse(args[0], snapVocab(m.snap))
	if err != nil {
		return result{}, usagef("%v", err)
	}
	var pub map[model.MachineID]model.Status
	if ids[0] != m.local.Machine {
		pub = statuses(ctx, m)
	}
	mctx, obs := machineCtx(m, pub, ids[0])
	q := evalQuery{
		Schema: EvalQuerySchema, Machine: ids[0], Name: mctx.Machine.Name, Condition: args[0],
		Expanded: cond.Expand(x), Names: cond.Names(x), Result: x.Eval(mctx), Observed: obs, Unavailable: []string{},
	}
	if q.Names == nil {
		q.Names = []string{}
	}
	if obs != observedLocal {
		for _, c := range cond.Collectors(x) {
			if _, ok := mctx.Observed[c]; !ok {
				q.Unavailable = append(q.Unavailable, c)
			}
		}
		if len(q.Unavailable) > 0 {
			q.Note = "observed facts of another machine are visible only when its collector publishes plain; " +
				strings.Join(q.Unavailable, ", ") + " read as false here"
		}
	}
	text := fmt.Sprintf("%v  (%s on %s)", q.Result, q.Expanded, q.Name)
	if q.Note != "" {
		text += "\n" + q.Note
	}
	return result{data: q, text: text}, nil
}
