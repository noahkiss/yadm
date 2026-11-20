package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/cond"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
)

// Hook events and their exit codes. A hook never fails an agent's turn
// because yadm broke: every internal error exits HookError, which harnesses
// treat as non-blocking.
const (
	HookPostEdit     = "post-edit"
	HookStop         = "stop"
	HookSessionStart = "session-start"

	HookAllow = 0 // nothing to decide; stdout is empty or carries context
	HookError = 1 // the hook failed; the harness goes on
	HookBlock = 2 // a decision is open; stderr says what and how to settle it

	// HookSchema is the version of the hook verdict.
	HookSchema = 1

	// hookTimeout bounds post-edit; stop gets twice as long. A remote that
	// does not answer in time leaves the commit local for the next sync.
	hookTimeout = 45 * time.Second
)

// Verdict decisions.
const (
	DecisionAllow = "allow"
	DecisionBlock = "block"
	DecisionAsk   = "ask"
)

// HookInput is what a harness writes on the hook's stdin: the hook envelope
// docs/hooks.md documents, plus optional normalized fields any harness glue
// may set.
// Unknown fields are ignored.
type HookInput struct {
	HookEventName  string          `json:"hook_event_name"`
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path,omitempty"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	ToolName       string          `json:"tool_name,omitempty"`
	ToolInput      json.RawMessage `json:"tool_input,omitempty"`
	ToolResponse   json.RawMessage `json:"tool_response,omitempty"`
	ToolUseID      string          `json:"tool_use_id,omitempty"`
	StopHookActive bool            `json:"stop_hook_active,omitempty"`
	AgentID        string          `json:"agent_id,omitempty"`
	AgentType      string          `json:"agent_type,omitempty"`
	Source         string          `json:"source,omitempty"` // session-start: startup, resume, clear, compact

	// Normalized fields. Action is one of shell, file_read, file_write,
	// file_edit, web_fetch, web_search, mcp_call, agent_spawn. Harness is
	// opaque: it is echoed back and never changes behaviour. Intent is a
	// short reason for the edit, used as the commit subject.
	Action  string `json:"action,omitempty"`
	Harness string `json:"harness,omitempty"`
	Intent  string `json:"intent,omitempty"`
}

// Verdict is the hook's one JSON object on stdout.
type Verdict struct {
	Schema       int             `json:"schema"`
	Event        string          `json:"event"`
	Decision     string          `json:"decision"` // allow, block or ask
	Reason       string          `json:"reason,omitempty"`
	Context      string          `json:"context,omitempty"`
	UpdatedInput json.RawMessage `json:"updated_input,omitempty"` // a rewritten tool input; yadm sets none today
	Harness      string          `json:"harness,omitempty"`
	Packets      []Packet        `json:"packets,omitempty"`
}

// Packet is one decision for the agent: what happened, how big it is, which
// machines it reaches, a proposed fix and the options with their commands.
type Packet struct {
	ID         string           `json:"id"` // the hold id; `yadm defer <id>` settles it for now
	Kind       string           `json:"kind"`
	Target     model.Target     `json:"target"`
	Scope      model.Scope      `json:"scope"`
	What       string           `json:"what"`
	Diff       *DiffSummary     `json:"diff,omitempty"`
	Reaches    *Reach           `json:"reaches,omitempty"`
	Neighbours []Neighbour      `json:"neighbours,omitempty"`
	Suggested  []model.TypeName `json:"suggested_types,omitempty"`
	Proposed   string           `json:"proposed"`
	Inspect    string           `json:"inspect"`          // a read-only command that shows the details
	Source     model.SourcePath `json:"source,omitempty"` // rendered_edit: the template
	Patch      string           `json:"patch,omitempty"`  // rendered_edit on a shared template only
	Options    []Option         `json:"options"`
}

// DiffSummary counts changed lines between the source and the target. It
// never carries content, so it is safe for enclave files.
type DiffSummary struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
}

// Reach is who receives a target.
type Reach struct {
	When     string            `json:"when"`
	Enclave  model.EnclaveName `json:"enclave,omitempty"`
	Machines []string          `json:"machines"` // names, else ids
	Types    []model.TypeName  `json:"types"`
}

// Neighbour is a managed target in the same directory as a new file.
type Neighbour struct {
	Target  model.Target      `json:"target"`
	When    string            `json:"when,omitempty"`
	Enclave model.EnclaveName `json:"enclave,omitempty"`
}

// Option is one way to settle a packet.
type Option struct {
	Label       string `json:"label"`
	Consequence string `json:"consequence"`
	Command     string `json:"command"`
}

func (a *app) registerHooks(root *cobra.Command) {
	h := &cobra.Command{
		Use:   "hook <event>",
		Short: "Agent harness hook: post-edit, stop or session-start; reads harness JSON on stdin",
		Args:  cobra.ArbitraryArgs,
	}
	h.Flags().String("format", "json", "json: one verdict object on stdout; text: the reason or context as plain text")
	h.RunE = func(cmd *cobra.Command, args []string) error {
		a.emitted = true
		a.code = a.runHook(cmd, args)
		a.hookRan = true
		return nil
	}
	root.AddCommand(h)

	d := a.leaf(root, "defer <hold-id>", "Move an open decision to the review queue so an agent session can end", a.cmdDefer)
	d.Args = cobra.ExactArgs(1)
	d.Flags().String("reason", "", "required: why the decision waits")
	d.Flags().String("session", "", "the harness session that defers it (default $YADM_SESSION)")
}

// runHook runs one hook event and returns its exit code.
func (a *app) runHook(cmd *cobra.Command, args []string) int {
	format, _ := cmd.Flags().GetString("format")
	fail := func(err error) int {
		fmt.Fprintf(a.stderr, "yadm hook: %v\n", err)
		return HookError
	}
	if len(args) != 1 {
		return fail(fmt.Errorf("want one event: %s, %s or %s", HookPostEdit, HookStop, HookSessionStart))
	}
	if format != "json" && format != "text" {
		return fail(fmt.Errorf("--format %q: want json or text", format))
	}
	in, err := readHookInput(hooks.stdin())
	if err != nil {
		return fail(err)
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	var v Verdict
	switch args[0] {
	case HookPostEdit:
		v, err = a.hookPostEdit(ctx, in)
	case HookStop:
		v, err = a.hookStop(ctx, in)
	case HookSessionStart:
		v, err = a.hookSessionStart(ctx, in)
	default:
		return fail(fmt.Errorf("unknown event %q: want %s, %s or %s", args[0], HookPostEdit, HookStop, HookSessionStart))
	}
	if err != nil {
		if errors.Is(err, errNotInitialized) {
			return HookAllow // not set up here: nothing to do
		}
		return fail(err)
	}
	v.Schema, v.Event, v.Harness = HookSchema, args[0], in.Harness
	if v.Decision == "" {
		v.Decision = DecisionAllow
	}
	if v.Decision == DecisionAllow && v.Context == "" && v.Reason == "" {
		return HookAllow // silence on clean
	}
	if format == "text" {
		text := v.Reason
		if v.Decision == DecisionAllow {
			text = v.Context
		}
		if v.Decision != DecisionBlock {
			fmt.Fprintln(a.stdout, strings.TrimRight(text, "\n"))
		}
	} else {
		enc := json.NewEncoder(a.stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(v)
	}
	if v.Decision == DecisionBlock {
		fmt.Fprintln(a.stderr, strings.TrimRight(v.Reason, "\n"))
		return HookBlock
	}
	return HookAllow
}

func readHookInput(r io.Reader) (HookInput, error) {
	var in HookInput
	b, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return in, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return in, nil
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return in, fmt.Errorf("stdin is not a hook JSON object: %w", err)
	}
	return in, nil
}

// editedPath returns the file a tool call wrote: tool_input's file_path,
// notebook_path or path. A shell command names no path; the scan finds what
// it changed.
func editedPath(in HookInput) string {
	switch in.Action {
	case "", "file_write", "file_edit":
	default:
		return ""
	}
	var ti struct {
		FilePath     string `json:"file_path"`
		NotebookPath string `json:"notebook_path"`
		Path         string `json:"path"`
	}
	if len(in.ToolInput) == 0 || json.Unmarshal(in.ToolInput, &ti) != nil {
		return ""
	}
	p := ti.FilePath
	if p == "" {
		p = ti.NotebookPath
	}
	if p == "" {
		p = ti.Path
	}
	if p != "" && !filepath.IsAbs(p) && in.Cwd != "" {
		p = filepath.Join(in.Cwd, p)
	}
	return p
}

// ---- session records ----

// sessionRecord is one line of a session's record file.
type sessionRecord struct {
	At     time.Time    `json:"at"`
	Target model.Target `json:"target"`
	Agent  string       `json:"agent,omitempty"`
	Tool   string       `json:"tool,omitempty"`
}

func sessionFile(stateDir, session string) string {
	h := sha256.Sum256([]byte(session))
	return filepath.Join(stateDir, "hooks", "sessions", hex.EncodeToString(h[:12])+".jsonl")
}

// recordEdit appends one record. One small append per edit, so parallel
// hooks of one session never lose each other's lines.
func recordEdit(stateDir, session string, r sessionRecord) error {
	if session == "" {
		return nil
	}
	p := sessionFile(stateDir, session)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// sessionTargets lists the targets a session (or one of its agents) edited.
func sessionTargets(stateDir, session, agent string) []model.Target {
	b, err := os.ReadFile(sessionFile(stateDir, session))
	if err != nil {
		return nil
	}
	seen := map[model.Target]bool{}
	var out []model.Target
	for _, l := range strings.Split(string(b), "\n") {
		var r sessionRecord
		if l == "" || json.Unmarshal([]byte(l), &r) != nil || r.Target == "" {
			continue
		}
		if agent != "" && r.Agent != agent {
			continue
		}
		if !seen[r.Target] {
			seen[r.Target] = true
			out = append(out, r.Target)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---- deferred decisions ----

// DeferredFile holds the decisions agents moved to the review queue.
const DeferredFile = "deferred.json"

// Deferred is one decision moved to the review queue.
type Deferred struct {
	ID      string           `json:"id"`
	Target  model.Target     `json:"target,omitempty"`
	Reason  model.HoldReason `json:"reason"`
	Why     string           `json:"why"`
	Session string           `json:"session,omitempty"`
	At      time.Time        `json:"at"`
}

func loadDeferred(stateDir string) map[string]Deferred {
	out := map[string]Deferred{}
	if b, err := os.ReadFile(filepath.Join(stateDir, DeferredFile)); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func saveDeferred(stateDir string, d map[string]Deferred) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	p := filepath.Join(stateDir, DeferredFile)
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// openDeferred returns the deferred decisions whose holds are still open,
// and drops the rest from the file.
func openDeferred(stateDir string, holds []model.Hold) []Deferred {
	d := loadDeferred(stateDir)
	open := map[string]bool{}
	for _, h := range withHoldNext(holds) {
		open[h.ID] = true
	}
	out := []Deferred{}
	changed := false
	for id, x := range d {
		if !open[id] {
			delete(d, id)
			changed = true
			continue
		}
		out = append(out, x)
	}
	if changed {
		_ = saveDeferred(stateDir, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out
}

func (a *app) cmdDefer(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	why, _ := cmd.Flags().GetString("reason")
	session, _ := cmd.Flags().GetString("session")
	if strings.TrimSpace(why) == "" {
		return result{}, usagef("--reason is required: say why the decision waits")
	}
	if session == "" {
		session = os.Getenv("YADM_SESSION")
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
	d := loadDeferred(m.paths.State)
	x := Deferred{ID: h.ID, Target: h.Target, Reason: h.Reason, Why: strings.TrimSpace(why), Session: session, At: hooks.now().UTC()}
	d[h.ID] = x
	if err := saveDeferred(m.paths.State, d); err != nil {
		return result{}, err
	}
	return result{data: x, next: []string{"yadm review list"}, text: "deferred " + h.ID[:min(12, len(h.ID))] + " to the review queue"}, nil
}

// ---- events ----

func (a *app) hookPostEdit(ctx context.Context, in HookInput) (Verdict, error) {
	p := editedPath(in)
	if p == "" {
		return Verdict{}, nil
	}
	m, err := open(ctx)
	if err != nil {
		return Verdict{}, err
	}
	t, err := target(m.home, p)
	if err != nil {
		return Verdict{}, nil // not under $HOME: not ours
	}
	if under(p, m.paths.Source) || under(p, m.paths.State) {
		return Verdict{}, nil // the tool's own directories
	}
	if err := recordEdit(m.paths.State, in.SessionID, sessionRecord{At: hooks.now().UTC(), Target: t, Agent: in.AgentID, Tool: in.ToolName}); err != nil {
		return Verdict{}, err
	}
	snap, err := m.load(ctx)
	if err != nil {
		return Verdict{}, err
	}
	if !managedOrRooted(snap, t) || m.eng.Ignored(t) {
		return Verdict{}, nil // ignored on purpose: only a named commit tracks it
	}
	ctx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()
	rep, _, err := m.hookCommit(ctx, a.version, sync.CommitOptions{
		Paths: []model.Target{t}, Unattended: true, Trigger: sync.TriggerHook,
		Session: in.SessionID, Tool: in.ToolName, Message: in.Intent, Push: true,
	}, hooks.hookWait)
	if errors.Is(err, sync.ErrLocked) {
		return Verdict{}, nil // a sync is running; the path is recorded for stop
	}
	if err != nil {
		return Verdict{}, err
	}
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return Verdict{}, err
	}
	hs = append(hs, rep.Holds...)
	packets := m.packets(ctx, decisionsFor(hs, []model.Target{t}, loadDeferred(m.paths.State)))
	if len(packets) == 0 {
		return Verdict{}, nil
	}
	return Verdict{Decision: DecisionBlock, Reason: renderPackets("this edit needs a decision", packets), Packets: packets}, nil
}

func (a *app) hookStop(ctx context.Context, in HookInput) (Verdict, error) {
	agent := ""
	if in.HookEventName == "SubagentStop" {
		agent = in.AgentID
	}
	p, err := DefaultPaths()
	if err != nil {
		return Verdict{}, err
	}
	ts := sessionTargets(p.State, in.SessionID, agent)
	if len(ts) == 0 {
		return Verdict{}, nil // this session edited nothing yadm saw
	}
	m, err := open(ctx)
	if err != nil {
		return Verdict{}, err
	}
	_, _ = m.load(ctx)
	kept := ts[:0:0]
	for _, t := range ts {
		if !m.eng.Ignored(t) {
			kept = append(kept, t)
		}
	}
	if ts = kept; len(ts) == 0 {
		return Verdict{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*hookTimeout)
	defer cancel()
	_, _, err = m.hookCommit(ctx, a.version, sync.CommitOptions{
		Paths: ts, Unattended: true, Trigger: sync.TriggerStop, Session: in.SessionID, Push: true,
	}, hooks.hookWait)
	if errors.Is(err, sync.ErrLocked) {
		return Verdict{Context: "yadm: a sync holds the lock; the timer commits this session's edits"}, nil
	}
	if err != nil {
		return Verdict{}, err
	}
	hs, err := m.eng.Holds(ctx)
	if err != nil {
		return Verdict{}, err
	}
	packets := m.packets(ctx, decisionsFor(hs, ts, loadDeferred(m.paths.State)))
	if len(packets) == 0 {
		return Verdict{}, nil
	}
	head := fmt.Sprintf("%d decision(s) from this session are open; settle each one, or move it to the review queue with yadm defer", len(packets))
	return Verdict{Decision: DecisionBlock, Reason: renderPackets(head, packets), Packets: packets}, nil
}

func (a *app) hookSessionStart(ctx context.Context, in HookInput) (Verdict, error) {
	m, err := open(ctx)
	if err != nil {
		return Verdict{}, err
	}
	_, _ = m.load(ctx)
	var lines []string
	sctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	rep, err := m.syncerWait(a.version, hooks.hookWait).Run(sctx, sync.Options{Quick: true, Push: true, MaxRetries: 1})
	cancel()
	switch {
	case errors.Is(err, sync.ErrLocked):
		lines = append(lines, "yadm: a sync is running; the source may be a moment behind")
	case err != nil:
		lines = append(lines, "yadm: sync failed: "+oneLine(err.Error()))
	case !rep.Skipped && rep.Applied != "":
		lines = append(lines, fmt.Sprintf("yadm: synced to %s (%s)", short(rep.Applied), rep.Reason))
	}
	m.snap = nil
	snap, _ := m.load(ctx)
	hs, _ := m.eng.Holds(ctx)
	deferred := openDeferred(m.paths.State, hs)
	skip := map[string]bool{}
	for _, d := range deferred {
		skip[d.ID] = true
	}
	rel := ""
	if in.Cwd != "" {
		if t, err := target(m.home, in.Cwd); err == nil {
			rel = string(t)
		}
	}
	var here, other []model.Hold
	for _, h := range withHoldNext(hs) {
		if skip[h.ID] || h.Reason == model.HoldDrifted {
			continue
		}
		if rel != "" && (string(h.Target) == rel || strings.HasPrefix(string(h.Target), rel+"/") || strings.HasPrefix(rel, string(h.Target)+"/")) {
			here = append(here, h)
		} else {
			other = append(other, h)
		}
	}
	for i, h := range here {
		if i == 3 {
			lines = append(lines, fmt.Sprintf("  and %d more here: yadm hold list", len(here)-3))
			break
		}
		lines = append(lines, fmt.Sprintf("yadm: held %s %s (%s): yadm hold show %s", h.Reason, h.Target+model.Target(h.Task), oneLine(h.Detail), h.ID[:12]))
	}
	if n := len(other); n > 0 {
		lines = append(lines, fmt.Sprintf("yadm: %d open decision(s) elsewhere: yadm hold list", n))
	}
	if n := len(deferred); n > 0 {
		lines = append(lines, fmt.Sprintf("yadm: %d deferred decision(s) wait in the review queue: yadm review list", n))
	}
	if n := m.unreviewedAuto(ctx, snap); n > 0 {
		lines = append(lines, fmt.Sprintf("yadm: %d auto-commit(s) not reviewed: yadm review list", n))
	}
	if s := m.fleetDrift(ctx, snap); s != "" {
		lines = append(lines, s)
	}
	if len(lines) > 10 {
		lines = append(lines[:9], "yadm: more in yadm status")
	}
	return Verdict{Context: strings.Join(lines, "\n")}, nil
}

// ---- helpers ----

// hookCommit commits through sync.Commit with a bounded lock wait.
// A failure after the commit step (fetch, replay, apply, push: an
// unreachable remote, for one) comes back as pushErr: the commit stands
// and the next sync pushes it.
func (m *machineEnv) hookCommit(ctx context.Context, version string, opts sync.CommitOptions, wait time.Duration) (sync.Report, error, error) {
	rep, err := m.syncerWait(version, wait).Commit(ctx, opts)
	var ee *sync.ExchangeError
	if errors.As(err, &ee) {
		return rep, ee.Err, nil
	}
	return rep, nil, err
}

// syncerWait is syncer with its own lock wait.
func (m *machineEnv) syncerWait(version string, wait time.Duration) *sync.Syncer {
	s := m.syncer(version)
	s.Lock = m.lock(wait)
	return s
}

func under(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// managedOrRooted reports whether t is managed here or inside an owned root.
func managedOrRooted(snap *apply.Snapshot, t model.Target) bool {
	if snap == nil || snap.Plan == nil {
		return false
	}
	if _, ok := snap.Plan.Targets[t]; ok {
		return true
	}
	return snap.Plan.Root(t) != nil
}

// decisionsFor returns the open holds on targets (or on the owned roots that
// contain them) that are not deferred. A plain drift is pending work, not a
// decision; the timer commits it.
func decisionsFor(hs []model.Hold, targets []model.Target, deferred map[string]Deferred) []model.Hold {
	seen := map[string]bool{}
	var out []model.Hold
	for _, h := range withHoldNext(hs) {
		if h.Target == "" || h.Reason == model.HoldDrifted || seen[h.ID] {
			continue
		}
		if _, ok := deferred[h.ID]; ok {
			continue
		}
		for _, t := range targets {
			if h.Target == t || strings.HasPrefix(string(t), string(h.Target)+"/") {
				seen[h.ID] = true
				out = append(out, h)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	return out
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:160] + "..."
	}
	return s
}

// packets builds one decision packet per hold.
func (m *machineEnv) packets(ctx context.Context, hs []model.Hold) []Packet {
	out := []Packet{}
	for _, h := range hs {
		out = append(out, m.packet(ctx, h))
	}
	return out
}

func deferOption(id string) Option {
	return Option{Label: "decide later", Consequence: "the file stays held and uncommitted; the decision moves to the review queue and the session can end",
		Command: "yadm defer " + id + " --reason \"<why it waits>\""}
}

func (m *machineEnv) packet(ctx context.Context, h model.Hold) Packet {
	snap := m.snap
	p := Packet{ID: h.ID, Kind: string(h.Reason), Target: h.Target, Scope: h.Scope, What: h.Detail}
	managed := false
	if snap != nil && snap.Plan != nil {
		if res, ok := snap.Plan.Targets[h.Target]; ok {
			managed = true
			p.Reaches = reach(snap, res.Entry.When, res.Entry.Enclave)
		} else if root := snap.Plan.Root(h.Target); root != nil {
			p.Reaches = reach(snap, root.When, root.Enclave)
		}
	}
	if managed && h.Reason != model.HoldRootUntrusted {
		p.Diff = m.diffSummary(ctx, h.Target)
	}
	p.Inspect = "yadm hold show " + h.ID
	switch {
	case h.Reason == model.HoldProtected && !managed:
		p.Kind = "new_file"
		p.What = "new file " + string(h.Target) + " in an owned root"
		p.Neighbours, p.Suggested = neighbours(snap, h.Target)
		p.Proposed = "commit it if every machine the root reaches should get it"
		if len(p.Suggested) > 0 {
			p.Proposed += "; its neighbours go to types " + joinTypes(p.Suggested) + ", so if it belongs only there, track it for those types"
		}
		if strings.Contains(h.Detail, "before its owned root") {
			p.Proposed = "it was here before the root was allowed: track it, or ignore it if it is machine-local"
		}
		p.Options = []Option{
			{Label: "share it", Consequence: "commits and pushes " + string(h.Target) + reachText(p.Reaches), Command: "yadm commit " + model.ShellQuote(string(h.Target))},
		}
		if len(p.Suggested) > 0 {
			types := make([]string, len(p.Suggested))
			for i, t := range p.Suggested {
				types[i] = string(t)
			}
			p.Options = append(p.Options, Option{Label: "track it for its neighbours' types",
				Consequence: "adds a manifest entry with when type:" + strings.Join(types, " | type:") + " and commits the file; only those machines get it",
				Command:     "yadm retag " + model.ShellQuote(string(h.Target)) + " " + model.ShellQuote(strings.Join(types, ",")) + enclaveFlag(p.Reaches)})
		}
		p.Options = append(p.Options,
			Option{Label: "ignore it", Consequence: "leaves the file untracked on this machine; it stops showing (yadm commit <path> tracks it later)", Command: "yadm hold ignore " + h.ID},
			deferOption(h.ID))
	case h.Reason == model.HoldProtected:
		p.Proposed = "commit it by name if the change is intended"
		p.Options = []Option{
			{Label: "commit it", Consequence: "commits and pushes the protected change" + reachText(p.Reaches), Command: "yadm commit " + model.ShellQuote(string(h.Target))},
			deferOption(h.ID),
		}
	case h.Reason == model.HoldRenderedEdit:
		p.Source, p.Patch = h.Source, h.Patch
		p.Proposed = "the edit touched rendered output; carry it into the template " + string(h.Source)
		if h.Patch != "" {
			p.Proposed += " (the patch below is against the " + h.PatchOf + ")"
		}
		p.Options = []Option{
			{Label: "drop the edit", Consequence: "re-renders the template over the target; the hand edit is lost (backed up)", Command: "yadm hold resolve " + h.ID + " --take source"},
			deferOption(h.ID),
		}
	case h.Reason == model.HoldCheckFailed:
		p.Proposed = "fix what the commit gate reported and save the file again; the next edit or stop retries"
		p.Options = []Option{
			{Label: "retry", Consequence: "runs the gate again on the current file and commits it if the gate passes", Command: "yadm commit " + model.ShellQuote(string(h.Target))},
			deferOption(h.ID),
		}
	case h.Reason == model.HoldSealGuard:
		p.Proposed = "put the sealed key, value or region markers back as they were, then save again; a capture never commits a sealed part as plaintext"
		p.Options = []Option{
			{Label: "restore from the source", Consequence: "rewrites the target from the source; the edit is lost (backed up)", Command: "yadm hold resolve " + h.ID + " --take source"},
			deferOption(h.ID),
		}
	case h.Reason == model.HoldConflict:
		p.Proposed = "merge both sides by hand and resolve with the merged file, or keep one side"
		p.Options = []Option{
			{Label: "keep the incoming change", Consequence: "rewrites the target from the source; this machine's edit is lost (backed up)", Command: "yadm hold resolve " + h.ID + " --take source"},
			{Label: "keep this edit", Consequence: "commits this machine's file over the incoming change and pushes it" + reachText(p.Reaches), Command: "yadm hold resolve " + h.ID + " --take target"},
			{Label: "use a merged file", Consequence: "writes the merged file to the target, commits and pushes it", Command: "yadm hold resolve " + h.ID + " --take <merged-file>"},
			deferOption(h.ID),
		}
	default:
		p.Proposed = "see the hold's suggested commands"
		for _, n := range h.Next {
			p.Options = append(p.Options, Option{Label: "suggested", Consequence: "settles the " + string(h.Reason) + " hold", Command: n})
		}
		p.Options = append(p.Options, deferOption(h.ID))
	}
	if p.What == "" {
		p.What = string(h.Reason)
	}
	return p
}

// enclaveFlag keeps a file of an enclave root sealed when it is tracked.
func enclaveFlag(r *Reach) string {
	if r == nil || r.Enclave == "" {
		return ""
	}
	return " --enclave " + model.ShellQuote(string(r.Enclave))
}

// reach evaluates a `when` against every fleet machine.
func reach(snap *apply.Snapshot, when string, enc model.EnclaveName) *Reach {
	r := &Reach{When: when, Enclave: enc, Machines: []string{}, Types: []model.TypeName{}}
	if snap == nil || snap.Fleet == nil {
		return r
	}
	expr := cond.Always()
	if when != "" {
		x, err := cond.Parse(when, snapVocab(snap))
		if err != nil {
			return r
		}
		expr = x
	}
	types := map[model.TypeName]bool{}
	ids := make([]string, 0, len(snap.Fleet.Machines))
	for id := range snap.Fleet.Machines {
		ids = append(ids, string(id))
	}
	sort.Strings(ids)
	for _, id := range ids {
		mc := snap.Fleet.Machines[model.MachineID(id)]
		mc.ID = model.MachineID(id)
		if !expr.Eval(model.Context{Machine: mc}) {
			continue
		}
		name := mc.Name
		if name == "" {
			name = id
		}
		r.Machines = append(r.Machines, name)
		for _, t := range mc.Types {
			types[t] = true
		}
	}
	for t := range types {
		r.Types = append(r.Types, t)
	}
	sort.Slice(r.Types, func(i, j int) bool { return r.Types[i] < r.Types[j] })
	return r
}

func reachText(r *Reach) string {
	if r == nil || len(r.Machines) == 0 {
		return ""
	}
	s := " to " + strings.Join(r.Machines, ", ")
	if r.Enclave != "" {
		s += " (sealed for " + string(r.Enclave) + ")"
	}
	return s
}

// neighbours lists managed targets in t's directory and the types their
// `when` names.
func neighbours(snap *apply.Snapshot, t model.Target) ([]Neighbour, []model.TypeName) {
	if snap == nil || snap.Plan == nil {
		return nil, nil
	}
	dir := path.Dir(string(t))
	var out []Neighbour
	types := map[model.TypeName]bool{}
	for nt, r := range snap.Plan.Targets {
		if path.Dir(string(nt)) != dir || nt == t {
			continue
		}
		out = append(out, Neighbour{Target: nt, When: r.Entry.When, Enclave: r.Entry.Enclave})
		for _, f := range strings.FieldsFunc(r.Entry.When, func(c rune) bool { return strings.ContainsRune(" &|!()", c) }) {
			if ty, ok := strings.CutPrefix(f, "type:"); ok {
				types[model.TypeName(ty)] = true
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Target < out[j].Target })
	if len(out) > 5 {
		out = out[:5]
	}
	var sug []model.TypeName
	for ty := range types {
		sug = append(sug, ty)
	}
	sort.Slice(sug, func(i, j int) bool { return sug[i] < sug[j] })
	return out, sug
}

// diffSummary counts the lines a target changes against its rendered
// source. It reads plaintext in memory and returns counts only.
func (m *machineEnv) diffSummary(ctx context.Context, t model.Target) *DiffSummary {
	if m.snap == nil || m.snap.Plan == nil {
		return nil
	}
	fd := m.diffOne(ctx, t)
	if fd.Skipped != "" {
		return nil
	}
	d := &DiffSummary{}
	for _, l := range strings.Split(fd.Diff, "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			d.Added++
		case strings.HasPrefix(l, "-"):
			d.Removed++
		}
	}
	return d
}

// renderPackets is the text an agent reads on stderr.
func renderPackets(head string, ps []Packet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "yadm: %s.\n", head)
	for i, p := range ps {
		fmt.Fprintf(&b, "\n[%d] %s: %s (scope %s)\n", i+1, p.Kind, p.Target, p.Scope)
		fmt.Fprintf(&b, "    what: %s\n", oneLine(p.What))
		if p.Diff != nil {
			fmt.Fprintf(&b, "    diff: +%d -%d lines against the source\n", p.Diff.Added, p.Diff.Removed)
		}
		if p.Reaches != nil {
			who := "no machine"
			if len(p.Reaches.Machines) > 0 {
				who = strings.Join(p.Reaches.Machines, ", ")
			}
			fmt.Fprintf(&b, "    reaches: %s (types %s)\n", who, joinTypes(p.Reaches.Types))
		}
		if len(p.Suggested) > 0 {
			fmt.Fprintf(&b, "    neighbours go to types: %s\n", joinTypes(p.Suggested))
		}
		fmt.Fprintf(&b, "    proposed: %s\n", p.Proposed)
		fmt.Fprintf(&b, "    inspect: %s\n", p.Inspect)
		if p.Patch != "" {
			fmt.Fprintf(&b, "    patch:\n%s\n", indent(p.Patch, "      "))
		}
		for j, o := range p.Options {
			fmt.Fprintf(&b, "    %c) %s: %s\n       $ %s\n", 'a'+j, o.Label, o.Consequence, o.Command)
		}
	}
	return b.String()
}

func indent(s, pre string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = pre + l
	}
	return strings.Join(lines, "\n")
}

// unreviewedAuto counts tool commits on main past each scope's reviewed ref.
func (m *machineEnv) unreviewedAuto(ctx context.Context, snap *apply.Snapshot) int {
	main, err := m.head(ctx)
	if err != nil || main == "" {
		return 0
	}
	scopes := []model.Scope{model.ScopeShared}
	if snap != nil && snap.Fleet != nil {
		for _, e := range snap.Fleet.Enclaves() {
			scopes = append(scopes, model.Scope(e))
		}
	}
	seen := map[model.CommitID]bool{}
	for _, sc := range scopes {
		rng := string(main)
		// The local reviewed ref only: a fetched one may skip commits.
		if base, _ := m.repo.ResolveRef(ctx, store.RefReviewed(sc)); base != "" {
			rng = string(base) + ".." + string(main)
		}
		cs, err := m.repo.Log(ctx, rng, nil)
		if err != nil {
			continue
		}
		for _, c := range cs {
			if auto := trailerOf(c.Message, store.TrailerAuto); auto != "" && auto != sync.TriggerManual && trailerOf(c.Message, store.TrailerScope) == string(sc) {
				seen[c.ID] = true
			}
		}
	}
	return len(seen)
}

func trailerOf(msg store.Message, key string) string {
	for _, t := range msg.Trailers {
		if t.Key == key {
			return t.Value
		}
	}
	return ""
}

// fleetDrift is one line on machines behind this one or not syncing.
func (m *machineEnv) fleetDrift(ctx context.Context, snap *apply.Snapshot) string {
	if snap == nil || snap.Fleet == nil {
		return ""
	}
	all, err := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	if err != nil {
		return ""
	}
	main, _ := m.head(ctx)
	var behind, stale []string
	for _, r := range fleet.List(snap.Fleet, all, hooks.now()) {
		if r.Machine.ID == m.local.Machine {
			continue
		}
		name := r.Machine.Name
		if name == "" {
			name = string(r.Machine.ID)
		}
		switch {
		case r.Stale:
			stale = append(stale, name)
		case r.Status != nil && main != "" && r.Status.Applied != main:
			behind = append(behind, name)
		}
	}
	var parts []string
	if len(behind) > 0 {
		parts = append(parts, fmt.Sprintf("%d not at this machine's main (%s)", len(behind), strings.Join(behind, ", ")))
	}
	if len(stale) > 0 {
		parts = append(parts, fmt.Sprintf("%d not synced in a day (%s)", len(stale), strings.Join(stale, ", ")))
	}
	if len(parts) == 0 {
		return ""
	}
	return "yadm: fleet: " + strings.Join(parts, "; ") + ": yadm fleet list"
}
