package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/pause"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/sync"
)

// pausePoll is how often `yadm pause` fetches peers' status records while
// it waits for them to confirm.
const pausePoll = 3 * time.Second

// pauseDefaultWait bounds the wait for confirmations when --wait is not given.
const pauseDefaultWait = 2 * time.Minute

const pauseLong = `Pause holds sync on every other machine for a bounded time, so you can
make a change that touches the whole fleet while no peer commits, applies
or pushes half of it.

How it works:
  1. This machine writes a signed pause record (who, why, until when) and
     pushes it. A pause lasts 30m unless --for says otherwise, and never
     more than 4h after it began.
  2. Every other machine sees the record on its next sync. It keeps
     fetching, but stops capturing, committing, applying and pushing. Its
     status record then shows "paused until", which confirms the pause.
     A manual "yadm commit" or "yadm apply" there refuses and says who
     paused the fleet, why, and until when.
  3. This command waits and shows who has confirmed. A machine that sleeps
     does not block you: --wait bounds the wait (default 2m), --no-wait
     skips it. The sleeping machine pauses when it wakes, if the pause is
     still on.
  4. Make the change here and commit it as usual. The machine that started
     the pause is not held.
  5. Every machine resumes by itself at the deadline, by its own clock,
     even offline. To end early, run "yadm resume". To extend, run
     "yadm pause --for <duration>" again on this machine.

Trust: only a member of an enclave can start a pause, and a machine honours
a pause or a resume only when the signer is a member of a key log that
machine has pinned. Any other record is ignored, and "yadm check" reports it.`

// registerPause adds pause and resume.
func (a *app) registerPause(root *cobra.Command) {
	pa := a.leaf(root, "pause", "Hold sync fleet-wide for a bounded time during a global change", a.cmdPause)
	pa.Long = pauseLong
	pa.Args = cobra.NoArgs
	pa.Flags().Duration("for", pause.DefaultFor, "how long the pause lasts (at most 4h after it began); on a pause this machine started, extends it")
	pa.Flags().String("reason", "", "why, shown to every machine the pause holds (plain text: every machine can read it)")
	pa.Flags().Duration("wait", pauseDefaultWait, "how long to wait for other machines to confirm")
	pa.Flags().Bool("no-wait", false, "return as soon as the pause is pushed")
	rs := a.leaf(root, "resume [pause-id]", "Lift a fleet pause before its deadline", a.cmdResume)
	rs.Long = `Resume lifts a fleet pause before its deadline. Any member of an enclave
can resume, not only the machine that paused: the resume record is signed,
and a machine accepts it only from a signer in a key log it has pinned.
Without an id it lifts the pause that holds this machine, or the one this
machine started. Every machine resumes on its next sync. A pause also ends
by itself at its deadline; that needs no resume.`
	rs.Args = cobra.MaximumNArgs(1)
}

// pauseData is the data of pause and resume.
type pauseData struct {
	ID        string          `json:"id"`
	Initiator model.MachineID `json:"initiator"`
	Reason    string          `json:"reason,omitempty"`
	Created   time.Time       `json:"created"`
	Until     time.Time       `json:"until"`
	Requested time.Time       `json:"requested"`
	Clamped   bool            `json:"clamped,omitempty"`
	Extended  bool            `json:"extended,omitempty"`
	Resumed   bool            `json:"resumed,omitempty"`
	Pushed    bool            `json:"pushed"`
	PushError string          `json:"push_error,omitempty"`
	confirmations
}

// confirmations is which peers confirmed a pause in their status records.
type confirmations struct {
	Confirmed []model.MachineID `json:"confirmed"`
	Waiting   []model.MachineID `json:"waiting"`
	Ignored   []peerIgnored     `json:"ignored,omitempty"`
}

type peerIgnored struct {
	Machine model.MachineID `json:"machine"`
	Why     string          `json:"why"`
}

// pauseStatus is the pause part of `yadm status`.
type pauseStatus struct {
	Held    *pause.Active   `json:"held,omitempty"` // another machine's pause holds this one
	Own     *pause.Active   `json:"own,omitempty"`  // a pause this machine started
	Ignored []pause.Ignored `json:"ignored,omitempty"`
	// Confirmations of Own, from peers' status records.
	Confirmations *confirmations `json:"confirmations,omitempty"`
}

// peers are the fleet's other machines, with their display names.
func (m *machineEnv) peers() map[model.MachineID]string {
	out := map[model.MachineID]string{}
	if m.snap == nil || m.snap.Fleet == nil {
		return out
	}
	for id, mc := range m.snap.Fleet.Machines {
		if id == m.local.Machine {
			continue
		}
		name := mc.Name
		if name == "" {
			name = string(id)
		}
		out[id] = name
	}
	return out
}

func (m *machineEnv) names(ids []model.MachineID) string {
	ps := m.peers()
	s := make([]string, len(ids))
	for i, id := range ids {
		if n, ok := ps[id]; ok {
			s[i] = n
		} else {
			s[i] = string(id)
		}
	}
	return strings.Join(s, ", ")
}

// confirm reads peers' status records: who confirmed pause id, who ignored
// it, and who has not answered yet.
func (m *machineEnv) confirm(ctx context.Context, id string) confirmations {
	c := confirmations{Confirmed: []model.MachineID{}, Waiting: []model.MachineID{}}
	all, _ := store.StatusRefs(m.repo, m.local.Machine).ReadAll(ctx)
	now := hooks.now()
	ids := make([]model.MachineID, 0)
	for p := range m.peers() {
		ids = append(ids, p)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, p := range ids {
		st, ok := all[p]
		switch {
		case ok && st.PauseID == id && st.PausedUntil != nil && st.PausedUntil.After(now):
			c.Confirmed = append(c.Confirmed, p)
		case ok && ignoredWhy(st, id) != "":
			c.Ignored = append(c.Ignored, peerIgnored{Machine: p, Why: ignoredWhy(st, id)})
		default:
			c.Waiting = append(c.Waiting, p)
		}
	}
	return c
}

func ignoredWhy(st model.Status, id string) string {
	for _, x := range st.PauseIgnored {
		if x.ID == id {
			return x.Why
		}
	}
	return ""
}

// pauseView evaluates the pause ref without recording anything: status,
// check and the refusals of apply and capture use it.
func (m *machineEnv) pauseView(ctx context.Context) (pause.View, pause.Signers) {
	var signers pause.Signers
	if m.snap != nil {
		signers = pause.TrustedSigners(m.snap.Enclaves, crypt.FilePins(m.paths.State))
	}
	v, _ := pause.Evaluate(ctx, m.repo, m.paths.State, m.local.Machine, signers, hooks.now(), false)
	return v, signers
}

// refuseHeld returns a pause.HeldError when another machine's pause holds
// this one, with the result that names it.
func (m *machineEnv) refuseHeld(ctx context.Context) (result, error) {
	if m.snap == nil {
		_, _ = m.load(ctx)
	}
	v, _ := m.pauseView(ctx)
	if h := v.Holding(m.local.Machine); h != nil {
		return heldResult(*h), m.heldErr(*h)
	}
	return result{}, nil
}

func (m *machineEnv) heldErr(h pause.Active) error {
	e := &pause.HeldError{Active: h, Self: m.local.Machine}
	if m.snap != nil && m.snap.Fleet != nil {
		e.Name = m.snap.Fleet.Machines[h.Initiator].Name
	}
	return e
}

func heldResult(h pause.Active) result {
	return result{details: h, next: []string{"yadm status", "yadm resume"}}
}

// trusted reports whether peers that pin the same key logs as this machine
// would accept its signature.
func trusted(signers pause.Signers, id *crypt.Identity) bool {
	me := id.Member()
	for _, m := range signers[id.Machine] {
		if m.SignKey == me.SignKey {
			return true
		}
	}
	return false
}

func errNoSigner(self model.MachineID) error {
	return fmt.Errorf("%w: %s is not a member of a pinned enclave key log, so no machine would trust its pause or resume; run it on a member (see `yadm enclave list`)", ErrRefused, self)
}

func clock(t time.Time) string { return t.In(time.Local).Format("15:04") }

func span(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Minute {
		return "under 1m"
	}
	s := d.String()
	s = strings.TrimSuffix(s, "0s")
	return strings.TrimSuffix(s, "h0m")
}

func (a *app) cmdPause(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	forD, _ := cmd.Flags().GetDuration("for")
	reason, _ := cmd.Flags().GetString("reason")
	wait, _ := cmd.Flags().GetDuration("wait")
	noWait, _ := cmd.Flags().GetBool("no-wait")
	if forD <= 0 {
		return result{}, usagef("--for must be positive")
	}
	if len(reason) > 200 || model.HasControl(reason) {
		return result{}, usagef("--reason must be one line of at most 200 bytes")
	}
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	if _, err := m.load(ctx); err != nil {
		return result{}, err
	}
	self := m.local.Machine
	if m.id == nil {
		return result{}, fmt.Errorf("%w: this machine has no signing identity", ErrRefused)
	}
	s := m.syncer(a.version)
	_ = s.FetchRefs(ctx) // see the current pauses; offline still writes locally
	v, signers, err := s.EvalPause(ctx)
	if err != nil {
		return lockedResult(err), err
	}
	if h := v.Holding(self); h != nil {
		return heldResult(*h), m.heldErr(*h)
	}
	if !trusted(signers, m.id) {
		return result{next: []string{"yadm enclave list"}}, errNoSigner(self)
	}
	now := hooks.now().UTC().Truncate(time.Second)
	var own *pause.Active
	for i := range v.Active {
		if v.Active[i].Initiator == self {
			own = &v.Active[i]
		}
	}
	rec := pause.Record{Op: pause.OpPause, Initiator: self, Reason: reason, Created: now, Deadline: now.Add(forD)}
	extended := own != nil
	if own != nil {
		rec.ID, rec.Created, rec.Deadline = own.ID, own.Created, own.Requested
		if reason == "" {
			rec.Reason = own.Reason
		}
		if want := now.Add(forD); want.After(rec.Deadline) {
			rec.Deadline = want
		}
	} else if rec.ID, err = pause.NewID(); err != nil {
		return result{}, err
	}
	asked := now.Add(forD)
	if capAt := rec.Created.Add(pause.MaxSpan); rec.Deadline.After(capAt) {
		rec.Deadline = capAt
	}
	d := pauseData{ID: rec.ID, Initiator: self, Reason: rec.Reason, Created: rec.Created, Extended: extended}
	if own == nil || rec.Deadline.After(own.Requested) || rec.Reason != own.Reason {
		signed, err := pause.Sign(rec, m.id)
		if err != nil {
			return result{}, err
		}
		d.Pushed, err = s.PublishPause(ctx, []pause.Record{signed})
		if err != nil {
			if errors.Is(err, sync.ErrLocked) {
				return lockedResult(err), err
			}
			d.PushError = err.Error()
		}
	} else {
		d.Pushed = true // nothing new to say; the record already went out
	}
	if v, _, err = s.EvalPause(ctx); err != nil {
		return lockedResult(err), err
	}
	act := v.Find(rec.ID)
	if act == nil {
		return result{}, fmt.Errorf("pause %s did not take effect on this machine", rec.ID)
	}
	d.Until, d.Requested, d.Clamped = act.Until, act.Requested, act.Clamped || asked.After(act.Until)
	if d.Pushed && d.PushError == "" && !(own != nil && !rec.Deadline.After(own.Requested)) {
		s.NudgePeers(ctx)
	}

	d.confirmations = m.confirm(ctx, rec.ID)
	if d.PushError == "" && !noWait && wait > 0 {
		end := hooks.now().Add(wait)
		last := ""
		for len(d.Waiting) > 0 {
			if !a.json {
				line := fmt.Sprintf("waiting… %d/%d confirmed (%s not yet)", len(d.Confirmed), len(d.Confirmed)+len(d.Waiting)+len(d.Ignored), m.names(d.Waiting))
				if line != last {
					fmt.Fprintln(a.stderr, line)
					last = line
				}
			}
			if !hooks.now().Before(end) {
				break
			}
			if err := hooks.sleep(ctx, pausePoll); err != nil {
				break
			}
			_ = s.FetchRefs(ctx)
			d.confirmations = m.confirm(ctx, rec.ID)
		}
	}

	var b strings.Builder
	left := span(d.Until.Sub(hooks.now()))
	verb := "paused"
	if extended {
		verb = "extended the pause"
	}
	switch {
	case d.PushError != "":
		fmt.Fprintf(&b, "%s until %s (%s) on this machine only: the push failed (%s); the next sync pushes it", verb, clock(d.Until), left, d.PushError)
	case len(d.Waiting) == 0 && len(d.Ignored) == 0:
		fmt.Fprintf(&b, "%s fleet-wide until %s (%s); resumes automatically", verb, clock(d.Until), left)
	default:
		total := len(d.Confirmed) + len(d.Waiting) + len(d.Ignored)
		fmt.Fprintf(&b, "%s until %s (%s); %d/%d confirmed", verb, clock(d.Until), left, len(d.Confirmed), total)
		if len(d.Waiting) > 0 {
			fmt.Fprintf(&b, "; %s not yet (each pauses on its next sync)", m.names(d.Waiting))
		}
		b.WriteString("; resumes automatically")
	}
	if d.Clamped {
		b.WriteString("\ncapped at 4h after the pause began")
	}
	for _, x := range d.Ignored {
		fmt.Fprintf(&b, "\n%s ignored it: %s", m.names([]model.MachineID{x.Machine}), x.Why)
	}
	next := []string{"yadm resume"}
	if d.PushError != "" {
		next = append([]string{"yadm sync"}, next...)
	}
	return result{data: d, text: b.String(), next: next}, nil
}

func (a *app) cmdResume(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	if _, err := m.load(ctx); err != nil {
		return result{}, err
	}
	self := m.local.Machine
	if m.id == nil {
		return result{}, fmt.Errorf("%w: this machine has no signing identity", ErrRefused)
	}
	s := m.syncer(a.version)
	_ = s.FetchRefs(ctx)
	v, signers, err := s.EvalPause(ctx)
	if err != nil {
		return lockedResult(err), err
	}
	var act *pause.Active
	switch {
	case len(args) == 1:
		if act = v.Find(args[0]); act == nil {
			return result{next: []string{"yadm status"}}, usagef("no active pause has id %q", args[0])
		}
	case v.Holding(self) != nil:
		act = v.Holding(self)
	case len(v.Active) > 0:
		act = &v.Active[0]
	}
	if act == nil {
		return result{data: map[string]any{"resumed": false}, text: "no pause holds the fleet"}, nil
	}
	if !trusted(signers, m.id) {
		return result{next: []string{"yadm enclave list"}}, errNoSigner(self)
	}
	rec, err := pause.Sign(pause.Record{Op: pause.OpResume, ID: act.ID, Initiator: act.Initiator, Reason: act.Reason, Created: act.Created, Deadline: act.Requested}, m.id)
	if err != nil {
		return result{}, err
	}
	d := pauseData{ID: act.ID, Initiator: act.Initiator, Reason: act.Reason, Created: act.Created, Until: act.Until, Requested: act.Requested, Resumed: true}
	d.Pushed, err = s.PublishPause(ctx, []pause.Record{rec})
	if err != nil {
		if errors.Is(err, sync.ErrLocked) {
			return lockedResult(err), err
		}
		d.PushError = err.Error()
	}
	if _, _, err := s.EvalPause(ctx); err != nil {
		return lockedResult(err), err
	}
	if d.Pushed {
		s.NudgePeers(ctx)
	}
	d.confirmations = confirmations{Confirmed: []model.MachineID{}, Waiting: []model.MachineID{}}
	text := fmt.Sprintf("resumed %s: every machine resumes on its next sync", act.ID)
	if d.PushError != "" {
		text = fmt.Sprintf("resumed %s on this machine only: the push failed (%s); the next sync pushes it", act.ID, d.PushError)
	}
	return result{data: d, text: text, next: []string{"yadm sync"}}, nil
}

// statusPause fills the pause part of `yadm status` and its text lines.
func (m *machineEnv) statusPause(ctx context.Context) (*pauseStatus, string) {
	v, _ := m.pauseView(ctx)
	ps := &pauseStatus{Held: v.Holding(m.local.Machine), Ignored: v.Ignored}
	for i := range v.Active {
		if v.Active[i].Initiator == m.local.Machine {
			ps.Own = &v.Active[i]
		}
	}
	if ps.Held == nil && ps.Own == nil && len(ps.Ignored) == 0 {
		return nil, ""
	}
	var b strings.Builder
	if h := ps.Held; h != nil {
		fmt.Fprintf(&b, "  paused by %s until %s", m.names([]model.MachineID{h.Initiator}), clock(h.Until))
		if h.Reason != "" {
			fmt.Fprintf(&b, " (%s)", h.Reason)
		}
		b.WriteString(": no capture, commit, apply or push here; resumes by itself\n")
	}
	if o := ps.Own; o != nil {
		c := m.confirm(ctx, o.ID)
		ps.Confirmations = &c
		fmt.Fprintf(&b, "  you paused the fleet until %s: %d/%d confirmed", clock(o.Until), len(c.Confirmed), len(c.Confirmed)+len(c.Waiting)+len(c.Ignored))
		if len(c.Waiting) > 0 {
			fmt.Fprintf(&b, " (%s not yet)", m.names(c.Waiting))
		}
		b.WriteString("\n")
	}
	for _, x := range ps.Ignored {
		fmt.Fprintf(&b, "  ignored pause %s: %s\n", x.ID, x.Why)
	}
	return ps, b.String()
}

// pauseCheck is the pause item of `yadm check`.
func (m *machineEnv) pauseCheck(ctx context.Context) checkItem {
	v, signers := m.pauseView(ctx)
	if len(v.Ignored) > 0 {
		var parts []string
		for _, x := range v.Ignored {
			who := ""
			if x.Signer != "" {
				who = " from " + string(x.Signer)
			}
			parts = append(parts, fmt.Sprintf("%s%s: %s", x.ID, who, x.Why))
		}
		return checkItem{Name: "pause", OK: false, Detail: "ignored pause records: " + strings.Join(parts, "; ")}
	}
	if h := v.Holding(m.local.Machine); h != nil {
		return checkItem{Name: "pause", OK: true, Warn: true, Detail: fmt.Sprintf("paused by %s until %s", h.Initiator, h.Until.UTC().Format(time.RFC3339))}
	}
	if len(signers) == 0 {
		return checkItem{Name: "pause", OK: true, Warn: true, Detail: "no pinned key log: this machine cannot verify a fleet pause and ignores every one"}
	}
	return checkItem{Name: "pause", OK: true, Detail: "no pause holds this machine"}
}
