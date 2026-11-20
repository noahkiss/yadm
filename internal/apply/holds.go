package apply

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// fileHoldReasons are the hold reasons apply and capture own. A successful
// apply, adopt or capture of a target clears them; other reasons belong to
// sync, the gate and tasks and are left alone.
var fileHoldReasons = map[model.HoldReason]bool{
	model.HoldDrifted:      true,
	model.HoldUncapturable: true,
	model.HoldSealGuard:    true,
	model.HoldRenderedEdit: true,
}

// HoldID returns the stable id of a hold. It is model.HoldID, kept here for
// callers of this package.
func HoldID(h model.Hold) string { return model.HoldID(h) }

// age renders how long ago t was, rounded for people.
func age(now, t time.Time) string {
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Minute).String()
	default:
		return d.Round(time.Hour).String()
	}
}

// fileHold builds a hold on a target. since is kept from an existing hold of
// the same reason, so the id and the reported age stay stable.
func fileHold(st *State, now time.Time, t model.Target, scope model.Scope, reason model.HoldReason, since time.Time, detail string) model.Hold {
	h := model.KeepSince(st.Holds, model.Hold{Target: t, Scope: scope, Reason: reason, Since: since}, now)
	h.Detail = fmt.Sprintf("%s; since %s (%s ago)", detail, h.Since.UTC().Format(time.RFC3339), age(now, h.Since))
	h.Next = []string{"yadm hold show " + h.ID, "yadm hold resolve " + h.ID + " --take target", "yadm hold resolve " + h.ID + " --take source"}
	return h
}

// putHold inserts or replaces the hold with the same target, task and reason.
func putHold(st *State, h model.Hold) {
	for i, x := range st.Holds {
		if model.SameHold(x, h) {
			st.Holds[i] = h
			return
		}
	}
	st.Holds = append(st.Holds, h)
}

// clearFileHolds removes apply- and capture-owned holds on a target.
func clearFileHolds(st *State, t model.Target) {
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target == t && fileHoldReasons[h.Reason] {
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
}

// clearTaskHolds removes the task_untrusted hold of a task that has now run.
func clearTaskHolds(st *State, task string) {
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target == "" && h.Task == task && h.Reason == model.HoldTaskUntrusted {
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
}

// heldFile reports whether a target has an apply- or capture-owned hold.
func heldFile(st *State, t model.Target) bool {
	for _, h := range st.Holds {
		if h.Target == t && fileHoldReasons[h.Reason] {
			return true
		}
	}
	return false
}

// Holds lists current holds from the state.
func (e *Engine) Holds(ctx context.Context) ([]model.Hold, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	out := make([]model.Hold, len(st.Holds))
	copy(out, st.Holds)
	return out, nil
}

// settleReasons are the hold reasons whose cause is the target's content.
// When a complete scan finds the target back at what this machine last
// wrote or captured, the cause is gone and SettleHolds drops them.
var settleReasons = map[model.HoldReason]bool{
	model.HoldDrifted:       true,
	model.HoldUncapturable:  true,
	model.HoldRenderedEdit:  true,
	model.HoldSealGuard:     true, // not a weakened-protection hold; see SettleHolds
	model.HoldCheckFailed:   true,
	model.HoldSecretScan:    true,
	model.HoldTaskUntrusted: true, // only a gate hold on a target
	model.HoldProtected:     true,
}

// SettleHolds drops the holds on managed targets whose cause is gone: drift
// is the result of a complete scan (no named paths), and a managed target
// it does not list equals what this machine last wrote or captured, so a
// check that failed, a capture that failed or a drift no longer applies.
// Conflict holds stay (they carry the incoming change), and so do holds
// for a manifest that weakened protection (apply sets them again from the
// plan). It returns the number of holds dropped.
func (e *Engine) SettleHolds(_ context.Context, drift []Drift) (int, error) {
	for _, d := range drift {
		if d.Kind == DriftUnreadable {
			return 0, nil // incomplete scan: absence proves nothing
		}
	}
	st, err := e.loadState()
	if err != nil {
		return 0, err
	}
	drifting := map[model.Target]bool{}
	for _, d := range drift {
		drifting[d.Target] = true
	}
	out := st.Holds[:0]
	n := 0
	for _, h := range st.Holds {
		_, managed := st.Targets[h.Target]
		if h.Target != "" && managed && !drifting[h.Target] && settleReasons[h.Reason] && !weakenedHold(h) {
			n++
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
	if n == 0 {
		return 0, nil
	}
	return n, e.State.Save(st)
}

func weakenedHold(h model.Hold) bool {
	return h.Reason == model.HoldSealGuard && strings.Contains(h.Detail, "weakened this file's protection")
}
