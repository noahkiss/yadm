package apply

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// fileHoldReasons are the hold reasons apply and capture own. A successful
// apply, adopt or capture of a target clears them; other reasons belong to
// sync, the gate and tasks and are left alone.
var fileHoldReasons = map[model.HoldReason]bool{
	model.HoldDrifted:       true,
	model.HoldUncapturable:  true,
	model.HoldSealGuard:     true,
	model.HoldRenderedEdit:  true,
	model.HoldNeedsDecision: true,
}

// ExpectTask is the Task of the seal_guard hold on a file that `yadm commit
// --expect-enclave` refused (package sync). Scan-driven captures skip it.
// It goes with the file, or once the file is back at what was written.
const ExpectTask = "expect-enclave"

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

// badNameDetail is the detail of a hold on a target whose name holds a
// control character. Such a file is never written, captured or resolved:
// its name cannot be shown or passed to a command safely.
const badNameDetail = "the file name holds a control character; it is never written or captured"

// badNameHold holds a target whose name holds a control character. Its
// only suggested command shows it; rename or remove the file to clear it.
func badNameHold(st *State, now time.Time, t model.Target, scope model.Scope, since time.Time) model.Hold {
	h := fileHold(st, now, t, scope, model.HoldUncapturable, since, badNameDetail)
	h.Next = []string{"yadm hold show " + h.ID}
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

// Holds lists current holds from the state, without the holds that went
// with their file (goesWithFile): the file is gone, so the next complete
// scan drops them. Holds never writes the state; callers need not hold the
// sync lock.
func (e *Engine) Holds(ctx context.Context) ([]model.Hold, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	out := make([]model.Hold, 0, len(st.Holds))
	for _, h := range st.Holds {
		if goesWithFile(st, h) && e.gone(ctx, h.Target) {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

// StoredHolds lists every hold in the state, those Holds leaves out
// included. A caller that prunes its own records by the open holds uses it:
// a file that is gone only for a moment must not end what its hold covers.
func (e *Engine) StoredHolds(ctx context.Context) ([]model.Hold, error) {
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

// goneReasons are the hold reasons on an unmanaged file that go with the
// file: a new file in an owned root held as protected, and a commit-gate
// hold from a track or commit the gate refused. Once the file is gone there
// is nothing left to commit or check, and no command could settle them.
var goneReasons = map[model.HoldReason]bool{
	model.HoldProtected:     true,
	model.HoldCheckFailed:   true,
	model.HoldTaskUntrusted: true, // only a gate hold on a target
}

// newInEnclaveRootDetail starts the detail of the seal_guard hold capture
// puts on a new file in an enclave root this machine cannot seal for.
const newInEnclaveRootDetail = "new file in an enclave root: "

// goesWithFile reports whether hold h has no cause left once its file is
// gone. It holds a file nothing manages here (no state record), and is one
// of:
//
//   - protected, check_failed or task_untrusted (goneReasons): a new file
//     or a file a refused track or commit named; nothing is left to commit
//     or check;
//   - seal_guard from `yadm commit --expect-enclave` (Task ExpectTask);
//   - seal_guard on a new file in an enclave root this machine cannot seal
//     for.
//
// Everything else outlives the file. A managed target's hold stays when the
// file is gone, since its deletion is what is held. A conflict carries the
// incoming change. A weakened-protection or held-path hold (Task GuardTask)
// comes from the manifest, not the file. Other seal_guard, drifted,
// needs_decision and uncapturable holds belong to apply, which decides
// them again from the plan. Holds without a target are not about a file.
func goesWithFile(st *State, h model.Hold) bool {
	if h.Target == "" {
		return false
	}
	if _, managed := st.Targets[h.Target]; managed {
		return false
	}
	switch {
	case goneReasons[h.Reason]:
		return true
	case h.Reason == model.HoldSealGuard && h.Task == ExpectTask:
		return true
	case h.Reason == model.HoldSealGuard && h.Task == "" && strings.HasPrefix(h.Detail, newInEnclaveRootDetail):
		return true
	}
	return false
}

// SettleHolds drops the holds on managed targets whose cause is gone: drift
// is the result of a complete scan (no named paths), and a managed target
// it does not list equals what this machine last wrote or captured, so a
// check that failed, a capture that failed or a drift no longer applies.
// Conflict holds stay (they carry the incoming change), and so do holds
// for a manifest that weakened protection (apply sets them again from the
// plan). A hold that goes with its file (goesWithFile) goes when the file
// is gone; while the file exists it stays. It returns the number of holds
// dropped.
func (e *Engine) SettleHolds(ctx context.Context, drift []Drift) (int, error) {
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
		if !drifting[h.Target] && goesWithFile(st, h) && e.gone(ctx, h.Target) {
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

// gone reports whether nothing is at target t in $HOME. The stat is
// bounded (Deps.StatTimeout): a stat that does not return proves nothing,
// so the file counts as there.
func (e *Engine) gone(ctx context.Context, t model.Target) bool {
	abs, err := e.abs(t)
	if err != nil {
		return false
	}
	_, err = bounded(ctx, e.StatTimeout, func() (fs.FileInfo, error) { return e.fs.Lstat(abs) })
	return errors.Is(err, fs.ErrNotExist)
}

// weakenedHold reports a hold for weakened protection: a held path's hold
// (Task GuardTask), or apply's own seal_guard hold for a weaker entry.
func weakenedHold(h model.Hold) bool {
	return h.Reason == model.HoldSealGuard && (h.Task == GuardTask || strings.Contains(h.Detail, "weakened this file's protection"))
}

// pruneStaleHolds drops the holds whose target nothing covers any more: no
// target of the plan, no state record, no applying glob entry and no owned
// root (in the manifest or accepted here). Such a hold names a file no
// command can commit, apply or settle, for example one whose entry and
// source a commit from another machine removed. Only the reasons
// SettleHolds settles go, except the commit gate's: a gate hold may name
// a file that a track or retag is about to cover. A conflict, a
// weakened-protection hold and holds without a target stay too. The caller
// holds a resolved plan.
func pruneStaleHolds(st *State, snap *Snapshot) {
	if snap == nil || snap.Plan == nil {
		return
	}
	covered := func(t model.Target) bool {
		if _, ok := snap.Plan.Targets[t]; ok {
			return true
		}
		if _, ok := st.Targets[t]; ok {
			return true
		}
		if snap.Plan.Root(t) != nil {
			return true
		}
		for _, r := range st.Roots {
			if t == r.Path || strings.HasPrefix(string(t), string(r.Path)+"/") {
				return true
			}
		}
		_, ok, err := snap.Plan.GlobNew(t)
		return ok || err != nil
	}
	out := st.Holds[:0]
	for _, h := range st.Holds {
		gate := h.Reason == model.HoldCheckFailed || h.Reason == model.HoldTaskUntrusted
		if h.Target != "" && settleReasons[h.Reason] && !gate && !weakenedHold(h) && !covered(h.Target) {
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
}
