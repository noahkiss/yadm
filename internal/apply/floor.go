package apply

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// GuardTask is the Task of the hold on a target whose protection a fetched
// commit weakened (a held path, below). Package sync names its whole-source
// refusal with the same task.
const GuardTask = "manifest-guard"

// Floor is the protection a fetched commit tried to take from a target: the
// protection the source this machine had accepted gave it. sync records it
// (HoldBack) before it takes the fetched source, so the next fetch, judged
// from the weakened source, cannot launder it.
//
// While a floor stands and the plan protects the target less, the target is
// a held path: apply, capture, resolve, record and track --variant treat it
// as weakened (weakened). Apply never writes or deletes it, capture never
// captures it, and one seal_guard hold with Task GuardTask names it. The
// floor goes when the plan protects the target at least as much again (a
// later commit restored it) or the user allows the new protection here
// (AllowProtection). A target that leaves the plan keeps its floor, without
// a hold: a later commit that adds it back weaker is held again.
type Floor struct {
	Protection protection     `json:"protection"`
	Commit     model.CommitID `json:"commit,omitempty"` // the fetched commit that weakened it
	Since      time.Time      `json:"since"`
}

// Weakening is one way a fetched manifest protects less than the source it is
// judged from: a target that loses protection, or an owned root that covers
// a protected path. Guard.Weakenings lists them.
type Weakening struct {
	Target model.Target `json:"target"`         // the target, or the root's path
	Root   bool         `json:"root,omitempty"` // an owned root
	Detail string       `json:"detail"`         // what weakened, and the command that allows it

	from protection // the protection the old source gave Target
}

// HoldBack records a floor for each target weakening in ws (roots are not
// held per path) and reports the targets that had none before. A target
// that already has a floor keeps it: it is the older, accepted protection.
func (e *Engine) HoldBack(_ context.Context, ws []Weakening, commit model.CommitID) ([]model.Target, error) {
	st, err := e.loadState()
	if err != nil {
		return nil, err
	}
	var fresh []model.Target
	for _, w := range ws {
		if w.Root || w.Target == "" {
			continue
		}
		if _, ok := st.Floors[w.Target]; ok {
			continue
		}
		if len(weakerBy(w.from, protection{})) == 0 {
			// Only Guard.Weakenings fills from; a floor of nothing
			// would hold nothing. Fail closed.
			return nil, fmt.Errorf("hold back %s: the weakening carries no protection to keep", w.Target)
		}
		if st.Floors == nil {
			st.Floors = map[model.Target]Floor{}
		}
		st.Floors[w.Target] = Floor{Protection: w.from, Commit: commit, Since: e.Now().UTC()}
		fresh = append(fresh, w.Target)
	}
	if len(fresh) == 0 {
		return nil, nil
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i] < fresh[j] })
	return fresh, e.State.Save(st)
}

// floorWeak lists how r protects its target less than the target's floor,
// unless the user allowed r's protection here. Empty: no floor, or the floor
// no longer holds the target.
func (e *Engine) floorWeak(st *State, r manifest.Resolved) []string {
	f, ok := st.Floors[r.Target]
	if !ok {
		return nil
	}
	next := protOf(r.Entry)
	why := weakerBy(f.Protection, next)
	if len(why) == 0 || e.allowed(KindProtection, string(r.Target), protectionHash(r.Target, next)) {
		return nil
	}
	return why
}

// floorDetail is the detail of the hold on a held path.
func floorDetail(why []string) string {
	return "a fetched commit weakened this file's protection (" + strings.Join(why, "; ") +
		"); this machine keeps the file as it is: it is neither applied, deleted nor captured until the new protection is allowed here or a later commit restores it"
}

// settleFloors runs after a full apply of snap: a floor whose target the
// plan protects enough again, or whose new protection is allowed, goes.
// A guard hold whose target this apply did not hold goes too: the target
// left the plan (its floor stays) or its floor went.
func (e *Engine) settleFloors(st *State, snap *Snapshot, held map[model.Target]bool) {
	for t := range st.Floors {
		r, ok := snap.Plan.Targets[t]
		if ok && !held[t] && len(e.floorWeak(st, r)) == 0 {
			delete(st.Floors, t)
		}
	}
	out := st.Holds[:0]
	for _, h := range st.Holds {
		if h.Target != "" && h.Task == GuardTask && !held[h.Target] {
			continue
		}
		out = append(out, h)
	}
	st.Holds = out
}

// floorHold is the one hold on a held path.
func floorHold(st *State, now time.Time, t model.Target, scope model.Scope, since time.Time, why []string) model.Hold {
	h := model.KeepSince(st.Holds, model.Hold{Target: t, Task: GuardTask, Scope: scope, Reason: model.HoldSealGuard, Since: since}, now)
	h.Detail = fmt.Sprintf("%s; since %s (%s ago)", floorDetail(why), h.Since.UTC().Format(time.RFC3339), age(now, h.Since))
	h.Next = []string{"yadm protection allow " + model.ShellQuote(string(t)), "yadm hold show " + h.ID}
	return h
}
