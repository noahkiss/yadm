package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/schedule"
	"github.com/noahkiss/yadm/internal/store"
)

type checkItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"` // passes, but needs a look
	Detail string `json:"detail"`
}

// scheduleCheck judges the schedule: it fails when the schedule is not
// loaded or the service manager reports it broken, and warns when the last
// scheduled run is older than ScheduleStaleAfter. lastRun is when `sync
// --auto` last started; the service manager's own time wins when it has
// one. fix says whether `yadm schedule install` repairs it.
func scheduleCheck(st schedule.Status, lastRun, now time.Time) (checkItem, bool) {
	it := checkItem{Name: "schedule"}
	if !st.LastRun.IsZero() {
		lastRun = st.LastRun
	}
	state := fmt.Sprintf("installed=%v loaded=%v", st.Installed, st.Loaded)
	if st.LastExit != nil {
		state += fmt.Sprintf(" last_exit=%d", *st.LastExit)
	}
	if st.Runs > 0 {
		state += fmt.Sprintf(" runs=%d", st.Runs)
	}
	switch why := st.Broken(); {
	case why != "":
		it.Detail = fmt.Sprintf("the scheduled sync cannot start (%s): the service manager refuses the job, usually after an upgrade replaced the binary, and this machine has stopped syncing; fix: yadm schedule install", why)
		return it, true
	case !st.Loaded:
		it.Detail = fmt.Sprintf("%s %s; fix: yadm schedule install", state, st.UnitPath)
		return it, true
	}
	it.OK = true
	switch age := now.Sub(lastRun); {
	case lastRun.IsZero():
		it.Detail = fmt.Sprintf("%s %s; no scheduled run recorded yet", state, st.UnitPath)
	case age > ScheduleStaleAfter:
		it.Warn = true
		it.Detail = fmt.Sprintf("%s %s; the last scheduled run started %s ago, expected every %s", state, st.UnitPath, age.Truncate(time.Second), ScheduleInterval)
	default:
		it.Detail = fmt.Sprintf("%s %s; last scheduled run %s ago", state, st.UnitPath, age.Truncate(time.Second))
	}
	return it, false
}

func (a *app) cmdCheck(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	m, err := open(ctx)
	if err != nil {
		return notInit(err), err
	}
	var checks []checkItem
	add := func(name string, ok bool, format string, args ...any) {
		checks = append(checks, checkItem{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)})
	}

	if m.id == nil {
		add("identity", false, "no identity keys in the state directory")
	} else {
		add("identity", true, "identity keys present with mode 0600 for %s", m.id.Machine)
	}

	snap, lerr := m.load(ctx)
	var ce *manifest.CollisionError
	switch {
	case lerr == nil:
		add("manifest", true, "%d targets resolve without collisions", len(snap.Plan.Targets))
	case errors.As(lerr, &ce):
		var parts []string
		for _, c := range ce.Collisions {
			parts = append(parts, fmt.Sprint(c))
		}
		add("manifest", false, "collisions: %s", strings.Join(parts, "; "))
	default:
		add("manifest", false, "source does not load: %v", lerr)
	}

	if snap != nil {
		enclaves := snap.Fleet.Enclaves()
		if len(enclaves) == 0 {
			add("key_logs", true, "no enclaves")
		}
		claims := onDemandClaims(ctx, m)
		for _, e := range enclaves {
			l, ok := snap.Enclaves[e]
			switch {
			case !ok:
				add("key_logs", true, "%s: no key log yet", e)
			case l.Err != nil:
				add("key_logs", false, "%s: refused: %v", e, l.Err)
			default:
				add("key_logs", true, "%s: verified at seq %d, epoch %d", e, l.Head.Seq, l.Head.Epoch)
			}
			if ok && l.Err == nil {
				detail, diff := membership(snap.Fleet, e, l.Head, claims[e])
				if diff != "" {
					detail += "; " + diff
				}
				add("membership", diff == "", "%s", detail)
			}
		}
		for _, e := range m.local.OnDemand {
			checks = append(checks, onDemandCheck(snap, e))
		}
	}

	var next []string
	if s, err := hooks.scheduler(); err != nil {
		add("schedule", false, "%v", err)
	} else if st, err := s.Status(ctx); err != nil {
		add("schedule", false, "%v", err)
	} else {
		item, fix := scheduleCheck(st, lastScheduledRun(m.paths.State), hooks.now())
		checks = append(checks, item)
		if fix {
			next = append(next, "yadm schedule install")
		}
	}

	if s := m.selfStatus(ctx); s == nil || s.LastSync.IsZero() {
		add("last_sync", false, "this machine has not published a sync")
	} else {
		age := hooks.now().Sub(s.LastSync)
		add("last_sync", age <= fleet.StaleAfter, "last sync %s ago", age.Truncate(time.Second))
	}

	checks = append(checks, m.pauseCheck(ctx))
	checks = append(checks, m.rerootCheck())

	hs, err := m.eng.Holds(ctx)
	if err != nil {
		add("holds", false, "%v", err)
	} else {
		conflicts := 0
		for _, h := range hs {
			if h.Reason == model.HoldConflict {
				conflicts++
			}
		}
		add("holds", len(hs) == 0, "%d held, %d conflicts", len(hs), conflicts)
	}
	if err == nil {
		// An expired defer is an open decision again; nothing commits it.
		now := hooks.now()
		for _, x := range openDeferred(m.paths.State, hs, m.managedTargets()) {
			if x.Expired(now) {
				checks = append(checks, checkItem{Name: "deferred", OK: true, Warn: true,
					Detail: fmt.Sprintf("%s: defer expired %s (%s); settle it: yadm hold show %s", x.Target, clockOn(x.Expires(), now), oneLine(x.Why), x.ID)})
			}
		}
	}

	if err := m.repo.CheckSecrecyConfig(ctx); err != nil {
		add("secrecy_config", false, "%v", err)
	} else {
		add("secrecy_config", true, "no textconv cache or textconv notes")
	}
	if found, err := gitDrivers(ctx, m.repo); err != nil {
		add("git_drivers", false, "%v", err)
	} else if len(found) > 0 {
		add("git_drivers", false, "git config sets merge drivers or filters that could act on the source clone, which the tool never uses: %s", strings.Join(found, ", "))
	} else {
		add("git_drivers", true, "no merge driver or filter in the clone's config or assigned by its attributes")
	}

	failed := 0
	var b strings.Builder
	for _, c := range checks {
		mark := "ok  "
		switch {
		case !c.OK:
			mark = "FAIL"
			failed++
		case c.Warn:
			mark = "WARN"
		}
		fmt.Fprintf(&b, "%s %-15s %s\n", mark, c.Name, c.Detail)
	}
	res := result{data: map[string]any{"checks": checks}, text: b.String(), next: next}
	if failed > 0 {
		return res, fmt.Errorf("%d of %d checks failed", failed, len(checks))
	}
	return res, nil
}

// gitDrivers returns the filter.* and merge.*.driver keys that could act on
// the source clone: every one in the clone's local config, and one from any
// scope whose driver an attribute source of the clone assigns. A global
// driver no attribute names (git lfs install's filter.lfs.*, for example)
// never runs on the clone's paths, so it is left alone.
func gitDrivers(ctx context.Context, repo *store.Repo) ([]string, error) {
	const re = `^(merge\..+\.driver|filter\..+)$`
	local, err := repo.ConfigKeys(ctx, re, true)
	if err != nil {
		return nil, err
	}
	all, err := repo.ConfigKeys(ctx, re, false)
	if err != nil {
		return nil, err
	}
	used, err := repo.AttributeDrivers(ctx)
	if err != nil {
		return nil, err
	}
	isLocal := map[string]bool{}
	for _, k := range local {
		isLocal[k] = true
	}
	var out []string
	for _, k := range all {
		// filter.<name>.<var> or merge.<name>.driver; <name> may hold dots.
		i, j := strings.Index(k, "."), strings.LastIndex(k, ".")
		if isLocal[k] || (i < j && used[k[:i]+"."+k[i+1:j]]) {
			out = append(out, k)
		}
	}
	return out, nil
}
