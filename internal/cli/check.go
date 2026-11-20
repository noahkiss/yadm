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
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

type checkItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
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
				add("membership", true, "%s", membershipDetail(snap.Fleet, e, l.Head))
				if d := membershipDiff(snap.Fleet, e, l.Head); d != "" {
					checks[len(checks)-1] = checkItem{Name: "membership", OK: false, Detail: string(e) + ": " + d}
				}
			}
		}
	}

	if s, err := hooks.scheduler(); err != nil {
		add("schedule", false, "%v", err)
	} else if st, err := s.Status(ctx); err != nil {
		add("schedule", false, "%v", err)
	} else {
		add("schedule", st.Loaded, "installed=%v loaded=%v %s", st.Installed, st.Loaded, st.UnitPath)
	}

	if s := m.selfStatus(ctx); s == nil || s.LastSync.IsZero() {
		add("last_sync", false, "this machine has not published a sync")
	} else {
		age := hooks.now().Sub(s.LastSync)
		add("last_sync", age <= fleet.StaleAfter, "last sync %s ago", age.Truncate(time.Second))
	}

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
		if !c.OK {
			mark = "FAIL"
			failed++
		}
		fmt.Fprintf(&b, "%s %-15s %s\n", mark, c.Name, c.Detail)
	}
	res := result{data: map[string]any{"checks": checks}, text: b.String()}
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

// membershipDiff compares the fleet's machines of an enclave type with the
// key log's members. Empty means they agree.
func membershipDiff(f *fleet.File, e model.EnclaveName, head crypt.LogEntry) string {
	inLog := map[model.MachineID]bool{}
	for _, mb := range head.Members {
		inLog[mb.Machine] = true
	}
	var onlyFleet, onlyLog []string
	for id, mc := range f.Machines {
		if mc.HasType(model.TypeName(e)) && !inLog[id] {
			onlyFleet = append(onlyFleet, string(id))
		}
	}
	for id := range inLog {
		mc, ok := f.Machines[id]
		if !ok || !mc.HasType(model.TypeName(e)) {
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
		parts = append(parts, "key-log members without the type in the fleet: "+strings.Join(onlyLog, ","))
	}
	return strings.Join(parts, "; ")
}

func membershipDetail(f *fleet.File, e model.EnclaveName, head crypt.LogEntry) string {
	return fmt.Sprintf("%s: %d members agree with the fleet", e, len(head.Members))
}
