package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

// TestSealedObservedFacts: host-c publishes a collector sealed for client.
// host-b, after joining client, reads it in fleet show, list, diff, eval --as
// and manifest --as. host-a, a non-member, reads the status ref but no
// command prints the facts, and its $HOME and every repository stay clean.
func TestSealedObservedFacts(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canary := secrecytest.NewCanary(t, "client")
	canaries := append(fx.AllCanaries(), canary)
	const visible = "tool-visible"

	// host-c, the only client member, adds host-b to client. The add
	// publishes a status of its own, so the sealed fact goes in after it.
	c := fixtureMachine(t, root, remote, fx, fixture.HostC, true)
	hb := fx.Identities[fixture.HostB].Member()
	env := yadmOK(t, "enclave", "add", "host-b", "--enclave", "client", "--recipient", hb.Recipient, "--sign-key", hb.SignKey)
	added := decode[entryData](t, env.Data)
	if added.Fingerprint == "" {
		t.Fatalf("add: %+v", added)
	}
	yadmRawPush(t)

	// host-c publishes its status with the sealed fact.
	ctx := context.Background()
	m, err := openLoaded(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Only the sealed collector, so `observed: published` on manifest and
	// eval comes from the opened facts alone.
	facts := map[string]model.ObservedFact{
		"client-tools": {Collector: "client-tools", Items: []string{canary.String(), visible}, CollectedAt: time.Now().UTC()},
	}
	plain, sealed, problems := fleet.Published(m.snap.Fleet, facts, m.snap.Keys)
	if len(problems) != 0 || len(sealed) != 1 {
		t.Fatalf("published: sealed %v problems %v", sealed, problems)
	}
	st := model.Status{Machine: fixture.HostC, Version: "test", LastSync: time.Now().UTC(), Observed: plain, Sealed: sealed}
	if err := store.StatusRefs(m.repo, fixture.HostC).Publish(ctx, st); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := yadmRaw(t, "git", "push", "-q", "origin", fleet.StatusRef(fixture.HostC)); code != 0 {
		t.Fatalf("push status: exit %d %s", code, stderr)
	}

	// host-b joins client and reads host-c's sealed facts.
	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "enclave", "join", "client", "--expect", added.Fingerprint)
	env = yadmOK(t, "fleet", "show", "host-c")
	row := decode[fleet.Summary](t, env.Data)
	if row.Status == nil || len(row.Status.Sealed) != 1 || len(row.SealedErrors) != 0 {
		t.Fatalf("member show: %+v status %+v", row, row.Status)
	}
	if got := row.SealedObserved["client"]["client-tools"].Items; len(got) != 2 || !strings.Contains(strings.Join(got, " "), canary.String()) {
		t.Fatalf("member show sealed_observed: %+v", row.SealedObserved)
	}
	if _, ok := row.Status.Observed["client-tools"]; ok {
		t.Fatal("member show merged sealed facts into status.observed")
	}
	env = yadmOK(t, "fleet", "list")
	if rows := decode[map[string][]fleet.Summary](t, env.Data)["machines"]; !hasSealedFacts(rows, fixture.HostC) {
		t.Fatalf("member list: %+v", rows)
	}
	env = yadmOK(t, "fleet", "diff", "client-tools")
	d := decode[fleet.ObservedDiff](t, env.Data)
	if _, ok := d.Missing[fixture.HostC]; !ok || len(d.Union) != 2 {
		t.Fatalf("member diff: %+v", d)
	}
	cond := "observed:client-tools=" + visible
	env = yadmOK(t, "eval", cond, "--as", "host-c")
	ev := decode[evalQuery](t, env.Data)
	if !ev.Result || len(ev.Unavailable) != 0 || ev.Observed != observedPublished {
		t.Fatalf("member eval: %+v", ev)
	}
	env = yadmOK(t, "manifest", "--as", "host-c")
	if q := decode[manifestQuery](t, env.Data); len(q.Machines) != 1 || q.Machines[0].Observed != observedPublished {
		t.Fatalf("member manifest: %+v", q)
	}

	// host-a is in personal only: it fetched host-c's status ref but sees
	// none of its client facts.
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	env = yadmOK(t, "fleet", "show", "host-c")
	row = decode[fleet.Summary](t, env.Data)
	if row.Status == nil || len(row.Status.Sealed) != 1 || row.SealedObserved != nil || row.SealedErrors != nil {
		t.Fatalf("non-member show: %+v", row)
	}
	env = yadmOK(t, "fleet", "diff", "client-tools")
	if d := decode[fleet.ObservedDiff](t, env.Data); len(d.Union) != 0 || !containsID(d.Unknown, fixture.HostC) {
		t.Fatalf("non-member diff: %+v", d)
	}
	env = yadmOK(t, "eval", cond, "--as", "host-c")
	if ev := decode[evalQuery](t, env.Data); ev.Result || len(ev.Unavailable) != 1 || ev.Unavailable[0] != "client-tools" || ev.Observed != observedNone {
		t.Fatalf("non-member eval: %+v", ev)
	}
	env = yadmOK(t, "manifest", "--as", "host-c")
	if q := decode[manifestQuery](t, env.Data); len(q.Machines) != 1 || q.Machines[0].Observed != observedNone {
		t.Fatalf("non-member manifest: %+v", q)
	}
	for _, args := range [][]string{
		{"fleet", "show", "host-c"}, {"fleet", "list"}, {"fleet", "diff", "client-tools"},
		{"eval", cond, "--as", "host-c"}, {"manifest", "--as", "host-c"}, {"manifest", "--fleet"},
	} {
		_, _, out := yadm(t, args...)
		text, stderr, _ := yadmRaw(t, args...)
		for _, s := range []string{string(out), text, stderr} {
			// eval echoes its condition, which names the visible item.
			if strings.Contains(s, canary.String()) || (args[0] != "eval" && strings.Contains(s, visible)) {
				t.Fatalf("yadm %v on a non-member printed client facts", args)
			}
		}
	}
	secrecytest.AssertTreeClean(t, a.Home, canaries...)
	for _, repo := range []string{remote, a.Source, b.Source, c.Source} {
		secrecytest.AssertRepoClean(t, repo, canaries...)
	}
}

func hasSealedFacts(rows []fleet.Summary, id model.MachineID) bool {
	for _, r := range rows {
		if r.Machine.ID == id {
			return len(r.SealedObserved["client"]["client-tools"].Items) == 2
		}
	}
	return false
}

func containsID(ids []model.MachineID, id model.MachineID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
