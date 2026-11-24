package sync

import (
	"context"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
)

// TestUnattendedCommitSkipsLeased: a hook's commit leaves a path a live
// lease names, whoever holds it; a manual commit that names it commits it.
func TestUnattendedCommitSkipsLeased(t *testing.T) {
	w := newWorld(t, nil, fixture.HostA)
	A := w.machines[fixture.HostA]
	A.sync()
	ctx := context.Background()
	if err := A.s.Leases.Take(Lease{Holder: "agent-x", Paths: []string{string(aliases)}, Expires: w.clock.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	A.write(aliases, "alias ll=\"ls -l\"\n")
	before := A.main()
	r, err := A.s.Commit(ctx, CommitOptions{Paths: []model.Target{aliases}, Trigger: TriggerStop, Unattended: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Committed) != 0 || A.main() != before {
		t.Fatalf("an unattended commit took a leased path: %+v", r)
	}
	r, err = A.s.Commit(ctx, CommitOptions{Paths: []model.Target{aliases}, Message: "shorter listing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Committed) != 1 || A.main() == before {
		t.Fatalf("a manual commit did not bypass the lease: %+v", r)
	}
}

// TestLeaseTakeAdds: a holder's repeat take adds its paths and refreshes
// the expiry of all of them; a release with paths drops only those.
func TestLeaseTakeAdds(t *testing.T) {
	l := FileLeases(t.TempDir())
	now := time.Now()
	if err := l.Take(Lease{Holder: "agent-x", Paths: []string{".config/a"}, Expires: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if err := l.Take(Lease{Holder: "agent-x", Paths: []string{".config/b", ".config/a"}, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	ls, err := l.List()
	if err != nil || len(ls) != 1 || len(ls[0].Paths) != 2 || !ls[0].Expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("after a repeat take: %+v %v", ls, err)
	}
	if !leased(ls, ".config/a", now.Add(30*time.Minute)) || !leased(ls, ".config/b", now.Add(30*time.Minute)) {
		t.Fatal("the first take lost its protection or its refresh")
	}
	if err := l.Release("agent-x", ".config/a"); err != nil {
		t.Fatal(err)
	}
	if ls, _ := l.List(); len(ls) != 1 || leased(ls, ".config/a", now) || !leased(ls, ".config/b", now) {
		t.Fatalf("after releasing one path: %+v", ls)
	}
	if err := l.Release("agent-x", ".config/b"); err != nil {
		t.Fatal(err)
	}
	if ls, _ := l.List(); len(ls) != 0 {
		t.Fatalf("a lease with no path left stays: %+v", ls)
	}

	// An expired lease's paths are not carried into a new one.
	if err := l.Take(Lease{Holder: "agent-y", Paths: []string{".config/old"}, Expires: now.Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if err := l.Take(Lease{Holder: "agent-y", Paths: []string{".config/new"}, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if ls, _ := l.List(); len(ls) != 1 || len(ls[0].Paths) != 1 || ls[0].Paths[0] != ".config/new" {
		t.Fatalf("an expired lease was carried over: %+v", ls)
	}
}
