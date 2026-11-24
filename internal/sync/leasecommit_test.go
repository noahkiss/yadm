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
