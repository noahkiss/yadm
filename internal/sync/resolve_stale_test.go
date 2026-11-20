package sync

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
)

// Resolving a conflict by taking this machine's file commits over the
// current main, not over a stale local head: when another machine changed
// the file again after the conflict, the resolution still lands.
func TestResolveConflictFetchesFirst(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	A.write(aliases, "alias ll=\"ls -A\"\nalias gs=\"status-tool\"\n")
	A.sync()
	B.write(aliases, "alias ll=\"ls -B\"\nalias gs=\"status-tool\"\n")
	if r := B.sync(); len(holdsOf(r, model.HoldConflict)) != 1 {
		t.Fatalf("no conflict: %+v", r.Holds)
	}
	// A changes the file again; B's local main does not have it yet.
	A.write(aliases, "alias ll=\"ls -A2\"\nalias gs=\"status-tool\"\n")
	A.sync()

	r, err := B.s.Commit(context.Background(), CommitOptions{Paths: []model.Target{aliases}, Resolve: true, Push: true, Message: "resolve"})
	if err != nil {
		t.Fatal(err)
	}
	if cs := holdsOf(r, model.HoldConflict); len(cs) != 0 {
		t.Fatalf("resolution conflicted again: %+v", cs)
	}
	if got := w.remoteFile("files/.config/shell/aliases.sh"); !strings.Contains(got, "ls -B") {
		t.Fatalf("resolution did not land: %q", got)
	}
}
