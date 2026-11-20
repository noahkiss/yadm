package sync

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
)

const aliases model.Target = ".config/shell/aliases.sh"
const pkgList model.Target = ".config/packages/list"

// aliasesLong puts context lines between the two aliases, so edits to each
// merge without touching the other.
const aliasesLong = "alias ll=\"ls -la\"\n# one\n# two\n# three\nalias gs=\"status-tool\"\n"

func TestFirstSyncAppliesFixture(t *testing.T) {
	w := newWorld(t, nil, fixture.HostA, fixture.HostB, fixture.HostC)
	for _, id := range []model.MachineID{fixture.HostA, fixture.HostB, fixture.HostC} {
		m := w.machines[id]
		r := m.sync()
		if r.Applied == "" {
			t.Fatalf("%s: nothing applied: %+v", id, r)
		}
		if got := m.read(aliases); !strings.Contains(got, "alias ll") {
			t.Errorf("%s: aliases %q", id, got)
		}
		if len(r.Holds) != 0 {
			t.Errorf("%s: holds after first sync: %+v", id, r.Holds)
		}
		if len(r.Committed) != 0 {
			t.Errorf("%s: first sync committed %v", id, r.Committed)
		}
	}
}

// syncAll runs one sync on each machine in order.
func (w *world) syncAll(ids ...model.MachineID) {
	for _, id := range ids {
		w.machines[id].sync()
	}
}

func TestConcurrentEditsConverge(t *testing.T) {
	a, b, c := fixture.HostA, fixture.HostB, fixture.HostC
	w := newWorld(t, nil, a, b, c)
	w.syncAll(a, b, c)
	A, B, C := w.machines[a], w.machines[b], w.machines[c]
	A.write(aliases, aliasesLong)
	A.sync()
	w.syncAll(b, c)

	// Two machines edit distant lines of one file, a third edits another file.
	A.write(aliases, strings.Replace(aliasesLong, "alias ll=\"ls -la\"", "alias ll=\"ls -la --a\"", 1))
	B.write(aliases, strings.Replace(aliasesLong, "alias gs=\"status-tool\"", "alias gs=\"status-tool --b\"", 1))
	C.write(pkgList, "tool-one\ntool-two\ntool-c\n")
	ra := A.sync()
	if len(ra.Committed) != 1 || !ra.Pushed {
		t.Fatalf("A: %+v", ra)
	}
	rb := B.sync()
	if rb.Replayed != 1 || !rb.Pushed || len(holdsOf(rb, model.HoldConflict)) != 0 {
		t.Fatalf("B: %+v", rb)
	}
	C.sync()
	w.syncAll(a, b, c)

	want := strings.Replace(strings.Replace(aliasesLong, "alias ll=\"ls -la\"", "alias ll=\"ls -la --a\"", 1),
		"alias gs=\"status-tool\"", "alias gs=\"status-tool --b\"", 1)
	for _, m := range []*machine{A, B, C} {
		if got := m.read(aliases); got != want {
			t.Errorf("%s aliases = %q, want %q", m.id, got, want)
		}
		if got := m.read(pkgList); got != "tool-one\ntool-two\ntool-c\n" {
			t.Errorf("%s list = %q", m.id, got)
		}
		if m.main() != model.CommitID(w.remoteMain()) {
			t.Errorf("%s main %s != remote %s", m.id, m.main(), w.remoteMain())
		}
	}
	// History stays linear: no merge commits.
	if n := git(t, w.remote, "rev-list", "--merges", "--count", "main"); n != "0" {
		t.Errorf("%s merge commits on main", n)
	}
	// Auto commits carry the trailers.
	msg := git(t, w.remote, "log", "-1", "--format=%B", "main~1")
	for _, want := range []string{"Machine: ", "Yadm-Auto: scan", "Yadm-Scope: shared"} {
		if !strings.Contains(msg, want) {
			t.Errorf("commit message lacks %q:\n%s", want, msg)
		}
	}
	// Each machine published its status ref.
	for _, id := range []model.MachineID{a, b, c} {
		git(t, w.remote, "rev-parse", "refs/yadm/status/"+string(id))
	}
}
