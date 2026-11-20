package e2e

import (
	"testing"
)

// TestUnionAppendsConverge: two machines append to a `merge = "union"`
// file. One commits and pushes; the other has not committed its line yet
// (its quiet period runs) when its sync brings the new source. Apply writes
// the union instead of holding the file, the next commit shares it, and
// both machines end with both lines and no hold.
func TestUnionAppendsConverge(t *testing.T) {
	const target = ".config/packages/Brewfile"
	_, ms, _ := synthWorld(t)
	a, b := ms[0], ms[1]

	appendLine(a, target, "brew \"from-a\"")
	appendLine(b, target, "brew \"from-b\"")
	a.OK("commit", target)

	// b's edit is younger than the quiet period: the auto sync fetches and
	// applies a's commit while b's line is still uncommitted.
	r := b.Run("sync", "--auto", "--full")
	if r.Code != 0 {
		t.Fatalf("b: sync --auto: %s", r.Err())
	}
	want := "brew \"git\"\nbrew \"from-a\"\nbrew \"from-b\"\n"
	if got, _ := b.ReadHome(target); string(got) != want {
		t.Fatalf("b after sync: %q, want %q", got, want)
	}
	if hs := b.Holds(); len(hs) != 0 {
		t.Fatalf("b holds after the union: %+v", hs)
	}

	b.OK("commit", target)
	a.OK("sync")
	for _, m := range []*Machine{a, b} {
		if got, _ := m.ReadHome(target); string(got) != want {
			t.Errorf("%s: %q, want %q", m.Name, got, want)
		}
		if hs := m.Holds(); len(hs) != 0 {
			t.Errorf("%s: holds %+v", m.Name, hs)
		}
	}
}
