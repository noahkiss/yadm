package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/secrecytest"
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
	// The next timer tick, before the quiet period ends, reports the union
	// as pending, like any edit that waits for its quiet period, and holds
	// nothing.
	r = b.Run("sync", "--auto", "--full")
	if r.Code != 0 {
		t.Fatalf("b: second sync --auto: %s", r.Err())
	}
	var tick struct {
		Pending []string `json:"pending"`
		Holds   []Hold   `json:"holds"`
	}
	if err := r.Decode(&tick); err != nil || len(tick.Holds) != 0 || len(tick.Pending) != 1 || tick.Pending[0] != target {
		t.Fatalf("b next tick: %+v %v", tick, err)
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

// TestSealedUnionAppendsConverge: the same for a sealed union file. The
// members converge on the union; the non-member receives none of it, and
// no appended line reaches its $HOME or any repository's object store.
func TestSealedUnionAppendsConverge(t *testing.T) {
	const target = ".config/vault/log"
	w, ms, setup := synthWorld(t)
	a, b, c := ms[0], ms[1], ms[2]
	c0 := secrecytest.NewCanary(t, "union-base")
	ca := secrecytest.NewCanary(t, "union-a")
	cb := secrecytest.NewCanary(t, "union-b")
	all := []secrecytest.Canary{setup, c0, ca, cb}

	a.WriteHome(target, []byte(c0.String()+"\n"), 0)
	a.OK("track", target, "--enclave", "home", "--when", "type:home")
	// The tracked entry is the manifest's last table: a writer makes it a
	// union file.
	pushSourceEdit(t, w, "union log", func(dir string) {
		f, _ := os.OpenFile(filepath.Join(dir, "manifest.toml"), os.O_APPEND|os.O_WRONLY, 0)
		_, _ = f.WriteString("merge = \"union\"\n")
		_ = f.Close()
	})
	for _, m := range ms {
		m.OK("sync")
	}

	appendLine(a, target, ca.String())
	appendLine(b, target, cb.String())
	a.OK("commit", target)
	if r := b.Run("sync", "--auto", "--full"); r.Code != 0 {
		t.Fatalf("b: sync --auto: %s", r.Err())
	}
	if hs := b.Holds(); len(hs) != 0 {
		t.Fatalf("b holds after the sealed union: %+v", hs)
	}
	b.OK("commit", target)
	for _, m := range ms {
		m.OK("sync")
	}
	want := c0.String() + "\n" + ca.String() + "\n" + cb.String() + "\n"
	for _, m := range []*Machine{a, b} {
		if got, _ := m.ReadHome(target); string(got) != want {
			t.Errorf("%s: sealed union file differs (has a=%v b=%v)", m.Name, bytes.Contains(got, ca.Bytes()), bytes.Contains(got, cb.Bytes()))
		}
		if hs := m.Holds(); len(hs) != 0 {
			t.Errorf("%s: holds %+v", m.Name, hs)
		}
	}
	if _, ok := c.ReadHome(target); ok {
		t.Error("host-c (non-member) received the sealed union file")
	}
	secrecytest.AssertTreeClean(t, c.Root, all...)
	secrecytest.AssertRepoClean(t, w.Remote, all...)
	for _, m := range ms {
		secrecytest.AssertRepoClean(t, m.Source, all...)
	}
}
