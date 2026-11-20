package e2e

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/secrecytest"
)

// TestTrackEnclaveSecrecy: `yadm track --enclave` on a member commits the
// new entry and the file sealed under sealed/<enclave>/ in one commit. The
// other member receives the plaintext; the non-member receives nothing,
// and the plaintext reaches neither its $HOME nor any repository's object
// store. A non-member cannot track into the enclave (exit 6).
func TestTrackEnclaveSecrecy(t *testing.T) {
	const target = ".config/secret/token"
	w, ms, setup := synthWorld(t)
	a, b, c := ms[0], ms[1], ms[2]
	canary := secrecytest.NewCanary(t, "home-track")
	a.WriteHome(target, []byte("token = "+canary.String()+"\n"), 0)

	r := a.OK("track", target, "--enclave", "home", "--when", "type:home")
	var d struct {
		Target string `json:"target"`
		Source string `json:"source"`
		Scope  string `json:"scope"`
		Commit string `json:"commit"`
		Pushed bool   `json:"pushed"`
	}
	if err := r.Decode(&d); err != nil {
		t.Fatalf("track data: %v", err)
	}
	if d.Target != target || d.Source != "sealed/home/"+target || d.Scope != "home" || d.Commit == "" || !d.Pushed {
		t.Fatalf("track data: %+v", d)
	}
	// One commit holds the manifest entry and the sealed source.
	files := w.Git(a.Source, "show", "--name-only", "--format=", d.Commit)
	if !strings.Contains(files, "manifest.toml") || !strings.Contains(files, "sealed/home/"+target) || strings.Contains(files, "files/"+target) {
		t.Fatalf("track commit files:\n%s", files)
	}
	if subject := w.Git(a.Source, "log", "-1", "--format=%s", d.Commit); subject != "track "+target {
		t.Fatalf("track commit subject %q", subject)
	}

	for _, m := range []*Machine{a, b, c} {
		m.OK("sync")
	}
	if got, ok := b.ReadHome(target); !ok || !bytes.Contains(got, canary.Bytes()) {
		t.Errorf("host-b (member) did not receive the tracked file (present=%v)", ok)
	}
	if _, ok := c.ReadHome(target); ok {
		t.Errorf("host-c (non-member) received the tracked file")
	}
	secrecytest.AssertTreeClean(t, c.Root, canary, setup)
	secrecytest.AssertRepoClean(t, w.Remote, canary, setup)
	for _, m := range ms {
		secrecytest.AssertRepoClean(t, m.Source, canary, setup)
	}

	// A non-member is refused, and nothing is committed.
	c.WriteHome(".config/secret/other", []byte("x\n"), 0)
	before := c.Main()
	if r := c.Run("track", ".config/secret/other", "--enclave", "home"); r.Code != 6 {
		t.Fatalf("non-member track: %s, want exit 6", r.Err())
	}
	if c.Main() != before {
		t.Fatal("a refused track committed")
	}
	if _, err := os.Stat(c.Source + "/sealed/home/.config/secret/other"); err == nil {
		t.Fatal("a refused track wrote a source file")
	}
}
