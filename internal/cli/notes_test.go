package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/sync"
)

// TestReviewNoteSecrecy: a member notes a commit that touches its enclave.
// The note is sealed; the member reads it, and a non-member sees only
// "sealed note" in log and review list. The plaintext reaches no repository
// and no non-member output.
func TestReviewNoteSecrecy(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	canaries := fx.AllCanaries()
	why := secrecytest.NewCanary(t, "personal")
	canaries = append(canaries, why)

	// The fixture's commit gate runs secret-check; a stub passes it.
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadm(t, "task", "allow")
	yadm(t, "apply")
	note := filepath.Join(a.Home, ".config/notes/private.md")
	writeFile(t, note, readFile(t, note)+"one more private line\n")
	env := yadmOK(t, "commit", "-m", "edit private notes")
	ids := decode[struct {
		Commits []model.CommitID `json:"commits"`
	}](t, env.Data).Commits
	if len(ids) != 1 {
		t.Fatalf("commit: %+v", env.Data)
	}
	c := string(ids[0])

	// Sealing to another enclave, or to none, is refused.
	if _, code, _ := yadm(t, "review", "note", c, "--why", "x", "--seal", "client"); code != ExitRefused {
		t.Fatalf("seal to another enclave: exit %d", code)
	}
	if _, code, _ := yadm(t, "review", "note", c); code != ExitUsage {
		t.Fatalf("no --why: exit %d", code)
	}
	env = yadmOK(t, "review", "note", c, "--why", why.String())
	d := decode[noteData](t, env.Data)
	if !d.Pushed || !d.Note.Sealed || !d.Note.Opened || d.Note.Enclave != "personal" || d.Note.Why != why.String() {
		t.Fatalf("note: %+v", d)
	}
	// The member reads it back in log and review list.
	if s := mustJSON(t, yadmOK(t, "log").Data); !strings.Contains(s, why.String()) {
		t.Fatalf("member log lacks its note: %s", s)
	}
	if s := mustJSON(t, yadmOK(t, "review", "list", "personal").Data); !strings.Contains(s, why.String()) {
		t.Fatalf("member review list lacks its note: %s", s)
	}

	// The fixture's first commit touches two enclaves: free text is refused,
	// a paths-only note is fine.
	logEnv := yadmOK(t, "log")
	all := decode[map[string][]logCommit](t, logEnv.Data)["commits"]
	first := string(all[len(all)-1].ID)
	if _, code, _ := yadm(t, "review", "note", first, "--why", "setup"); code != ExitRefused {
		t.Fatalf("free text on a two-enclave commit: exit %d", code)
	}
	d = decode[noteData](t, yadmOK(t, "review", "note", first, "--paths-only").Data)
	if d.Note.Sealed || !d.Note.PathsOnly || !strings.HasPrefix(d.Note.Why, "paths: ") {
		t.Fatalf("paths-only note: %+v", d.Note)
	}

	// host-b is in no enclave.
	b := fixtureMachine(t, root, remote, fx, fixture.HostB, true)
	yadmOK(t, "apply")
	yadm(t, "sync", "--full")
	for _, args := range [][]string{{"log"}, {"review", "list"}, {"review", "list", "personal"}} {
		_, _, out := yadm(t, args...)
		for _, cn := range canaries {
			if strings.Contains(string(out), cn.String()) {
				t.Fatalf("yadm %v on a non-member printed %s plaintext", args, cn.Label)
			}
		}
	}
	var seen bool
	for _, lc := range decode[map[string][]logCommit](t, yadmOK(t, "log").Data)["commits"] {
		if string(lc.ID) == c {
			if lc.Note == nil || !lc.Note.Sealed || lc.Note.Opened || lc.Note.Why != "" || lc.Note.Text() != "sealed note" {
				t.Fatalf("non-member view of the note: %+v", lc.Note)
			}
			seen = true
		}
	}
	if !seen {
		t.Fatal("non-member log lacks the noted commit")
	}
	if out, _, _ := yadmRaw(t, "log"); !strings.Contains(out, "why: sealed note") {
		t.Fatalf("non-member text log: %s", out)
	}
	secrecytest.AssertTreeClean(t, b.Home, canaries...)
	for _, repo := range []string{a.Source, b.Source, remote} {
		secrecytest.AssertRepoClean(t, repo, canaries...)
	}

	// Notes written apart merge: host-b notes a shared commit without
	// pushing while host-a pushes another note; host-b's sync rebuilds its
	// notes ref on the remote one and both machines see both notes.
	d = decode[noteData](t, yadmOK(t, "review", "note", first, "--paths-only", "--no-push").Data)
	if d.Pushed {
		t.Fatal("--no-push pushed")
	}
	useMachine(t, root, string(fixture.HostA))
	yadmOK(t, "review", "note", c, "--why", "second "+why.String())
	useMachine(t, root, string(fixture.HostB))
	yadm(t, "sync", "--full")
	useMachine(t, root, string(fixture.HostA))
	yadm(t, "sync", "--full")
	notes := map[model.CommitID]*sync.Note{}
	for _, lc := range decode[map[string][]logCommit](t, yadmOK(t, "log").Data)["commits"] {
		notes[lc.ID] = lc.Note
	}
	if n := notes[model.CommitID(c)]; n == nil || n.Why != "second "+why.String() {
		t.Fatalf("host-a note on %s: %+v", c, n)
	}
	if n := notes[model.CommitID(first)]; n == nil || n.Machine != fixture.HostB || !n.PathsOnly {
		t.Fatalf("host-b's note did not reach host-a: %+v", n)
	}
	for _, repo := range []string{a.Source, b.Source, remote} {
		secrecytest.AssertRepoClean(t, repo, canaries...)
	}
}
