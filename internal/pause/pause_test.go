package pause

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "pause-home-")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{
		"HOME":                home,
		"XDG_CONFIG_HOME":     filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL":   "/dev/null",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_AUTHOR_NAME":     "test",
		"GIT_AUTHOR_EMAIL":    "test@example.invalid",
		"GIT_COMMITTER_NAME":  "test",
		"GIT_COMMITTER_EMAIL": "test@example.invalid",
	} {
		os.Setenv(k, v)
	}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

const (
	self model.MachineID = "m-self"
	peer model.MachineID = "m-peer"
)

var t0 = time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)

type env struct {
	t     *testing.T
	ctx   context.Context
	dir   string
	state string
	repo  *store.Repo
	ids   map[model.MachineID]*crypt.Identity
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "src")
	if out, err := exec.Command("git", "init", "-q", "-b", "main", dir).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	state := t.TempDir()
	repo, err := store.Open(dir, state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { repo.Close() })
	e := &env{t: t, ctx: context.Background(), dir: dir, state: state, repo: repo, ids: map[model.MachineID]*crypt.Identity{}}
	for _, m := range []model.MachineID{self, peer} {
		id, err := crypt.GenerateIdentity(m)
		if err != nil {
			t.Fatal(err)
		}
		e.ids[m] = id
	}
	return e
}

func (e *env) trust(time.Time) Trust {
	return Trust{
		Fleet:   map[model.MachineID]bool{self: true, peer: true},
		Members: map[model.MachineID][]crypt.Member{self: {e.ids[self].Member()}, peer: {e.ids[peer].Member()}},
	}
}

func (e *env) pause(by model.MachineID, created time.Time, span time.Duration) Record {
	e.t.Helper()
	id, err := NewID()
	if err != nil {
		e.t.Fatal(err)
	}
	r, err := Sign(Record{Op: OpPause, ID: id, Initiator: by, Created: created, Deadline: created.Add(span)}, e.ids[by])
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *env) write(now time.Time, recs ...Record) {
	e.t.Helper()
	if _, err := Write(e.ctx, e.repo, recs, now); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) eval(now time.Time) View {
	e.t.Helper()
	v, err := Evaluate(e.ctx, e.repo, e.state, self, e.trust(now), now, true)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) git(args ...string) string {
	e.t.Helper()
	out, err := exec.Command("git", append([]string{"-C", e.dir}, args...)...).CombinedOutput()
	if err != nil {
		e.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Chained pauses from one signer hold a machine at most MaxSpan in a row;
// a pause first seen after an unheld evaluation starts a new run.
func TestChainedPausesCapped(t *testing.T) {
	e := newEnv(t)
	e.write(t0, e.pause(peer, t0, MaxSpan))
	if h := e.eval(t0).Holding(self); h == nil || !h.Until.Equal(t0.Add(MaxSpan)) {
		t.Fatalf("first pause: %+v", h)
	}
	at := t0.Add(3 * time.Hour)
	e.write(at, e.pause(peer, at, MaxSpan))
	if h := e.eval(at); h.Holding(self) == nil {
		t.Fatal("second pause not honoured during the run")
	}
	for _, now := range []time.Time{t0.Add(MaxSpan), t0.Add(MaxSpan + time.Minute), t0.Add(5 * time.Hour)} {
		if h := e.eval(now).Holding(self); h != nil {
			t.Fatalf("held at %s past the 4h run: %+v", now.Sub(t0), h)
		}
	}
	if !HeldUntil(e.state).IsZero() {
		t.Fatal("held_until not cleared")
	}
	at = t0.Add(5 * time.Hour)
	e.write(at, e.pause(peer, at, 30*time.Minute))
	if h := e.eval(at).Holding(self); h == nil || !h.Until.Equal(at.Add(30*time.Minute)) {
		t.Fatalf("a pause after an unheld evaluation: %+v", h)
	}
}

// An initiator whose clock runs ahead holds a peer no longer than the
// pause's own span.
func TestSkewedCreatedHoldsItsSpan(t *testing.T) {
	e := newEnv(t)
	e.write(t0, e.pause(peer, t0.Add(48*time.Hour), 30*time.Minute))
	if h := e.eval(t0).Holding(self); h == nil || !h.Until.Equal(t0.Add(30*time.Minute)) {
		t.Fatalf("skewed pause: %+v", h)
	}
	if h := e.eval(t0.Add(31 * time.Minute)).Holding(self); h != nil {
		t.Fatalf("skewed pause held past its span: %+v", h)
	}
}

// Two machines that pause at once: only the earlier pause holds the other
// initiator.
func TestConcurrentPausesOrder(t *testing.T) {
	e := newEnv(t)
	mine := e.pause(self, t0.Add(time.Second), time.Hour)
	theirs := e.pause(peer, t0, time.Hour)
	e.write(t0, mine, theirs)
	if h := e.eval(t0.Add(time.Second)).Holding(self); h == nil || h.ID != theirs.ID {
		t.Fatalf("the later initiator is not held by the earlier pause: %+v", h)
	}

	e2 := newEnv(t)
	mine = e2.pause(self, t0, time.Hour)
	theirs = e2.pause(peer, t0.Add(time.Second), time.Hour)
	e2.write(t0, mine, theirs)
	if h := e2.eval(t0.Add(time.Second)).Holding(self); h != nil {
		t.Fatalf("the earlier initiator is held by a later pause: %+v", h)
	}
}

// Garbage on the ref never fails an evaluation and never grows the report
// without bound.
func TestReadBounded(t *testing.T) {
	e := newEnv(t)
	var changes []store.Change
	for i := 0; i < 100; i++ {
		changes = append(changes, store.Change{Path: model.SourcePath(fmt.Sprintf("p-%012x.json", i)), Blob: []byte("{\"x\":\"\x1b[31m\"}"), Mode: 0o100644})
	}
	changes = append(changes,
		store.Change{Path: "notes/\x1b]0;hi\x07.json", Blob: []byte("x"), Mode: 0o100644},
		store.Change{Path: "p-aaaaaaaaaaaa.json", Blob: []byte(strings.Repeat(" ", 5000) + "{}"), Mode: 0o100644},
	)
	c, err := e.repo.CommitPaths(e.ctx, "", changes, store.Message{Subject: "junk"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.repo.UpdateRef(e.ctx, RemoteRef, c, ""); err != nil {
		t.Fatal(err)
	}
	v := e.eval(t0)
	if len(v.Ignored) == 0 || len(v.Ignored) > maxIgnored || v.Holding(self) != nil {
		t.Fatalf("view: %d ignored, held %v", len(v.Ignored), v.Holding(self))
	}
	for _, x := range v.Ignored {
		if model.HasControl(x.ID) || model.HasControl(x.Why) || model.HasControl(string(x.Signer)) {
			t.Fatalf("control character in report: %q", x)
		}
	}

	// A ref that names a blob reads as no records.
	blob := e.git("hash-object", "-w", "--stdin")
	e.git("update-ref", Ref, blob)
	if _, err := Evaluate(e.ctx, e.repo, e.state, self, e.trust(t0), t0, true); err != nil {
		t.Fatalf("a blob ref failed the evaluation: %v", err)
	}
}

// A pause record never replaces a resume of the same pause, and a write
// that changes nothing makes no commit.
func TestWriteKeepsResume(t *testing.T) {
	e := newEnv(t)
	p := e.pause(peer, t0, time.Hour)
	e.write(t0, p)
	head, _ := e.repo.ResolveRef(e.ctx, Ref)
	e.write(t0, p)
	if again, _ := e.repo.ResolveRef(e.ctx, Ref); again != head {
		t.Fatal("an unchanged write made a commit")
	}
	r := p
	r.Op = OpResume
	r, err := Sign(r, e.ids[self])
	if err != nil {
		t.Fatal(err)
	}
	e.write(t0, r)
	ext := p
	ext.Deadline = t0.Add(2 * time.Hour)
	if ext, err = Sign(ext, e.ids[peer]); err != nil {
		t.Fatal(err)
	}
	e.write(t0, ext)
	recs, _, err := Read(e.ctx, e.repo)
	if err != nil || len(recs) != 1 || recs[0].Op != OpResume {
		t.Fatalf("records after a pause over a resume: %+v %v", recs, err)
	}
}

// A record whose push failed is carried onto a remote ref that moved.
func TestRestageCarriesUnpushed(t *testing.T) {
	e := newEnv(t)
	theirs := e.pause(peer, t0, time.Hour)
	e.write(t0, theirs)
	remote, _ := e.repo.ResolveRef(e.ctx, Ref)
	e.git("update-ref", "-d", Ref)
	mine := e.pause(self, t0, time.Hour)
	e.write(t0, mine) // no remote yet: a root commit, never pushed
	if err := e.repo.UpdateRef(e.ctx, RemoteRef, remote, ""); err != nil {
		t.Fatal(err)
	}
	if spec, _ := Spec(e.ctx, e.repo); spec != "" {
		t.Fatalf("diverged ref pushed as is: %q", spec)
	}
	if err := Restage(e.ctx, e.repo, t0); err != nil {
		t.Fatal(err)
	}
	if spec, _ := Spec(e.ctx, e.repo); spec == "" {
		t.Fatal("restaged ref has nothing to push")
	}
	local, _ := e.repo.ResolveRef(e.ctx, Ref)
	ents, err := e.repo.ListTree(e.ctx, local)
	if err != nil || len(ents) != 2 {
		t.Fatalf("restaged tree: %+v %v", ents, err)
	}
}

// A record from a fleet machine counts; a pinned member's signature makes
// it verified, a failing one makes it forged; a machine outside fleet.toml
// is refused; with RequireMember an unverified record is refused.
func TestTrust(t *testing.T) {
	e := newEnv(t)
	tr := e.trust(t0)
	p := e.pause(peer, t0, time.Hour)
	if ok, err := tr.Verify(p); err != nil || !ok {
		t.Fatalf("member signature: %v %v", ok, err)
	}
	unsigned := p
	unsigned.Sig = nil
	if ok, err := tr.Verify(unsigned); err != nil || ok {
		t.Fatalf("unsigned record: %v %v", ok, err)
	}
	other, err := crypt.GenerateIdentity(peer)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := Sign(Record{Op: OpPause, ID: p.ID, Initiator: peer, Created: t0, Deadline: t0.Add(time.Hour)}, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Verify(forged); !errors.Is(err, ErrForged) {
		t.Fatalf("forged signature: %v", err)
	}
	noLog := Trust{Fleet: tr.Fleet, Members: map[model.MachineID][]crypt.Member{}}
	if ok, err := noLog.Verify(forged); err != nil || ok {
		t.Fatalf("a signer no pinned log lists: %v %v", ok, err)
	}
	stranger, err := crypt.GenerateIdentity("m-stranger")
	if err != nil {
		t.Fatal(err)
	}
	e.ids["m-stranger"] = stranger
	if _, err := tr.Verify(e.pause("m-stranger", t0, time.Hour)); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("a machine outside fleet.toml: %v", err)
	}
	strict := tr
	strict.RequireMember = true
	if _, err := strict.Verify(unsigned); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("unverified with RequireMember: %v", err)
	}
	if strict.Can(self, other.Member().SignKey) || !strict.Can(self, e.ids[self].Member().SignKey) || !tr.Can(self, "") {
		t.Fatal("Can")
	}
}

// An unverified record never extends a verified pause.
func TestUnverifiedExtension(t *testing.T) {
	e := newEnv(t)
	p := e.pause(peer, t0, 30*time.Minute)
	e.write(t0, p)
	if h := e.eval(t0).Holding(self); h == nil || !h.Verified {
		t.Fatalf("verified pause: %+v", h)
	}
	ext := p
	ext.Deadline, ext.Sig = t0.Add(3*time.Hour), nil
	e.write(t0, ext)
	v := e.eval(t0)
	if h := v.Holding(self); h == nil || !h.Until.Equal(t0.Add(30*time.Minute)) || len(v.Ignored) != 1 {
		t.Fatalf("unverified extension: %+v %+v", h, v.Ignored)
	}
}
