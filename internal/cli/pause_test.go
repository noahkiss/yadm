package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/pause"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

// fakeClock is a controllable hooks.now.
type fakeClock struct {
	mu gosync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// pauseFleet sets up host-a (member of personal), host-b (no enclave) and
// host-c (member of client). No machine pins another enclave's key log: a
// pause trusts the fleet.toml machines under the keys their status records
// published. Every machine has applied and synced, so each pins the others.
func pauseFleet(t *testing.T) (root, remote string, fx *fixture.Fixture, clk *fakeClock, m map[model.MachineID]machineDirs) {
	t.Helper()
	hermetic(t)
	root = t.TempDir()
	fx = fixture.Build(t)
	remote = fixtureRemote(t, root, fx)
	bin := t.TempDir()
	writeFile(t, filepath.Join(bin, "secret-check"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true}'\n")
	if err := os.Chmod(filepath.Join(bin, "secret-check"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	clk = &fakeClock{t: time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)}
	hooks.now = clk.Now
	hooks.sleep = func(context.Context, time.Duration) error { clk.Add(3 * time.Second); return nil }
	m = map[model.MachineID]machineDirs{}
	for _, id := range []model.MachineID{fixture.HostA, fixture.HostB, fixture.HostC} {
		d := fixtureMachine(t, root, remote, fx, id, true)
		yadmOK(t, "task", "allow")
		yadmOK(t, "apply")
		yadmOK(t, "sync", "--full")
		m[id] = d
	}
	return root, remote, fx, clk, m
}

func on(t *testing.T, root string, id model.MachineID) {
	t.Helper()
	useMachine(t, root, string(id))
}

type syncOut struct {
	Paused    bool             `json:"paused"`
	Reason    string           `json:"reason"`
	Committed []model.CommitID `json:"committed"`
	Applied   model.CommitID   `json:"applied"`
}

func selfStatus(t *testing.T, id model.MachineID) model.Status {
	t.Helper()
	env := yadmOK(t, "fleet", "show", string(id))
	return *decode[struct {
		Status *model.Status `json:"status"`
	}](t, env.Data).Status
}

// TestPauseFleet: host-a pauses; host-b and host-c confirm through their
// status records and refuse commit and apply; host-a's own commit lands but
// no peer applies it; an extension works up to the 4h cap and a 24h request
// is clamped; at the deadline host-b resumes by its own clock and applies.
func TestPauseFleet(t *testing.T) {
	root, remote, fx, clk, m := pauseFleet(t)
	t0 := clk.Now()
	shared := ".config/shell/aliases.sh"

	on(t, root, fixture.HostA)
	env := yadmOK(t, "pause", "--for", "30m", "--reason", "rename shell config", "--no-wait")
	d := decode[pauseData](t, env.Data)
	if !d.Pushed || d.Initiator != fixture.HostA || !d.Until.Equal(t0.Add(30*time.Minute)) || len(d.Waiting) != 2 || len(d.Confirmed) != 0 {
		t.Fatalf("pause: %+v", d)
	}
	id := d.ID

	// Waiting with no peer confirmed: progress on stderr, then success.
	out, errOut, code := yadmRaw(t, "pause", "--wait", "10s")
	if code != ExitOK || !strings.Contains(errOut, "waiting… 0/2 confirmed (host-b, host-c not yet)") || !strings.Contains(out, "0/2 confirmed") {
		t.Fatalf("pause wait: exit %d\nstdout %s\nstderr %s", code, out, errOut)
	}

	// host-b's timer tick sees the pause ref move; host-c syncs by hand.
	// Both confirm it.
	for _, p := range []model.MachineID{fixture.HostB, fixture.HostC} {
		on(t, root, p)
		args := []string{"sync", "--full"}
		if p == fixture.HostB {
			args = []string{"sync", "--auto"}
		}
		s := decode[syncOut](t, yadmOK(t, args...).Data)
		if !s.Paused || (p == fixture.HostB && s.Reason != "remote moved") {
			t.Fatalf("%s sync not paused: %+v", p, s)
		}
		st := selfStatus(t, p)
		if st.PauseID != id || st.PausedUntil == nil || !st.PausedUntil.Equal(t0.Add(30*time.Minute)) {
			t.Fatalf("%s status does not confirm: %+v", p, st)
		}
	}

	// host-b refuses a manual commit and apply, naming who, why and until.
	on(t, root, fixture.HostB)
	writeFile(t, filepath.Join(m[fixture.HostB].Home, shared), "# edited on host-b during the pause\n")
	for _, args := range [][]string{{"commit", shared}, {"apply"}, {"capture"}} {
		env, code, _ := yadm(t, args...)
		if code != ExitLocked || env.Error.Code != CodeLocked || !strings.Contains(env.Error.Message, "host-a") || !strings.Contains(env.Error.Message, "rename shell config") || !strings.Contains(env.Error.Message, "2030-01-01T12:30:00Z") {
			t.Fatalf("%v while paused: exit %d %+v", args, code, env.Error)
		}
	}
	// The timer neither captures nor commits it.
	clk.Add(time.Minute)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--auto", "--full").Data); !s.Paused || len(s.Committed) != 0 {
		t.Fatalf("auto sync while paused: %+v", s)
	}
	if _, code, _ := yadm(t, "apply", "--dry-run"); code != ExitOK && code != ExitAttention {
		t.Fatalf("apply --dry-run while paused: exit %d", code)
	}
	if ps := decode[statusData](t, yadmOK(t, "status").Data).Pause; ps == nil || ps.Held == nil || ps.Held.ID != id {
		t.Fatalf("status on host-b: %+v", ps)
	}

	// host-a waits for confirmations: both are in.
	on(t, root, fixture.HostA)
	env = yadmOK(t, "pause", "--wait", "10s")
	d = decode[pauseData](t, env.Data)
	if d.ID != id || len(d.Confirmed) != 2 || len(d.Waiting) != 0 {
		t.Fatalf("wait: %+v", d)
	}
	if out, _, _ := yadmRaw(t, "pause", "--wait", "10s"); !strings.Contains(out, "fleet-wide until") {
		t.Fatalf("pause text: %q", out)
	}
	if ps := decode[statusData](t, yadmOK(t, "status").Data).Pause; ps == nil || ps.Own == nil || ps.Held != nil || ps.Confirmations == nil || len(ps.Confirmations.Confirmed) != 2 {
		t.Fatalf("status on host-a: %+v", ps)
	}
	if out, _, _ := yadmRaw(t, "fleet", "list"); strings.Count(out, "paused until") < 2 {
		t.Fatalf("fleet list does not show the pause:\n%s", out)
	}

	// The initiator's commit lands.
	writeFile(t, filepath.Join(m[fixture.HostA].Home, shared), "# the global change\n")
	env = yadmOK(t, "commit", "-m", "the global change", shared)
	if c := decode[map[string]any](t, env.Data); c["pushed"] != true {
		t.Fatalf("initiator commit: %+v", c)
	}

	// Extend: 20 minutes in, ask for 1h more; then ask for 24h, which is
	// clamped to 4h after the pause began.
	clk.Add(20 * time.Minute)
	d = decode[pauseData](t, yadmOK(t, "pause", "--for", "1h", "--no-wait").Data)
	if d.ID != id || !d.Extended || !d.Until.Equal(clk.Now().Add(time.Hour)) || d.Clamped {
		t.Fatalf("extend: %+v", d)
	}
	d = decode[pauseData](t, yadmOK(t, "pause", "--for", "24h", "--no-wait").Data)
	if d.ID != id || !d.Until.Equal(t0.Add(pause.MaxSpan)) || !d.Clamped {
		t.Fatalf("extend past the cap: %+v", d)
	}

	// host-b sees the extension and still does not apply host-a's commit.
	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-b after extend: %+v", s)
	}
	if st := selfStatus(t, fixture.HostB); st.PausedUntil == nil || !st.PausedUntil.Equal(t0.Add(pause.MaxSpan)) {
		t.Fatalf("host-b status after extend: %+v", st)
	}
	if got := readFile(t, filepath.Join(m[fixture.HostB].Home, shared)); strings.Contains(got, "global change") {
		t.Fatal("host-b applied during the pause")
	}

	// A minute before the deadline the timer still holds; once the
	// deadline passes, the quick check runs in full by itself.
	clk.Add(t0.Add(pause.MaxSpan).Sub(clk.Now()) - time.Minute)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--auto").Data); !s.Paused {
		t.Fatalf("host-b before the deadline: %+v", s)
	}
	clk.Add(2 * time.Minute)
	s := decode[syncOut](t, yadmOK(t, "sync", "--auto").Data)
	if s.Paused || s.Reason != "pause ended" {
		t.Fatalf("host-b after the deadline: %+v", s)
	}
	if st := selfStatus(t, fixture.HostB); st.PausedUntil != nil || st.PauseID != "" {
		t.Fatalf("host-b status still paused: %+v", st)
	}
	// host-b's own edit conflicts with host-a's change; either way the
	// commit is no longer refused for the pause.
	if env, code, _ := yadm(t, "commit", shared); code == ExitLocked {
		t.Fatalf("commit after the deadline refused: %+v", env.Error)
	}
	// host-c, with no edit of its own, applies the initiator's change.
	on(t, root, fixture.HostC)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("host-c after the deadline: %+v", s)
	}
	if got := readFile(t, filepath.Join(m[fixture.HostC].Home, shared)); !strings.Contains(got, "global change") {
		t.Fatalf("host-c did not apply the change made during the pause: %q", got)
	}

	for _, repo := range []string{remote, m[fixture.HostB].Source, m[fixture.HostC].Source} {
		secrecytest.AssertRepoClean(t, repo, fx.AllCanaries()...)
	}
}

// TestPauseResumeAndOffline: a signed resume lifts a pause early; a machine
// that was offline for a whole pause ignores the expired record.
func TestPauseResumeAndOffline(t *testing.T) {
	root, _, _, clk, _ := pauseFleet(t)

	on(t, root, fixture.HostA)
	id := decode[pauseData](t, yadmOK(t, "pause", "--no-wait").Data).ID
	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-b not paused: %+v", s)
	}
	on(t, root, fixture.HostA)
	if d := decode[pauseData](t, yadmOK(t, "resume").Data); d.ID != id || !d.Resumed || !d.Pushed {
		t.Fatalf("resume: %+v", d)
	}
	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--auto").Data); s.Paused || s.Reason != "remote moved" {
		t.Fatalf("host-b timer tick after resume: %+v", s)
	}
	if _, code, _ := yadm(t, "apply"); code == ExitLocked {
		t.Fatal("apply refused after resume")
	}

	// A second pause runs its full course while host-c is offline.
	on(t, root, fixture.HostA)
	id2 := decode[pauseData](t, yadmOK(t, "pause", "--for", "30m", "--no-wait").Data).ID
	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-b not paused by the second pause: %+v", s)
	}
	clk.Add(time.Hour)
	on(t, root, fixture.HostC)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("host-c woke after the pause and was held: %+v", s)
	}
	if b, err := os.ReadFile(filepath.Join(useMachineState(t, root, fixture.HostC), pause.StateFile)); err == nil && strings.Contains(string(b), id2) {
		t.Fatalf("host-c recorded the expired pause: %s", b)
	}
	if st := selfStatus(t, fixture.HostC); st.PausedUntil != nil {
		t.Fatalf("host-c status paused: %+v", st)
	}
	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("host-b held past the deadline: %+v", s)
	}
}

func useMachineState(t *testing.T, root string, id model.MachineID) string {
	t.Helper()
	return useMachine(t, root, string(id)).State
}

// TestPauseForged: host-b pins personal's key log, so it can verify
// host-a. A writer pushes a record whose signature fails under host-a's
// pinned key, and one from a machine that is not in fleet.toml: host-b
// ignores both and check fails. A record host-a did sign that asks for 24h
// holds host-b at most 4h, verified; a forged resume does not lift it. One
// whose creation time lies in the future holds for its own span from when
// host-b first saw it.
func TestPauseForged(t *testing.T) {
	root, remote, fx, clk, m := pauseFleet(t)
	ctx := context.Background()
	now := clk.Now()

	on(t, root, fixture.HostB)
	b := m[fixture.HostB]
	pin, err := crypt.PinOf(fx.Logs["personal"][len(fx.Logs["personal"])-1])
	if err != nil {
		t.Fatal(err)
	}
	if err := crypt.FilePins(b.State).Set("personal", pin); err != nil {
		t.Fatal(err)
	}
	repo, err := store.Open(b.Source, b.State)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	newID := func() string {
		id, err := pause.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	rec := func(by model.MachineID) pause.Record {
		return pause.Record{Schema: pause.Schema, Op: pause.OpPause, ID: newID(), Initiator: by, Signer: by, Created: now, Deadline: now.Add(time.Hour)}
	}
	forged, err := pause.Sign(rec(fixture.HostB), fx.Identities[fixture.HostB])
	if err != nil {
		t.Fatal(err)
	}
	forged.Initiator, forged.Signer = fixture.HostA, fixture.HostA // host-b's key, host-a's name
	strangerID, err := crypt.GenerateIdentity("m-stranger")
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := pause.Sign(rec("m-stranger"), strangerID)
	if err != nil {
		t.Fatal(err)
	}
	push := func(recs ...pause.Record) {
		t.Helper()
		if _, err := pause.Write(ctx, repo, recs, clk.Now()); err != nil {
			t.Fatal(err)
		}
		git(t, b.Source, "push", "-q", remote, pause.Ref+":"+pause.Ref)
	}
	push(forged, stranger)

	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("host-b honoured a forged pause: %+v", s)
	}
	env, code, _ := yadm(t, "check")
	if code != ExitError {
		t.Fatalf("check with forged pauses: exit %d", code)
	}
	var detail string
	for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
		if c.Name == "pause" {
			detail = c.Detail
			if c.OK {
				t.Fatalf("pause check passed: %+v", c)
			}
		}
	}
	for _, r := range []pause.Record{forged, stranger} {
		if !strings.Contains(detail, r.ID) {
			t.Fatalf("check does not name %s: %s", r.ID, detail)
		}
	}
	if !strings.Contains(detail, "forged") || !strings.Contains(detail, "m-stranger") || !strings.Contains(detail, "fleet.toml") {
		t.Fatalf("check does not explain the ignored records: %s", detail)
	}
	if st := selfStatus(t, fixture.HostB); len(st.PauseIgnored) != 2 {
		t.Fatalf("host-b status does not report the ignored records: %+v", st.PauseIgnored)
	}
	on(t, root, fixture.HostA)
	if _, code, _ := yadm(t, "commit"); code == ExitLocked {
		t.Fatal("host-a held by a forged pause")
	}

	// host-a's key signs a 24h pause directly (a buggy or old client): host-b
	// clamps it to 4h and marks it verified.
	on(t, root, fixture.HostB)
	long := rec(fixture.HostA)
	long.Deadline = now.Add(24 * time.Hour)
	if long, err = pause.Sign(long, fx.Identities[fixture.HostA]); err != nil {
		t.Fatal(err)
	}
	push(long)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-b ignored a signed pause: %+v", s)
	}
	if st := selfStatus(t, fixture.HostB); st.PausedUntil == nil || !st.PausedUntil.Equal(now.Add(pause.MaxSpan)) || !st.PauseVerified {
		t.Fatalf("24h pause not clamped or not verified: %+v", st)
	}
	on(t, root, fixture.HostA)
	yadmOK(t, "sync", "--full") // host-a records its own pause
	// A resume whose signature fails under host-a's key does not lift it;
	// host-a's signed resume does.
	on(t, root, fixture.HostB)
	fakeResume := long
	fakeResume.Op = pause.OpResume
	if fakeResume, err = pause.Sign(fakeResume, fx.Identities[fixture.HostB]); err != nil {
		t.Fatal(err)
	}
	fakeResume.Signer = fixture.HostA
	push(fakeResume)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("a forged resume lifted the pause: %+v", s)
	}
	on(t, root, fixture.HostA)
	yadmOK(t, "resume", long.ID)
	on(t, root, fixture.HostB)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("signed resume did not lift: %+v", s)
	}
	// Replaying the original signed pause does not hold host-b again.
	git(t, b.Source, "fetch", "-q", remote, "+"+pause.Ref+":"+pause.RemoteRef)
	git(t, b.Source, "update-ref", pause.Ref, strings.TrimSpace(git(t, b.Source, "rev-parse", pause.RemoteRef)))
	p, err := pause.Sign(long, fx.Identities[fixture.HostA])
	if err != nil {
		t.Fatal(err)
	}
	c, err := repo.CommitPaths(ctx, model.CommitID(strings.TrimSpace(git(t, b.Source, "rev-parse", pause.Ref))), []store.Change{{Path: model.SourcePath(p.ID + ".json"), Blob: recordJSON(t, p), Mode: 0o100644}}, store.Message{Subject: "replay"})
	if err != nil {
		t.Fatal(err)
	}
	git(t, b.Source, "push", "-q", remote, string(c)+":"+pause.Ref)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("a replayed pause held host-b again: %+v", s)
	}

	// A signed 2h pause created 48h in the future (a skewed clock) holds
	// 2h from when host-b first saw it.
	skew := rec(fixture.HostA)
	skew.Created, skew.Deadline = now.Add(48*time.Hour), now.Add(50*time.Hour)
	if skew, err = pause.Sign(skew, fx.Identities[fixture.HostA]); err != nil {
		t.Fatal(err)
	}
	push(skew)
	seen := clk.Now()
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-b ignored the skewed pause: %+v", s)
	}
	if st := selfStatus(t, fixture.HostB); st.PausedUntil == nil || !st.PausedUntil.Equal(seen.Add(2*time.Hour)) {
		t.Fatalf("skewed pause not clamped to its span: %+v", st.PausedUntil)
	}
	clk.Add(pause.MaxSpan + time.Minute)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("skewed pause held past first sight + its span: %+v", s)
	}
	// A day later the record still sits on the ref with its future
	// deadline; it does not hold host-b a second time.
	for i := 0; i < 3; i++ {
		clk.Add(15 * time.Hour)
		if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
			t.Fatalf("skewed pause held again %dh later: %+v", 15*(i+1), s)
		}
	}
}

func recordJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// TestPauseUnverifiedAndSwitch: host-b, in no enclave, pauses; host-a
// honours it as unverified and may resume it. With pause_requires =
// "member" in fleet.toml, host-b may not pause, and host-a ignores an
// unverified record.
func TestPauseUnverifiedAndSwitch(t *testing.T) {
	root, remote, _, clk, m := pauseFleet(t)
	ctx := context.Background()

	on(t, root, fixture.HostB)
	id := decode[pauseData](t, yadmOK(t, "pause", "--no-wait").Data).ID
	on(t, root, fixture.HostA)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); !s.Paused {
		t.Fatalf("host-a ignored a pause from a machine in no enclave: %+v", s)
	}
	if ps := decode[statusData](t, yadmOK(t, "status").Data).Pause; ps == nil || ps.Held == nil || ps.Held.Verified {
		t.Fatalf("host-a status: %+v", ps)
	}
	if st := selfStatus(t, fixture.HostA); st.PauseID != id || st.PauseVerified {
		t.Fatalf("host-a status record: %+v", st)
	}
	env, _, _ := yadm(t, "check")
	for _, c := range decode[map[string][]checkItem](t, env.Data)["checks"] {
		if c.Name == "pause" && (!c.OK || !c.Warn || !strings.Contains(c.Detail, "unverified")) {
			t.Fatalf("pause check while held unverified: %+v", c)
		}
	}
	if out, _, _ := yadmRaw(t, "fleet", "list"); !strings.Contains(out, "(unverified)") {
		t.Fatalf("fleet list does not mark the pause unverified:\n%s", out)
	}
	if _, code, _ := yadm(t, "commit"); code != ExitLocked {
		t.Fatalf("host-a commit while host-b paused: exit %d", code)
	}
	yadmOK(t, "resume", id) // any fleet machine may resume
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("host-a still held after its resume: %+v", s)
	}

	// Turn the switch on.
	a := m[fixture.HostA]
	fl := filepath.Join(a.Source, "fleet.toml")
	writeFile(t, fl, strings.Replace(readFile(t, fl), "schema = 1\n", "schema = 1\npause_requires = \"member\"\n", 1))
	git(t, a.Source, "commit", "-q", "-am", "chore: require a member's signature on a pause")
	yadmOK(t, "sync", "--full")
	on(t, root, fixture.HostB)
	yadmOK(t, "sync", "--full")
	if _, code, _ := yadm(t, "pause", "--no-wait"); code != ExitRefused {
		t.Fatalf("pause by a non-member with the switch on: exit %d", code)
	}

	// A writer pushes host-b's signed record anyway: host-a ignores it.
	b := m[fixture.HostB]
	repo, err := store.Open(b.Source, b.State)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	pid, err := pause.NewID()
	if err != nil {
		t.Fatal(err)
	}
	now := clk.Now()
	r, err := pause.Sign(pause.Record{Op: pause.OpPause, ID: pid, Initiator: fixture.HostB, Created: now, Deadline: now.Add(time.Hour)}, useIdentity(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pause.Write(ctx, repo, []pause.Record{r}, now); err != nil {
		t.Fatal(err)
	}
	git(t, b.Source, "push", "-q", remote, pause.Ref+":"+pause.Ref)
	on(t, root, fixture.HostA)
	if s := decode[syncOut](t, yadmOK(t, "sync", "--full").Data); s.Paused {
		t.Fatalf("host-a honoured an unverified pause with the switch on: %+v", s)
	}
	if st := selfStatus(t, fixture.HostA); len(st.PauseIgnored) != 1 || st.PauseIgnored[0].ID != pid {
		t.Fatalf("host-a does not report the unverified record: %+v", st.PauseIgnored)
	}
}

func useIdentity(t *testing.T, d machineDirs) *crypt.Identity {
	t.Helper()
	id, err := crypt.LoadIdentity(d.State)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
