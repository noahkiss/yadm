package sync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
	"github.com/noahkiss/yadm/internal/store"
)

func capture(paths ...string) apply.Capture {
	c := apply.Capture{Scopes: map[model.Target]model.Scope{}}
	for _, p := range paths {
		t := model.Target(strings.TrimPrefix(p, "-"))
		c.Paths = append(c.Paths, t)
		c.Changes = append(c.Changes, store.Change{Path: model.SourcePath("files/" + string(t)), Blob: []byte("x"), Delete: strings.HasPrefix(p, "-")})
		c.Scopes[t] = model.ScopeShared
	}
	return c
}

func TestPlanCommitsPolicy(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	st := &apply.State{Targets: map[model.Target]apply.TargetState{
		"old":    {ChangedAt: now.Add(-3 * time.Hour)},
		"fresh":  {ChangedAt: now.Add(-time.Minute)},
		"leased": {ChangedAt: now.Add(-3 * time.Hour)},
		"rev":    {ChangedAt: now.Add(-3 * time.Hour)},
		"gone":   {ChangedAt: now.Add(-3 * time.Hour)},
		"zero":   {ChangedAt: now.Add(-time.Second)},
		"conf":   {ChangedAt: now.Add(-3 * time.Hour)},
	}, Holds: []model.Hold{{Target: "conf", Reason: model.HoldConflict}}}
	p := Policy{
		Quiet:   DefaultQuiet,
		Protect: func(t model.Target) bool { return t == "rev" },
		QuietFor: func(t model.Target) (time.Duration, bool) {
			return 0, t == "zero"
		},
		Host: "host-a",
	}
	leases := []Lease{{Holder: "agent", Paths: []string{"leased"}, Expires: now.Add(time.Hour)}, {Holder: "old", Paths: []string{"old"}, Expires: now.Add(-time.Hour)}}
	planned, holds, err := PlanCommits(capture("old", "fresh", "leased", "rev", "-gone", "zero", "conf"), st, p, leases, "m-x", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(planned) != 1 || fmt.Sprint(planned[0].Targets) != "[old zero]" {
		t.Fatalf("planned %+v", planned)
	}
	m := planned[0].Message
	if m.Subject != "auto(host-a): 2 files [shared]" || trailer(m, store.TrailerAuto) != "1" || trailer(m, store.TrailerScope) != "shared" || trailer(m, store.TrailerMachine) != "m-x" {
		t.Errorf("message %+v", m)
	}
	got := map[model.Target]model.HoldReason{}
	for _, h := range holds {
		got[h.Target] = h.Reason
		if h.ID == "" || h.Since.IsZero() {
			t.Errorf("hold without id or since: %+v", h)
		}
	}
	if len(got) != 2 || got["rev"] != model.HoldProtected || got["gone"] != model.HoldProtected {
		t.Errorf("holds %+v", holds)
	}
}

func TestPlanCommitsMassChangeAndBuiltins(t *testing.T) {
	now := time.Now()
	var paths []string
	for i := 0; i < 4; i++ {
		paths = append(paths, fmt.Sprintf("f%d", i))
	}
	_, holds, err := PlanCommits(capture(paths...), &apply.State{}, Policy{MassChange: 3}, nil, "m", now)
	if err != nil || len(holds) != 4 {
		t.Fatalf("mass change: %v %+v", err, holds)
	}
	c := capture("ok")
	c.Changes[0].Path = "keys/personal/2.toml"
	planned, holds, _ := PlanCommits(c, &apply.State{}, Policy{}, nil, "m", now)
	if len(planned) != 0 || len(holds) != 1 {
		t.Errorf("keys/** not protected: %+v %+v", planned, holds)
	}
}

func TestUnionLines(t *testing.T) {
	base := "a\nb\nc\n"
	got := string(unionLines([]byte(base), []byte("a\nc\nd\n"), []byte("a\nb\nc\ne\n")))
	if got != "a\nc\nd\ne\n" {
		t.Errorf("union = %q", got)
	}
}

func TestLeasesExpire(t *testing.T) {
	dir := t.TempDir()
	l := FileLeases(dir)
	if err := l.Take(Lease{Holder: "agent-1", Paths: []string{".config/**"}}); err == nil {
		t.Error("a lease without expiry was accepted")
	}
	if err := l.Take(Lease{Holder: "agent-1", Paths: []string{".config/**"}, Expires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := l.Take(Lease{Holder: "agent-2", Paths: []string{"x"}, Expires: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	ls, err := l.List()
	if err != nil || len(ls) != 1 || ls[0].Holder != "agent-1" {
		t.Fatalf("list %+v %v", ls, err)
	}
	if !leased(ls, ".config/app/x", time.Now()) || leased(ls, ".zshrc", time.Now()) {
		t.Error("lease matching")
	}
	if err := l.Release("agent-1"); err != nil {
		t.Fatal(err)
	}
	if ls, _ := l.List(); len(ls) != 0 {
		t.Errorf("after release %+v", ls)
	}
}

func TestLockTimesOut(t *testing.T) {
	dir := t.TempDir()
	rel, err := FileLock(dir).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := FileLockTimeout(dir, 150*time.Millisecond).Acquire(context.Background()); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("lock wait was not bounded")
	}
	rel()
	rel2, err := FileLockTimeout(dir, time.Second).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rel2()
}

func TestSyncerRefusesUnwiredDeps(t *testing.T) {
	var s Syncer
	if _, err := s.Run(context.Background(), Options{}); err == nil {
		t.Error("an empty Syncer ran")
	}
}

func TestUnionPolicyResolvesListConflict(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	for _, m := range w.machines {
		m.s.Policy.MergeFor = func(t model.Target) MergePolicy {
			if t == pkgList {
				return MergeUnion
			}
			return ""
		}
	}
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	A.write(pkgList, "tool-one\ntool-two\ntool-a\n")
	A.sync()
	B.write(pkgList, "tool-one\ntool-two\ntool-b\n")
	r := B.sync()
	if len(holdsOf(r, model.HoldConflict)) != 0 || !hasTrailerResolved(r, RungUnion) {
		t.Fatalf("union: %+v", r)
	}
	if got := w.remoteFile("files/.config/packages/list"); got != "tool-one\ntool-two\ntool-b\ntool-a" {
		t.Errorf("remote list %q", got)
	}
	msg := git(t, w.remote, "log", "-1", "--format=%B", "main")
	if !strings.Contains(msg, TrailerResolved+": union files/.config/packages/list") {
		t.Errorf("no resolution trailer:\n%s", msg)
	}
}

func TestManualCommitAndReview(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	ctx := context.Background()
	w.clock.offset = 0 // inside the quiet period: only a manual commit lands

	notes := model.Target(".config/notes/private.md")
	edit := secrecytest.NewCanary(t, "review-edit")
	A.write(notes, A.read(notes)+edit.String()+"\n")
	A.write(aliases, "alias ll=\"ls\"\n")
	r, err := A.s.Commit(ctx, CommitOptions{Message: "tidy notes", Paths: []model.Target{notes}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Committed) != 1 {
		t.Fatalf("manual commit: %+v", r)
	}
	msg := git(t, A.repo.Dir(), "log", "-1", "--format=%B", "main")
	if !strings.HasPrefix(msg, "tidy notes") || strings.Contains(msg, "Yadm-Auto") || !strings.Contains(msg, "Yadm-Scope: personal") {
		t.Errorf("manual message:\n%s", msg)
	}
	if strings.Contains(git(t, A.repo.Dir(), "show", "--stat", "main"), "aliases") {
		t.Error("an unnamed path was swept into the commit")
	}
	A.sync()
	B.sync()

	// A member reviews in plaintext; a non-member sees only that it changed.
	items, err := Unreviewed(ctx, A.st, keysOf(t, A), "personal")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 || !strings.Contains(items[len(items)-1].Diff, edit.String()) {
		t.Fatalf("member review %+v", items)
	}
	items, err = Unreviewed(ctx, B.st, nil, "personal")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) == 0 || strings.Contains(items[len(items)-1].Diff, edit.String()) || !strings.Contains(items[len(items)-1].Diff, "not a member") {
		t.Fatalf("non-member review %+v", items)
	}
	last := items[len(items)-1].Commit.ID
	if err := Ack(ctx, B.st, "personal", last); err != nil {
		t.Fatal(err)
	}
	if items, _ := Unreviewed(ctx, B.st, nil, "personal"); len(items) != 0 {
		t.Errorf("still unreviewed after ack: %d", len(items))
	}
	if err := Ack(ctx, B.st, "personal", items0Parent(t, B, last)); err == nil {
		t.Error("ack moved the reviewed ref back")
	}
	// The reviewed ref travels with the next sync.
	B.sync()
	if got := git(t, w.remote, "rev-parse", store.RefReviewed("personal")); got != string(last) {
		t.Errorf("remote reviewed ref %s, want %s", got, last)
	}
	A.sync()
	if items, _ := Unreviewed(ctx, A.st, nil, "personal"); len(items) != 0 {
		t.Errorf("A still sees %d unreviewed after B's ack", len(items))
	}
}

func items0Parent(t *testing.T, m *machine, id model.CommitID) model.CommitID {
	return model.CommitID(git(t, m.repo.Dir(), "rev-parse", string(id)+"^"))
}

func keysOf(t *testing.T, m *machine) *crypt.Set {
	snap, err := m.eng.Load(context.Background(), m.main())
	if err != nil {
		t.Fatal(err)
	}
	return snap.Keys
}
