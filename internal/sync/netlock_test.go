package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	gosync "sync"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
	"github.com/noahkiss/yadm/internal/tasks"
)

// stallStore blocks Fetch or Push until release is closed, and closes
// entered when the stalled call starts: a slow network.
type stallStore struct {
	store.Store
	fetch, push bool
	entered     chan struct{}
	release     chan struct{}
	once        gosync.Once
}

func newStall(s store.Store, fetch, push bool) *stallStore {
	return &stallStore{Store: s, fetch: fetch, push: push, entered: make(chan struct{}), release: make(chan struct{})}
}

func (s *stallStore) stall() {
	s.once.Do(func() {
		close(s.entered)
		<-s.release
	})
}

func (s *stallStore) Fetch(ctx context.Context) error {
	if s.fetch {
		s.stall()
	}
	return s.Store.Fetch(ctx)
}

func (s *stallStore) Push(ctx context.Context, specs []string) error {
	if s.push {
		s.stall()
	}
	return s.Store.Push(ctx, specs)
}

// twin is a second yadm process on machine m: its own store handle and
// apply engine over the same clone, $HOME and state directory. Its sync
// lock gives up after 300 ms, so a regression fails fast.
func (m *machine) twin() *Syncer {
	t := m.w.t
	t.Helper()
	repo, err := store.Open(m.repo.Dir(), m.state)
	if err != nil {
		t.Fatal(err)
	}
	runner := &tasks.Runner{Exec: m.exec, Allow: m.allows, Units: nopUnits{}}
	eng := apply.New(apply.Deps{Store: repo, Self: m.id, Identity: m.w.f.Identities[m.id], Pins: crypt.FilePins(m.state),
		State: apply.FileStateDB(m.state), Home: m.home, User: "user", StateDir: m.state, Tasks: runner, Allow: m.allows, Now: m.w.clock.Now})
	return &Syncer{Deps: Deps{Store: repo, Apply: eng, Status: store.StatusRefs(repo, m.id), Exec: m.exec,
		Identity: fleet.Identity{Machine: m.id}, Lock: FileLockTimeout(m.state, 300*time.Millisecond), Leases: FileLeases(m.state),
		Version: "test", Now: m.w.clock.Now, Backoff: time.Millisecond}}
}

// stalledSync starts m's sync over st in the background and waits until
// it is inside the stalled network call. done yields its result.
func stalledSync(t *testing.T, m *machine, st *stallStore) (done chan error) {
	t.Helper()
	m.s.Store = st
	done = make(chan error, 1)
	go func() {
		_, err := m.s.Run(context.Background(), Options{Auto: true, Push: true})
		done <- err
	}()
	select {
	case <-st.entered:
	case err := <-done:
		t.Fatalf("sync ended before the stall: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("sync never reached the network")
	}
	return done
}

// A local commit completes while another process's fetch or push hangs on
// the network: neither holds the sync lock.
func TestLocalCommitWhileNetworkStalls(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fetch, push bool
	}{{"fetch", true, false}, {"push", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			a := fixture.HostA
			w := newWorld(t, nil, a)
			w.syncAll(a)
			A := w.machines[a]
			orig := A.s.Store
			if tc.push {
				// Give the stalled sync something to push.
				A.write(pkgList, "tool-one\ntool-two\ntool-stalled\n")
			}
			st := newStall(orig, tc.fetch, tc.push)
			done := stalledSync(t, A, st)

			A.write(aliases, "alias ll=\"ls -la\"\nalias during=\"stall\"\n")
			rep, err := A.twin().Commit(context.Background(), CommitOptions{Paths: []model.Target{aliases}})
			if err != nil {
				close(st.release)
				<-done
				t.Fatalf("local commit during a stalled %s: %v", tc.name, err)
			}
			if len(rep.Committed) != 1 {
				t.Errorf("committed %v", rep.Committed)
			}
			// The twin also sees the network lock held, and says so.
			r2, err := A.twin().Run(context.Background(), Options{Push: true})
			if err != nil {
				t.Errorf("second sync during the stall: %v", err)
			} else if !strings.Contains(r2.Network, "skipped") || r2.Pushed {
				t.Errorf("second sync: network %q pushed %v", r2.Network, r2.Pushed)
			}
			close(st.release)
			if err := <-done; err != nil {
				t.Fatalf("stalled sync: %v", err)
			}
			A.s.Store = orig
			A.sync()
			if !strings.Contains(w.remoteFile("files/.config/shell/aliases.sh"), "during") {
				t.Error("the commit made during the stall never reached the remote")
			}
			if tc.push && !strings.Contains(w.remoteFile("files/.config/packages/list"), "tool-stalled") {
				t.Error("the stalled sync's own commit never reached the remote")
			}
		})
	}
}

// A held network lock makes sync skip its network steps without an error;
// the commit stays local and the next quick check runs in full.
func TestNetBusySkipsNetwork(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	w.syncAll(a)
	A := w.machines[a]
	release, err := FileNetLock(A.state).TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	before := w.remoteMain()
	A.write(aliases, "alias ll=\"ls -la\"\nalias busy=\"net\"\n")
	r := A.sync()
	if len(r.Committed) == 0 || r.Pushed {
		t.Fatalf("committed %v pushed %v", r.Committed, r.Pushed)
	}
	if !strings.Contains(r.Network, "fetch skipped") || !strings.Contains(r.Network, "push skipped") {
		t.Errorf("network note %q", r.Network)
	}
	if w.remoteMain() != before {
		t.Fatal("pushed while another process held the network lock")
	}

	// A manual commit with push says the push was deferred.
	A.write(pkgList, "tool-one\ntool-two\ntool-busy\n")
	_, err = A.s.Commit(context.Background(), CommitOptions{Paths: []model.Target{pkgList}, Push: true})
	var ee *ExchangeError
	if !errors.As(err, &ee) || !errors.Is(err, ErrPushDeferred) {
		t.Fatalf("commit with a busy network: %v", err)
	}

	// The quick check while the network is busy: unpushed commits trigger
	// a full run, whose network steps skip again.
	r, err = A.s.Run(context.Background(), Options{Quick: true, Push: true})
	if err != nil || r.Reason != "unpushed commits" || r.Pushed {
		t.Fatalf("quick sync: %v reason %q pushed %v", err, r.Reason, r.Pushed)
	}
	release()
	r, err = A.s.Run(context.Background(), Options{Quick: true, Push: true})
	if err != nil || !r.Pushed {
		t.Fatalf("after release: %v pushed %v", err, r.Pushed)
	}
	if !strings.Contains(w.remoteFile("files/.config/shell/aliases.sh"), "busy") ||
		!strings.Contains(w.remoteFile("files/.config/packages/list"), "tool-busy") {
		t.Error("the deferred commits did not land")
	}
}

// A push the remote rejects (it moved after the fetch) is not an error
// when no retry is left: the next tick fetches, replays and pushes.
func TestRejectedPushRecoversNextTick(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]

	A.write(aliases, "alias ll=\"ls -la\"\nalias gs=\"status-tool\"\nalias a=\"tool-a\"\n")
	B.write(pkgList, "tool-one\ntool-two\ntool-b\n")
	orig := B.s.Store
	B.s.Store = &racingStore{Store: orig, before: func() { A.sync() }}
	r, err := B.s.Run(context.Background(), Options{Auto: true, Push: true, MaxRetries: -1})
	if err != nil {
		t.Fatalf("rejected push is an error: %v", err)
	}
	if r.Pushed || r.Retries != 0 || !strings.Contains(r.Network, "rejected") {
		t.Fatalf("pushed %v retries %d network %q", r.Pushed, r.Retries, r.Network)
	}
	B.s.Store = orig
	r, err = B.s.Run(context.Background(), Options{Auto: true, Push: true, Quick: true})
	if err != nil || !r.Pushed || r.Reason != "unpushed commits" {
		t.Fatalf("next tick: %v pushed %v reason %q", err, r.Pushed, r.Reason)
	}
	if !strings.Contains(w.remoteFile("files/.config/shell/aliases.sh"), "tool-a") ||
		!strings.Contains(w.remoteFile("files/.config/packages/list"), "tool-b") {
		t.Error("a commit was lost")
	}
}

// Two machines syncing at the same time, several rounds each, converge.
func TestInterleavedSyncsConverge(t *testing.T) {
	a, b := fixture.HostA, fixture.HostB
	w := newWorld(t, nil, a, b)
	w.syncAll(a, b)
	A, B := w.machines[a], w.machines[b]
	const rounds = 3
	var wg gosync.WaitGroup
	errs := make(chan error, 2*rounds)
	run := func(m *machine, edit func(i int)) {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			edit(i)
			if _, err := m.s.Run(context.Background(), Options{Auto: true, Push: true}); err != nil {
				errs <- fmt.Errorf("%s round %d: %w", m.id, i, err)
			}
		}
	}
	wg.Add(2)
	go run(A, func(i int) { A.write(aliases, fmt.Sprintf("alias ll=\"ls -la\"\nalias a%d=\"x\"\n", i)) })
	go run(B, func(i int) { B.write(pkgList, fmt.Sprintf("tool-one\ntool-two\ntool-b%d\n", i)) })
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	w.syncAll(a, b, a)
	for _, m := range []*machine{A, B} {
		if got := m.read(aliases); !strings.Contains(got, "alias a2=") {
			t.Errorf("%s aliases = %q", m.id, got)
		}
		if got := m.read(pkgList); !strings.Contains(got, "tool-b2") {
			t.Errorf("%s list = %q", m.id, got)
		}
		if string(m.main()) != w.remoteMain() {
			t.Errorf("%s main %s, remote %s", m.id, m.main(), w.remoteMain())
		}
	}
}

// The locked error names the holder and its age; a record whose pid is
// dead is ignored.
func TestLockedErrorNamesHolder(t *testing.T) {
	dir := t.TempDir()
	release, err := FileLock(dir).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = FileLockTimeout(dir, 100*time.Millisecond).Acquire(context.Background())
	if !errors.Is(err, ErrLocked) || errors.Is(err, ErrNetBusy) {
		t.Fatalf("err = %v, want ErrLocked", err)
	}
	if msg := err.Error(); !strings.Contains(msg, fmt.Sprintf("pid %d", os.Getpid())) || !strings.Contains(msg, "held ") ||
		!strings.Contains(msg, filepath.Base(os.Args[0])) {
		t.Errorf("locked error %q does not name the holder", msg)
	}
	held := HeldLocks(dir)
	if len(held) != 1 || held[0].Lock != LockSync || held[0].Holder.PID != os.Getpid() {
		t.Errorf("held locks %+v", held)
	}

	nrel, err := FileNetLock(dir).TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FileNetLock(dir).TryAcquire(); !errors.Is(err, ErrNetBusy) || errors.Is(err, ErrLocked) {
		t.Errorf("second net lock: %v, want ErrNetBusy", err)
	}
	if len(HeldLocks(dir)) != 2 {
		t.Errorf("held locks %+v", HeldLocks(dir))
	}
	nrel()
	release()
	if h := HeldLocks(dir); len(h) != 0 {
		t.Errorf("released locks still listed: %+v", h)
	}

	// A record left by a process that died holding the lock.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	dead := cmd.Process.Pid
	rec := fmt.Sprintf(`{"pid":%d,"command":"yadm sync","since":%q}`, dead, time.Now().Add(-time.Hour).Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(dir, LockFile), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if h := HeldLocks(dir); len(h) != 0 {
		t.Errorf("dead holder listed: %+v", h)
	}
	release, err = FileLockTimeout(dir, 100*time.Millisecond).Acquire(context.Background())
	if err != nil {
		t.Fatalf("lock with a stale record: %v", err)
	}
	release()
}
