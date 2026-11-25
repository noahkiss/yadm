package sync

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

// TestAcquireNeverWaitsOnItsParent: a yadm command that a task or check
// runs while its parent yadm holds the sync lock fails at once, instead of
// waiting out its bound on a parent that waits for it. Any other holder is
// waited for, and FileLockWait says once whom it waits for.
func TestAcquireNeverWaitsOnItsParent(t *testing.T) {
	dir := t.TempDir()
	release, err := FileLock(dir).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	t.Setenv(extexec.EnvParentPID, strconv.Itoa(os.Getpid()))
	start := time.Now()
	_, err = FileLockTimeout(dir, 5*time.Second).Acquire(context.Background())
	if !errors.Is(err, ErrSelfLocked) || !errors.Is(err, ErrLocked) {
		t.Fatalf("acquire under the parent's lock: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("acquire under the parent's lock waited %v", d)
	}

	t.Setenv(extexec.EnvParentPID, strconv.Itoa(os.Getpid()+1))
	var notes int
	var holder *Holder
	_, err = FileLockWait(dir, 200*time.Millisecond, func(h *Holder, d time.Duration) {
		notes++
		holder = h
	}).Acquire(context.Background())
	if !errors.Is(err, ErrLocked) || errors.Is(err, ErrSelfLocked) {
		t.Fatalf("acquire under another holder: %v", err)
	}
	if notes != 1 || holder == nil || holder.PID != os.Getpid() {
		t.Fatalf("wait notes %d, holder %+v", notes, holder)
	}
}

// TestCommitBuildSeesTheMainItLandsOn: a retag computed before a wait
// carries a whole manifest from an older main, and committing it would
// undo the retag the process it waited for committed. Build computes the
// change under the commit's own hold of the lock, so both edits stand.
func TestCommitBuildSeesTheMainItLandsOn(t *testing.T) {
	a := fixture.HostA
	w := newWorld(t, nil, a)
	w.syncAll(a)
	A := w.machines[a]
	ctx := context.Background()
	types := []model.TypeName{"personal", "work"}
	retag := func(ctx context.Context, tg model.Target) (*apply.Capture, []store.Change, error) {
		c, err := A.eng.Retag(ctx, tg, apply.RetagOptions{Types: types})
		if err != nil {
			return nil, nil, err
		}
		last := len(c.Changes) - 1
		return &apply.Capture{Changes: c.Changes[last:], Paths: c.Paths, Scopes: c.Scopes}, c.Changes[:last], nil
	}
	const first, second = model.Target(".config/shell/aliases.sh"), model.Target(".gitconfig")

	// The waiting command checked its retag before the wait.
	if _, _, err := retag(ctx, second); err != nil {
		t.Fatal(err)
	}
	// Meanwhile the process it waits for commits another retag.
	cp, changes, err := retag(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := A.s.Commit(ctx, CommitOptions{Message: "retag first", Capture: cp, Changes: changes, Atomic: true, Push: true}); err != nil {
		t.Fatal(err)
	}
	built := 0
	rep, err := A.s.Commit(ctx, CommitOptions{Message: "retag second", Atomic: true, Push: true,
		Build: func(ctx context.Context) (*apply.Capture, []store.Change, error) {
			built++
			return retag(ctx, second)
		}})
	if err != nil || built != 1 || len(rep.Committed) != 1 {
		t.Fatalf("build commit: built %d, %+v %v", built, rep, err)
	}
	m, err := manifest.Parse([]byte(w.remoteFile(manifest.FileName)))
	if err != nil {
		t.Fatal(err)
	}
	when := map[model.Target]string{}
	for _, e := range m.Entries {
		when[e.Target] = e.When
	}
	for _, tg := range []model.Target{first, second} {
		if when[tg] != "type:personal | type:work" {
			t.Fatalf("%s: when %q after both retags", tg, when[tg])
		}
	}

	// A Build that finds nothing to change commits nothing.
	head := A.main()
	rep, err = A.s.Commit(ctx, CommitOptions{Push: true, Build: func(context.Context) (*apply.Capture, []store.Change, error) { return nil, nil, nil }})
	if err != nil || len(rep.Committed) != 0 || A.main() != head {
		t.Fatalf("empty build: %+v %v", rep, err)
	}
}

// TestAcquireNoticesItsParentTakingTheLock: a command waits behind another
// holder, and then the yadm that runs it takes the lock. The wait must end
// at once with ErrSelfLocked, not run out its bound behind the parent.
func TestAcquireNoticesItsParentTakingTheLock(t *testing.T) {
	dir := t.TempDir()
	release, err := FileLock(dir).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	parent := os.Getppid() // alive, and not this process
	t.Setenv(extexec.EnvParentPID, strconv.Itoa(parent))
	go func() {
		time.Sleep(300 * time.Millisecond)
		b, _ := json.Marshal(Holder{PID: parent, Command: "yadm sync", Since: time.Now()})
		_ = os.WriteFile(filepath.Join(dir, LockFile), b, 0o600)
	}()
	start := time.Now()
	_, err = FileLockTimeout(dir, 10*time.Second).Acquire(context.Background())
	if !errors.Is(err, ErrSelfLocked) {
		t.Fatalf("acquire after the parent took the lock: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("acquire waited %v after the parent took the lock", d)
	}
}
