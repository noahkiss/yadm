package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/schedule"
)

// fakeScheduler reports a fixed status and counts installs.
type fakeScheduler struct {
	st       schedule.Status
	installs []schedule.Spec
	fail     error
}

func (f *fakeScheduler) Install(_ context.Context, s schedule.Spec) error {
	f.installs = append(f.installs, s)
	if f.fail == nil {
		// A fresh job has not exited yet.
		f.st.LastExit, f.st.NeedsConstraintUpdate = nil, false
	}
	return f.fail
}
func (f *fakeScheduler) Uninstall(context.Context) error { return nil }
func (f *fakeScheduler) Status(context.Context) (schedule.Status, error) {
	return f.st, nil
}

func brokenStatus() schedule.Status {
	n := schedule.ExConfig
	return schedule.Status{Installed: true, Loaded: true, LastExit: &n, Runs: 40, NeedsConstraintUpdate: true}
}

func useScheduler(t *testing.T, f *fakeScheduler) {
	t.Helper()
	hooks.scheduler = func() (schedule.Scheduler, error) { return f, nil }
}

func TestScheduleCheck(t *testing.T) {
	now := time.Date(2030, 1, 3, 12, 0, 0, 0, time.UTC)
	zero, ok := 0, schedule.Status{Installed: true, Loaded: true}
	ok.LastExit = &zero
	for name, c := range map[string]struct {
		st       schedule.Status
		lastRun  time.Time
		pass     bool
		warn     bool
		fix      bool
		contains string
	}{
		"broken":     {st: brokenStatus(), lastRun: now, fix: true, contains: "fix: yadm schedule install"},
		"not loaded": {st: schedule.Status{Installed: true}, fix: true, contains: "loaded=false"},
		"fresh":      {st: ok, lastRun: now.Add(-90 * time.Second), pass: true, contains: "last_exit=0"},
		"stale":      {st: ok, lastRun: now.Add(-time.Hour), pass: true, warn: true, contains: "1h0m0s ago"},
		"no record":  {st: ok, pass: true, contains: "no scheduled run recorded"},
		// systemd's own trigger time wins over the run record.
		"manager time": {st: schedule.Status{Installed: true, Loaded: true, LastRun: now.Add(-time.Minute)}, lastRun: now.Add(-time.Hour), pass: true},
	} {
		it, fix := scheduleCheck(c.st, c.lastRun, now)
		if it.OK != c.pass || it.Warn != c.warn || fix != c.fix || !strings.Contains(it.Detail, c.contains) {
			t.Errorf("%s: %+v fix=%v", name, it, fix)
		}
	}
}

func TestHealScheduleRateLimit(t *testing.T) {
	hermetic(t)
	state := t.TempDir()
	now := time.Date(2030, 1, 3, 12, 0, 0, 0, time.UTC)
	hooks.now = func() time.Time { return now }
	ctx := context.Background()

	// Healthy, or not installed: nothing happens.
	f := &fakeScheduler{st: schedule.Status{Installed: true, Loaded: true}}
	useScheduler(t, f)
	if s := healSchedule(ctx, state); s != "" || len(f.installs) != 0 {
		t.Fatalf("healthy: %q %v", s, f.installs)
	}
	f.st = brokenStatus()
	f.st.Installed = false
	if s := healSchedule(ctx, state); s != "" || len(f.installs) != 0 {
		t.Fatalf("not installed: %q %v", s, f.installs)
	}

	// Broken: one reinstall and one line.
	f.st = brokenStatus()
	s := healSchedule(ctx, state)
	if len(f.installs) != 1 || !strings.Contains(s, "reinstalled") || !strings.Contains(s, "EX_CONFIG") || strings.Contains(s, "\n") {
		t.Fatalf("heal: %q %v", s, f.installs)
	}
	if f.installs[0].Binary != "/usr/local/bin/yadm" || filepath.Base(f.installs[0].Log) != scheduleLogFile {
		t.Errorf("spec: %+v", f.installs[0])
	}

	// Broken again within the hour: no second reinstall.
	f.st = brokenStatus()
	now = now.Add(30 * time.Minute)
	if s := healSchedule(ctx, state); s != "" || len(f.installs) != 1 {
		t.Fatalf("within the hour: %q %v", s, f.installs)
	}
	// After the hour it tries again; a failure says so and is rate-limited too.
	now = now.Add(31 * time.Minute)
	f.fail = errors.New("bootstrap: exit 5")
	if s := healSchedule(ctx, state); !strings.Contains(s, "reinstall failed") || !strings.Contains(s, "yadm schedule install") || len(f.installs) != 2 {
		t.Fatalf("failed heal: %q %v", s, f.installs)
	}
	now = now.Add(time.Minute)
	if s := healSchedule(ctx, state); s != "" || len(f.installs) != 2 {
		t.Fatalf("failed heal retried at once: %q %v", s, f.installs)
	}
}

func TestMarkScheduledRunRotatesLog(t *testing.T) {
	hermetic(t)
	state := t.TempDir()
	now := time.Date(2030, 1, 3, 12, 0, 0, 0, time.UTC)
	hooks.now = func() time.Time { return now }
	if !lastScheduledRun(state).IsZero() {
		t.Fatal("run recorded before any run")
	}
	log := filepath.Join(state, scheduleLogFile)
	writeFile(t, log, strings.Repeat("x", scheduleLogMax+1))
	markScheduledRun(state)
	if !lastScheduledRun(state).Equal(now) {
		t.Errorf("last run = %v", lastScheduledRun(state))
	}
	if _, err := os.Stat(log); !errors.Is(err, os.ErrNotExist) {
		t.Error("full log not rotated")
	}
	if fi, err := os.Stat(log + ".1"); err != nil || fi.Size() != scheduleLogMax+1 {
		t.Errorf("rotated log: %v %v", fi, err)
	}
	writeFile(t, log, "small\n")
	markScheduledRun(state)
	if b, _ := os.ReadFile(log); string(b) != "small\n" {
		t.Error("small log rotated")
	}
}

// A sync run by hand and the session-start hook heal a broken schedule;
// the scheduled run (sync --auto) never does.
func TestSyncAndSessionStartHealSchedule(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	a := hookMachine(t, root, remote, "a", "host-a")
	now := time.Now()
	hooks.now = func() time.Time { return now }
	f := &fakeScheduler{st: brokenStatus()}
	useScheduler(t, f)

	yadm(t, "sync", "--auto")
	if len(f.installs) != 0 {
		t.Fatalf("sync --auto healed: %v", f.installs)
	}
	if !lastScheduledRun(a.State).Equal(now.UTC().Truncate(time.Second)) {
		t.Errorf("sync --auto recorded no run: %v", lastScheduledRun(a.State))
	}

	env, _, _ := yadm(t, "sync")
	d := decode[syncData](t, env.Data)
	if len(f.installs) != 1 || !strings.Contains(d.ScheduleHealed, "reinstalled") {
		t.Fatalf("sync: %+v %v", d, f.installs)
	}

	// The next hour: the hook heals, and says so first.
	now = now.Add(2 * time.Hour)
	f.st = brokenStatus()
	code, stdout, _ := hookRun(t, payload(payloadSessionStart, "session-h", a.Home, ""), HookSessionStart, "--format", "text")
	if code != HookAllow || len(f.installs) != 2 || !strings.HasPrefix(stdout, "yadm: the sync schedule had stopped") {
		t.Fatalf("session-start: exit %d %v\n%s", code, f.installs, stdout)
	}

	// yadm check fails and names the fix.
	f.st = brokenStatus()
	env, code, _ = yadm(t, "check")
	if code != ExitError || len(env.Next) != 1 || env.Next[0] != "yadm schedule install" {
		t.Fatalf("check: exit %d next %v", code, env.Next)
	}
}
