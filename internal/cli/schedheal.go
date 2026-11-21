package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/schedule"
)

// Files in the state directory that track the schedule's health.
const (
	scheduleRunFile  = "schedule-run"  // when `sync --auto` last started
	scheduleHealFile = "schedule-heal" // when a command last reinstalled a broken schedule
	scheduleLogFile  = "schedule.log"  // the launchd job's stdout and stderr
)

// ScheduleStaleAfter is how old the last scheduled run may be before
// `yadm check` warns.
const ScheduleStaleAfter = 5 * ScheduleInterval

// scheduleLogMax bounds the schedule log: a scheduled run that finds it
// larger moves it to schedule.log.1, replacing the older copy.
const scheduleLogMax = 512 << 10

// healEvery is how often a command may reinstall a broken schedule.
const healEvery = time.Hour

// markScheduledRun records the start of a scheduled run and rotates the
// schedule log. It runs before anything in the run can fail.
func markScheduledRun(stateDir string) {
	writeStamp(filepath.Join(stateDir, scheduleRunFile), hooks.now())
	p := filepath.Join(stateDir, scheduleLogFile)
	if fi, err := os.Stat(p); err == nil && fi.Size() > scheduleLogMax {
		_ = os.Rename(p, p+".1")
	}
}

// lastScheduledRun is when `sync --auto` last started, or zero.
func lastScheduledRun(stateDir string) time.Time {
	return readStamp(filepath.Join(stateDir, scheduleRunFile))
}

func writeStamp(p string, t time.Time) {
	_ = os.WriteFile(p, []byte(t.UTC().Format(time.RFC3339)+"\n"), 0o600)
}

func readStamp(p string) time.Time {
	b, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}
	}
	return t
}

// healSchedule reinstalls the schedule when the service manager reports it
// broken (schedule.Status.Broken), at most once per healEvery, and returns
// one line that says so. It returns "" when nothing was done. The caller
// never runs it from a scheduled run.
func healSchedule(ctx context.Context, stateDir string) string {
	s, err := hooks.scheduler()
	if err != nil {
		return ""
	}
	st, err := s.Status(ctx)
	if err != nil {
		return ""
	}
	why := st.Broken()
	if why == "" {
		return ""
	}
	stamp := filepath.Join(stateDir, scheduleHealFile)
	now := hooks.now()
	if last := readStamp(stamp); !last.IsZero() && now.Sub(last) < healEvery && !now.Before(last) {
		return ""
	}
	// Stamp first, so a failing install is not retried on every call.
	writeStamp(stamp, now)
	if err := s.Install(ctx, scheduleSpec()); err != nil {
		return "yadm: the sync schedule has stopped (" + why + "); reinstall failed: " + oneLine(err.Error()) + "; run yadm schedule install"
	}
	return "yadm: the sync schedule had stopped (" + why + "); reinstalled it"
}

// scheduleSpec is the schedule this binary installs.
func scheduleSpec() schedule.Spec {
	sp := schedule.Spec{Binary: schedule.StableBinary(hooks.binary()), Interval: ScheduleInterval, Label: schedule.DefaultLabel}
	if p, err := DefaultPaths(); err == nil && filepath.IsAbs(p.State) {
		sp.Log = filepath.Join(p.State, scheduleLogFile)
	}
	return sp
}
