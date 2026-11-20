package cli

import (
	"errors"
	"runtime"
	"testing"

	"github.com/noahkiss/yadm/internal/schedule"
)

// TestDefaultSchedulerIsLive: the CLI's default scheduler hook asks for the
// live scheduler, so init, adopt and `schedule install` can change the real
// schedule. The test swaps the constructor and runs no service manager.
func TestDefaultSchedulerIsLive(t *testing.T) {
	saved := forOSLive
	t.Cleanup(func() { forOSLive = saved })
	stop := errors.New("stop")
	var calls []bool
	forOSLive = func(goos string, live bool) (schedule.Scheduler, error) {
		if goos != runtime.GOOS {
			t.Errorf("goos %q, want %q", goos, runtime.GOOS)
		}
		calls = append(calls, live)
		return nil, stop
	}
	if _, err := hooks.scheduler(); !errors.Is(err, stop) {
		t.Fatalf("the default scheduler hook did not use forOSLive: %v", err)
	}
	if len(calls) != 1 || !calls[0] {
		t.Fatalf("the default scheduler hook passed live = %v, want true", calls)
	}
}
