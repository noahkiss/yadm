package schedule

import (
	"context"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// DefaultInterval is the sync period.
const DefaultInterval = 5 * time.Minute

// DefaultLabel names the launchd agent and the systemd units.
const DefaultLabel = "yadm-sync"

// Spec describes the schedule to install.
type Spec struct {
	Binary   string
	Interval time.Duration
	Label    string
}

// Status is what Status reports.
type Status struct {
	Installed bool      `json:"installed"`
	Loaded    bool      `json:"loaded"`
	LastRun   time.Time `json:"last_run,omitempty"`
	UnitPath  string    `json:"unit_path,omitempty"`
}

// Scheduler manages the platform's user-level scheduler.
type Scheduler interface {
	Install(ctx context.Context, s Spec) error
	Uninstall(ctx context.Context) error
	Status(ctx context.Context) (Status, error)
}

// ForOS returns the scheduler for "darwin" (launchd) or "linux" (systemd).
func ForOS(goos string) (Scheduler, error) { return nil, model.ErrNotImplemented }
