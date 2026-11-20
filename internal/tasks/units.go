package tasks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
)

// UnitReloader reloads one service unit.
type UnitReloader interface {
	Reload(ctx context.Context, u manifest.Unit, home string) error
}

// Commander runs one service-manager command. Tests pass a fake, so they
// never call launchctl or systemctl.
type Commander interface {
	Run(ctx context.Context, argv []string) (output []byte, err error)
}

// unitTimeout bounds each service-manager command.
const unitTimeout = 30 * time.Second

// SystemReloader returns the launchd/systemd reloader for this OS.
func SystemReloader(goos string) (UnitReloader, error) {
	return NewReloader(goos, ExecCommander{}, os.Getuid())
}

// NewReloader returns the reloader for goos with c running the commands.
// uid names the launchd GUI domain ("gui/<uid>").
//
//   - darwin reloads launchd units: `launchctl bootout gui/<uid> <plist>`
//     (an error there means it was not loaded and is ignored), then
//     `launchctl bootstrap gui/<uid> <plist>`.
//   - linux reloads systemd user units: `systemctl --user daemon-reload`,
//     then `systemctl --user restart <unit name>`.
//
// A unit of the other kind is an error, not a silent skip.
func NewReloader(goos string, c Commander, uid int) (UnitReloader, error) {
	switch goos {
	case "darwin":
		return launchdReloader{c: c, uid: uid}, nil
	case "linux":
		return systemdReloader{c: c}, nil
	}
	return nil, fmt.Errorf("unit reload: unsupported OS %q", goos)
}

// unitPath resolves a unit target under home and refuses one that escapes it.
func unitPath(u manifest.Unit, home string) (string, error) {
	t := string(u.Target)
	if t == "" || path.IsAbs(t) || strings.HasPrefix(path.Clean(t), "../") || path.Clean(t) == ".." {
		return "", fmt.Errorf("unit %q: target must be a path under $HOME", t)
	}
	if home == "" {
		return "", fmt.Errorf("unit %q: no home directory", t)
	}
	return filepath.Join(home, filepath.FromSlash(path.Clean(t))), nil
}

type launchdReloader struct {
	c   Commander
	uid int
}

func (l launchdReloader) Reload(ctx context.Context, u manifest.Unit, home string) error {
	if u.Kind != manifest.UnitLaunchd {
		return fmt.Errorf("unit %s: kind %q cannot be reloaded on darwin", u.Target, u.Kind)
	}
	p, err := unitPath(u, home)
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(l.uid)
	_, _ = l.c.Run(ctx, []string{"launchctl", "bootout", domain, p})
	if out, err := l.c.Run(ctx, []string{"launchctl", "bootstrap", domain, p}); err != nil {
		return fmt.Errorf("launchctl bootstrap %s: %w: %s", u.Target, err, strings.TrimSpace(string(out)))
	}
	return nil
}

type systemdReloader struct{ c Commander }

func (s systemdReloader) Reload(ctx context.Context, u manifest.Unit, home string) error {
	if u.Kind != manifest.UnitSystemd {
		return fmt.Errorf("unit %s: kind %q cannot be reloaded on linux", u.Target, u.Kind)
	}
	if _, err := unitPath(u, home); err != nil {
		return err
	}
	name := path.Base(string(u.Target))
	if out, err := s.c.Run(ctx, []string{"systemctl", "--user", "daemon-reload"}); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := s.c.Run(ctx, []string{"systemctl", "--user", "restart", name}); err != nil {
		return fmt.Errorf("systemctl restart %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ExecCommander runs commands as child processes with a timeout.
type ExecCommander struct{}

// Run runs argv and returns its combined output.
func (ExecCommander) Run(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	ctx, cancel := context.WithTimeout(ctx, unitTimeout)
	defer cancel()
	return exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
}
