package schedule

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DefaultInterval is the sync period.
const DefaultInterval = 5 * time.Minute

// DefaultLabel names the launchd agent and the systemd units.
const DefaultLabel = "yadm-sync"

// LiveEnv must be "1" for a test binary to install or remove a real
// schedule. Production code decides through Options.Live instead.
const LiveEnv = "YADM_SCHEDULE_LIVE"

// SystemPath is the PATH tail every schedule sets, after the binary's own
// directory: the Homebrew prefixes (Apple silicon, Intel, Linux), then the
// system directories. A launchd or systemd job otherwise starts with a
// minimal PATH that lacks git and the tools tasks call.
var SystemPath = []string{
	"/opt/homebrew/bin", "/opt/homebrew/sbin",
	"/usr/local/bin", "/usr/local/sbin",
	"/home/linuxbrew/.linuxbrew/bin", "/home/linuxbrew/.linuxbrew/sbin",
	"/usr/bin", "/bin", "/usr/sbin", "/sbin",
}

// Spec describes the schedule to install.
type Spec struct {
	Binary   string        // absolute path of yadm; see StableBinary
	Interval time.Duration // default DefaultInterval
	Label    string        // default DefaultLabel
	// Path is the PATH the job runs with. Empty means the binary's
	// directory followed by SystemPath.
	Path []string
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

// Commander runs one launchctl or systemctl command. Tests pass a fake.
type Commander interface {
	Run(ctx context.Context, argv []string) (output []byte, err error)
}

// Options configure a Scheduler. ForOS fills them from the environment.
type Options struct {
	Home       string    // $HOME; launchd agents live under it
	ConfigHome string    // $XDG_CONFIG_HOME; default $HOME/.config
	UID        int       // launchd GUI domain
	Label      string    // for Uninstall and Status; default DefaultLabel
	Commander  Commander // runs launchctl or systemctl
	// Live allows Install and Uninstall to run the real launchctl or
	// systemctl. The caller sets it: init and adopt pass true unless given
	// --no-schedule, and `yadm schedule install|uninstall` pass true.
	Live bool
}

// ErrNotLive is returned when Install or Uninstall would change the real
// schedule without Options.Live, or from a test binary without
// YADM_SCHEDULE_LIVE=1.
var ErrNotLive = errors.New("schedule: refusing to change the real schedule: use ForOSLive or Options.Live (a test binary also needs " + LiveEnv + "=1)")

// ForOS returns the read-only scheduler for "darwin" (launchd) or "linux"
// (systemd): Status works, Install and Uninstall return ErrNotLive. Use
// ForOSLive to change the schedule.
func ForOS(goos string) (Scheduler, error) { return ForOSLive(goos, false) }

// ForOSLive returns the scheduler for goos with Options.Live set by the
// caller.
func ForOSLive(goos string, live bool) (Scheduler, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return New(goos, Options{
		Home:       home,
		ConfigHome: os.Getenv("XDG_CONFIG_HOME"),
		UID:        os.Getuid(),
		Commander:  execCommander{},
		Live:       live,
	})
}

// StableBinary maps a binary inside a Homebrew Cellar
// (<prefix>/Cellar/<formula>/<version>/bin/<name>) to the version-free link
// <prefix>/bin/<name> when that link names the same file, so a schedule
// survives an upgrade. Any other path comes back unchanged.
func StableBinary(p string) string {
	dir, name := filepath.Split(filepath.Clean(p))
	parts := strings.Split(filepath.ToSlash(filepath.Clean(dir)), "/")
	// .../<prefix>/Cellar/<formula>/<version>/bin
	n := len(parts)
	if n < 5 || parts[n-1] != "bin" || parts[n-4] != "Cellar" {
		return p
	}
	prefix := filepath.FromSlash(strings.Join(parts[:n-4], "/"))
	link := filepath.Join(prefix, "bin", name)
	a, err1 := os.Stat(p)
	b, err2 := os.Stat(link)
	if err1 != nil || err2 != nil || !os.SameFile(a, b) {
		return p
	}
	return link
}

// New returns the scheduler for goos with explicit options. With the real
// Commander, Install and Uninstall return ErrNotLive, before writing any
// file, unless Options.Live is set. Status is read-only and always runs.
func New(goos string, o Options) (Scheduler, error) {
	if o.Home == "" || !filepath.IsAbs(o.Home) {
		return nil, fmt.Errorf("schedule: home %q must be an absolute path", o.Home)
	}
	if o.ConfigHome == "" || !filepath.IsAbs(o.ConfigHome) {
		o.ConfigHome = filepath.Join(o.Home, ".config")
	}
	if o.Label == "" {
		o.Label = DefaultLabel
	}
	if !labelPattern.MatchString(o.Label) {
		return nil, fmt.Errorf("schedule: label %q: invalid", o.Label)
	}
	if o.Commander == nil {
		return nil, errors.New("schedule: no commander")
	}
	b := base{o: o}
	switch goos {
	case "darwin":
		return &launchd{b}, nil
	case "linux":
		return &systemd{b}, nil
	}
	return nil, fmt.Errorf("schedule: unsupported OS %q", goos)
}

type base struct{ o Options }

// guard refuses to change the real service manager unless Live is set. A
// test binary also needs YADM_SCHEDULE_LIVE=1, so no test touches the
// developer's service manager by accident.
func (b base) guard() error {
	if _, real := b.o.Commander.(execCommander); !real {
		return nil
	}
	if !b.o.Live || (testing.Testing() && os.Getenv(LiveEnv) != "1") {
		return ErrNotLive
	}
	return nil
}

func (b base) run(ctx context.Context, argv ...string) ([]byte, error) {
	return b.o.Commander.Run(ctx, argv)
}

var labelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// normalize fills defaults and validates a spec.
func normalize(s Spec) (Spec, error) {
	if s.Interval == 0 {
		s.Interval = DefaultInterval
	}
	if s.Label == "" {
		s.Label = DefaultLabel
	}
	if !filepath.IsAbs(s.Binary) {
		return s, fmt.Errorf("schedule: binary %q must be an absolute path", s.Binary)
	}
	if strings.ContainsAny(s.Binary, "\n\r\x00") {
		return s, fmt.Errorf("schedule: binary path holds a control character")
	}
	if s.Interval < time.Minute || s.Interval%time.Second != 0 {
		return s, fmt.Errorf("schedule: interval %s: want whole seconds, at least 1m", s.Interval)
	}
	if !labelPattern.MatchString(s.Label) {
		return s, fmt.Errorf("schedule: label %q: invalid", s.Label)
	}
	if len(s.Path) == 0 {
		s.Path = append([]string{filepath.Dir(s.Binary)}, SystemPath...)
	}
	seen := map[string]bool{}
	var path []string
	for _, d := range s.Path {
		if !filepath.IsAbs(d) || strings.ContainsAny(d, ":\n\r\x00") {
			return s, fmt.Errorf("schedule: PATH entry %q must be an absolute path without ':' or control characters", d)
		}
		if !seen[d] {
			seen[d] = true
			path = append(path, d)
		}
	}
	s.Path = path
	return s, nil
}

// pathValue is the PATH a spec's job runs with.
func pathValue(s Spec) string { return strings.Join(s.Path, ":") }

// syncArgs is what every schedule runs.
var syncArgs = []string{"sync", "--auto"}

// LaunchdPlist returns the launchd agent for a spec. It runs at load (login)
// and every Interval. launchd coalesces intervals missed during sleep into
// one run at wake, so a missed run is not queued twice.
func LaunchdPlist(s Spec) ([]byte, error) {
	s, err := normalize(s)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	esc := func(v string) string {
		var e bytes.Buffer
		_ = xml.EscapeText(&e, []byte(v))
		return e.String()
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + esc(s.Label) + `</string>
	<key>ProgramArguments</key>
	<array>
`)
	for _, a := range append([]string{s.Binary}, syncArgs...) {
		b.WriteString("\t\t<string>" + esc(a) + "</string>\n")
	}
	b.WriteString(`	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>` + esc(pathValue(s)) + `</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>` + strconv.Itoa(int(s.Interval/time.Second)) + `</integer>
	<key>ProcessType</key>
	<string>Background</string>
	<key>LowPriorityIO</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/dev/null</string>
	<key>StandardErrorPath</key>
	<string>/dev/null</string>
</dict>
</plist>
`)
	return b.Bytes(), nil
}

// systemdQuote quotes one ExecStart word: "%" doubles, and a word with a
// space, quote or backslash is double-quoted with C escapes.
func systemdQuote(w string) string {
	w = strings.ReplaceAll(w, "%", "%%")
	if w != "" && !strings.ContainsAny(w, " \t\"'\\$;") {
		return w
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `$$`)
	return `"` + r.Replace(w) + `"`
}

// systemdEnv quotes one Environment= assignment: "%" doubles, and a
// backslash or double quote is escaped inside the double quotes.
func systemdEnv(k, v string) string {
	r := strings.NewReplacer(`%`, `%%`, `\`, `\\`, `"`, `\"`)
	return `"` + r.Replace(k+"="+v) + `"`
}

// SystemdService returns the oneshot service the timer starts.
func SystemdService(s Spec) ([]byte, error) {
	s, err := normalize(s)
	if err != nil {
		return nil, err
	}
	words := []string{systemdQuote(s.Binary)}
	words = append(words, syncArgs...)
	return []byte(`[Unit]
Description=yadm sync
After=network-online.target

[Service]
Type=oneshot
Environment=` + systemdEnv("PATH", pathValue(s)) + `
ExecStart=` + strings.Join(words, " ") + `
Nice=10
IOSchedulingClass=idle
`), nil
}

// SystemdTimer returns the timer. It fires one minute after the user manager
// starts (login) and every Interval. When Interval divides an hour in whole
// minutes it uses a persistent calendar timer, so a run missed during
// suspend fires once at resume; otherwise a monotonic timer.
func SystemdTimer(s Spec) ([]byte, error) {
	s, err := normalize(s)
	if err != nil {
		return nil, err
	}
	var every string
	if s.Interval%time.Minute == 0 && time.Hour%s.Interval == 0 {
		every = "OnCalendar=*:0/" + strconv.Itoa(int(s.Interval/time.Minute)) + "\nPersistent=true\n"
	} else {
		every = "OnUnitActiveSec=" + strconv.Itoa(int(s.Interval/time.Second)) + "s\n"
	}
	return []byte(`[Unit]
Description=yadm sync every ` + s.Interval.String() + `

[Timer]
OnStartupSec=1min
` + every + `AccuracySec=30s
Unit=` + s.Label + `.service

[Install]
WantedBy=timers.target
`), nil
}

// writeAtomic writes b to p with mode 0644 through a temp file.
func writeAtomic(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func cmdErr(what string, err error, out []byte) error {
	return fmt.Errorf("%s: %w: %s", what, err, strings.TrimSpace(string(out)))
}

// launchd manages ~/Library/LaunchAgents/<label>.plist in gui/<uid>.
type launchd struct{ base }

func (l *launchd) plistPath(label string) string {
	return filepath.Join(l.o.Home, "Library", "LaunchAgents", label+".plist")
}

func (l *launchd) domain() string { return "gui/" + strconv.Itoa(l.o.UID) }

func (l *launchd) Install(ctx context.Context, s Spec) error {
	if s.Label == "" {
		s.Label = l.o.Label
	}
	b, err := LaunchdPlist(s)
	if err != nil {
		return err
	}
	if err := l.guard(); err != nil {
		return err
	}
	p := l.plistPath(s.Label)
	if err := writeAtomic(p, b); err != nil {
		return err
	}
	// A loaded old copy must go first; an error means it was not loaded.
	_, _ = l.run(ctx, "launchctl", "bootout", l.domain(), p)
	if out, err := l.run(ctx, "launchctl", "bootstrap", l.domain(), p); err != nil {
		return cmdErr("launchctl bootstrap", err, out)
	}
	return nil
}

func (l *launchd) Uninstall(ctx context.Context) error {
	if err := l.guard(); err != nil {
		return err
	}
	p := l.plistPath(l.o.Label)
	_, _ = l.run(ctx, "launchctl", "bootout", l.domain()+"/"+l.o.Label)
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Status reads the plist and asks launchd whether the agent is loaded.
// LastRun stays zero: launchd keeps no run time; the caller fills it from
// the sync state.
func (l *launchd) Status(ctx context.Context) (Status, error) {
	p := l.plistPath(l.o.Label)
	st := Status{UnitPath: p, Installed: exists(p)}
	_, err := l.run(ctx, "launchctl", "print", l.domain()+"/"+l.o.Label)
	st.Loaded = err == nil
	return st, nil
}

// systemd manages <label>.service and <label>.timer in $XDG_CONFIG_HOME/systemd/user.
type systemd struct{ base }

func (s *systemd) dir() string { return filepath.Join(s.o.ConfigHome, "systemd", "user") }

func (s *systemd) paths(label string) (service, timer string) {
	return filepath.Join(s.dir(), label+".service"), filepath.Join(s.dir(), label+".timer")
}

func (s *systemd) Install(ctx context.Context, sp Spec) error {
	if sp.Label == "" {
		sp.Label = s.o.Label
	}
	svc, err := SystemdService(sp)
	if err != nil {
		return err
	}
	tmr, err := SystemdTimer(sp)
	if err != nil {
		return err
	}
	if err := s.guard(); err != nil {
		return err
	}
	ps, pt := s.paths(sp.Label)
	if err := writeAtomic(ps, svc); err != nil {
		return err
	}
	if err := writeAtomic(pt, tmr); err != nil {
		return err
	}
	if out, err := s.run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return cmdErr("systemctl daemon-reload", err, out)
	}
	if out, err := s.run(ctx, "systemctl", "--user", "enable", "--now", sp.Label+".timer"); err != nil {
		return cmdErr("systemctl enable", err, out)
	}
	return nil
}

func (s *systemd) Uninstall(ctx context.Context) error {
	if err := s.guard(); err != nil {
		return err
	}
	_, _ = s.run(ctx, "systemctl", "--user", "disable", "--now", s.o.Label+".timer")
	ps, pt := s.paths(s.o.Label)
	for _, p := range []string{pt, ps} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if out, err := s.run(ctx, "systemctl", "--user", "daemon-reload"); err != nil {
		return cmdErr("systemctl daemon-reload", err, out)
	}
	return nil
}

// Status reads the unit files and asks systemd whether the timer is active
// and when it last fired.
func (s *systemd) Status(ctx context.Context) (Status, error) {
	ps, pt := s.paths(s.o.Label)
	st := Status{UnitPath: pt, Installed: exists(ps) && exists(pt)}
	_, err := s.run(ctx, "systemctl", "--user", "is-active", "--quiet", s.o.Label+".timer")
	st.Loaded = err == nil
	if out, err := s.run(ctx, "systemctl", "--user", "show", s.o.Label+".timer", "--property=LastTriggerUSec", "--value"); err == nil {
		st.LastRun = parseSystemdTime(strings.TrimSpace(string(out)))
	}
	return st, nil
}

// parseSystemdTime parses systemctl's "Thu 2030-01-03 12:00:00 UTC". Anything
// else, such as "n/a", is the zero time.
func parseSystemdTime(v string) time.Time {
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// execCommander runs commands as child processes with a timeout.
type execCommander struct{}

func (execCommander) Run(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
}
