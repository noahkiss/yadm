package schedule

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

const bin = "/opt/yadm/bin/yadm"

const goldenPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>yadm-sync</string>
	<key>ProgramArguments</key>
	<array>
		<string>/opt/yadm/bin/yadm</string>
		<string>sync</string>
		<string>--auto</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>/opt/yadm/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin</string>
	</dict>
	<key>RunAtLoad</key>
	<true/>
	<key>StartInterval</key>
	<integer>300</integer>
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
`

const goldenService = `[Unit]
Description=yadm sync
After=network-online.target

[Service]
Type=oneshot
Environment="PATH=/opt/yadm/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin"
ExecStart=/opt/yadm/bin/yadm sync --auto
SuccessExitStatus=3
Nice=10
IOSchedulingClass=idle
`

const goldenTimer = `[Unit]
Description=yadm sync every 5m0s

[Timer]
OnStartupSec=1min
OnCalendar=*:0/5
Persistent=true
AccuracySec=30s
Unit=yadm-sync.service

[Install]
WantedBy=timers.target
`

const goldenTimerOdd = `[Unit]
Description=yadm sync every 7m0s

[Timer]
OnStartupSec=1min
OnUnitActiveSec=420s
AccuracySec=30s
Unit=yadm-sync.service

[Install]
WantedBy=timers.target
`

func TestGolden(t *testing.T) {
	s := Spec{Binary: bin}
	for name, c := range map[string]struct {
		gen  func(Spec) ([]byte, error)
		spec Spec
		want string
	}{
		"plist":     {LaunchdPlist, s, goldenPlist},
		"service":   {SystemdService, s, goldenService},
		"timer":     {SystemdTimer, s, goldenTimer},
		"timer-odd": {SystemdTimer, Spec{Binary: bin, Interval: 7 * time.Minute}, goldenTimerOdd},
	} {
		got, err := c.gen(c.spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != c.want {
			t.Errorf("%s:\n--- got\n%s--- want\n%s", name, got, c.want)
		}
	}
}

func TestEscaping(t *testing.T) {
	odd := "/opt/my tools/<y&m>/100%/yadm"
	p, err := LaunchdPlist(Spec{Binary: odd})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p), "<string>/opt/my tools/&lt;y&amp;m&gt;/100%/yadm</string>") {
		t.Errorf("plist escaping:\n%s", p)
	}
	svc, _ := SystemdService(Spec{Binary: odd})
	if !strings.Contains(string(svc), `ExecStart="/opt/my tools/<y&m>/100%%/yadm" sync --auto`) {
		t.Errorf("service escaping:\n%s", svc)
	}
	if !strings.Contains(string(svc), `Environment="PATH=/opt/my tools/<y&m>/100%%:/opt/homebrew/bin:`) {
		t.Errorf("service PATH escaping:\n%s", svc)
	}
	if _, err := LaunchdPlist(Spec{Binary: bin, Path: []string{"/a:b"}}); err == nil {
		t.Error("PATH entry with ':' accepted")
	}
	if _, err := SystemdService(Spec{Binary: bin, Path: []string{"relative/bin"}}); err == nil {
		t.Error("relative PATH entry accepted")
	}
	p, _ = LaunchdPlist(Spec{Binary: bin, Path: []string{"/x/bin", "/x/bin", "/usr/bin"}})
	if !strings.Contains(string(p), "<string>/x/bin:/usr/bin</string>") {
		t.Errorf("explicit PATH:\n%s", p)
	}
}

func TestStableBinary(t *testing.T) {
	prefix := t.TempDir()
	cellar := filepath.Join(prefix, "Cellar", "yadm", "1.2.3", "bin", "yadm")
	if err := os.MkdirAll(filepath.Dir(cellar), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cellar, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := StableBinary(cellar); got != cellar {
		t.Errorf("no link yet: %s", got)
	}
	link := filepath.Join(prefix, "bin", "yadm")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cellar, link); err != nil {
		t.Fatal(err)
	}
	if got := StableBinary(cellar); got != link {
		t.Errorf("StableBinary = %s, want %s", got, link)
	}
	if got := StableBinary("/usr/local/bin/yadm"); got != "/usr/local/bin/yadm" {
		t.Errorf("plain path changed: %s", got)
	}
}

func TestSpecValidation(t *testing.T) {
	for name, s := range map[string]Spec{
		"relative": {Binary: "yadm"},
		"short":    {Binary: bin, Interval: 30 * time.Second},
		"fraction": {Binary: bin, Interval: time.Minute + time.Millisecond},
		"label":    {Binary: bin, Label: "../x"},
		"newline":  {Binary: "/opt/x\n/yadm"},
	} {
		if _, err := LaunchdPlist(s); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

type fakeCmd struct {
	argv [][]string
	fail map[string]error
	out  map[string]string
}

func (f *fakeCmd) Run(_ context.Context, argv []string) ([]byte, error) {
	f.argv = append(f.argv, argv)
	key := strings.Join(argv, " ")
	return []byte(f.out[key]), f.fail[key]
}

func TestLaunchd(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	c := &fakeCmd{fail: map[string]error{"launchctl print gui/501/yadm-sync": errors.New("not found")}}
	s, err := New("darwin", Options{Home: home, UID: 501, Commander: c})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.Status(ctx)
	plist := filepath.Join(home, "Library", "LaunchAgents", "yadm-sync.plist")
	if st.Installed || st.Loaded || st.UnitPath != plist {
		t.Errorf("before: %+v", st)
	}
	if err := s.Install(ctx, Spec{Binary: bin}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(plist)
	if string(b) != goldenPlist {
		t.Errorf("written plist differs:\n%s", b)
	}
	c.fail = nil
	st, _ = s.Status(ctx)
	if !st.Installed || !st.Loaded {
		t.Errorf("after: %+v", st)
	}
	if err := s.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(plist); !errors.Is(err, os.ErrNotExist) {
		t.Error("plist not removed")
	}
	want := [][]string{
		{"launchctl", "print", "gui/501/yadm-sync"},
		{"launchctl", "bootout", "gui/501", plist},
		{"launchctl", "bootstrap", "gui/501", plist},
		{"launchctl", "print", "gui/501/yadm-sync"},
		{"launchctl", "bootout", "gui/501/yadm-sync"},
	}
	if !reflect.DeepEqual(c.argv, want) {
		t.Errorf("argv:\n%v\nwant\n%v", c.argv, want)
	}
	// A failed bootstrap is an error.
	c.fail = map[string]error{"launchctl bootstrap gui/501 " + plist: errors.New("exit 5")}
	if err := s.Install(ctx, Spec{Binary: bin}); err == nil {
		t.Error("bootstrap failure ignored")
	}
}

func TestSystemd(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	cfg := filepath.Join(t.TempDir(), "cfg")
	c := &fakeCmd{out: map[string]string{
		"systemctl --user show yadm-sync.timer --property=LastTriggerUSec --value": "Thu 2030-01-03 12:00:00 UTC\n",
	}}
	s, err := New("linux", Options{Home: home, ConfigHome: cfg, Commander: c})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Install(ctx, Spec{Binary: bin}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(cfg, "systemd", "user")
	svc, _ := os.ReadFile(filepath.Join(dir, "yadm-sync.service"))
	tmr, _ := os.ReadFile(filepath.Join(dir, "yadm-sync.timer"))
	if string(svc) != goldenService || string(tmr) != goldenTimer {
		t.Errorf("unit files differ:\n%s\n%s", svc, tmr)
	}
	st, _ := s.Status(ctx)
	if !st.Installed || !st.Loaded || st.UnitPath != filepath.Join(dir, "yadm-sync.timer") ||
		!st.LastRun.Equal(time.Date(2030, 1, 3, 12, 0, 0, 0, time.UTC)) {
		t.Errorf("status = %+v", st)
	}
	if err := s.Uninstall(ctx); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("unit files left: %v", ents)
	}
	want := [][]string{
		{"systemctl", "--user", "daemon-reload"},
		{"systemctl", "--user", "enable", "--now", "yadm-sync.timer"},
		{"systemctl", "--user", "is-active", "--quiet", "yadm-sync.timer"},
		{"systemctl", "--user", "show", "yadm-sync.timer", "--property=LastTriggerUSec", "--value"},
		{"systemctl", "--user", "disable", "--now", "yadm-sync.timer"},
		{"systemctl", "--user", "daemon-reload"},
	}
	if !reflect.DeepEqual(c.argv, want) {
		t.Errorf("argv:\n%v\nwant\n%v", c.argv, want)
	}
	// ConfigHome defaults under Home.
	s2, _ := New("linux", Options{Home: home, Commander: c})
	st, _ = s2.Status(ctx)
	if st.UnitPath != filepath.Join(home, ".config", "systemd", "user", "yadm-sync.timer") {
		t.Errorf("default config home: %s", st.UnitPath)
	}
	if parseSystemdTime("n/a").IsZero() != true {
		t.Error("n/a should be zero")
	}
}

func TestNewErrors(t *testing.T) {
	c := &fakeCmd{}
	for name, o := range map[string]Options{
		"no home":     {Commander: c},
		"rel home":    {Home: "home", Commander: c},
		"no cmd":      {Home: "/tmp/h"},
		"bad label":   {Home: "/tmp/h", Commander: c, Label: "a b"},
		"unsupported": {Home: "/tmp/h", Commander: c},
	} {
		goos := "linux"
		if name == "unsupported" {
			goos = "plan9"
		}
		if _, err := New(goos, o); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// The real scheduler refuses to change anything from a test binary unless
// YADM_SCHEDULE_LIVE=1, and fails before it writes a file.
func TestRealSchedulerGuard(t *testing.T) {
	if os.Getenv(LiveEnv) == "1" {
		t.Skip("live mode")
	}
	home := t.TempDir()
	for _, goos := range []string{"darwin", "linux"} {
		s, err := New(goos, Options{Home: home, Commander: execCommander{}})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Install(context.Background(), Spec{Binary: bin}); !errors.Is(err, ErrNotLive) {
			t.Errorf("%s Install: %v", goos, err)
		}
		if err := s.Uninstall(context.Background()); !errors.Is(err, ErrNotLive) {
			t.Errorf("%s Uninstall: %v", goos, err)
		}
	}
	if ents, _ := os.ReadDir(home); len(ents) != 0 {
		t.Errorf("guard wrote files: %v", ents)
	}
	if s, err := ForOS(runtime.GOOS); err == nil {
		if err := s.Install(context.Background(), Spec{Binary: bin}); !errors.Is(err, ErrNotLive) {
			t.Errorf("ForOS Install: %v", err)
		}
	}
	// A live production scheduler is still refused from a test binary.
	if s, err := ForOSLive(runtime.GOOS, true); err == nil {
		if err := s.Install(context.Background(), Spec{Binary: bin}); !errors.Is(err, ErrNotLive) {
			t.Errorf("ForOSLive Install from a test: %v", err)
		}
	}
	live, err := New("linux", Options{Home: home, Commander: execCommander{}, Live: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := live.Uninstall(context.Background()); !errors.Is(err, ErrNotLive) {
		t.Errorf("Live from a test: %v", err)
	}
}

// TestLive installs, inspects and removes a real schedule under a throwaway
// label. It runs only with YADM_SCHEDULE_LIVE=1.
func TestLive(t *testing.T) {
	if os.Getenv(LiveEnv) != "1" {
		t.Skip("set " + LiveEnv + "=1 to touch the real service manager")
	}
	home, _ := os.UserHomeDir()
	s, err := New(runtime.GOOS, Options{Home: home, ConfigHome: os.Getenv("XDG_CONFIG_HOME"), UID: os.Getuid(),
		Label: "yadm-sync-livetest", Commander: execCommander{}, Live: true})
	if err != nil {
		t.Skip(err)
	}
	ctx := context.Background()
	if err := s.Install(ctx, Spec{Binary: "/usr/bin/true", Label: "yadm-sync-livetest", Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Uninstall(ctx) })
	st, err := s.Status(ctx)
	if err != nil || !st.Installed || !st.Loaded {
		t.Errorf("status = %+v, %v", st, err)
	}
}
