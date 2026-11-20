package tasks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// writePlist writes a synthetic launchd plist with label and an extra
// top-level key/value block (XML) under home.
func writePlist(t *testing.T, home, target, label, extra string) {
	t.Helper()
	p := filepath.Join(home, filepath.FromSlash(target))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array><string>/usr/bin/true</string></array>
	<key>EnvironmentVariables</key>
	<dict><key>KeepAlive</key><string>not-top-level</string></dict>
` + extra + `</dict>
</plist>
`
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchdReloadSkips(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	env := map[string]string{"XPC_SERVICE_NAME": "example.runner"}
	unit := func(name string) manifest.Unit {
		return manifest.Unit{Target: model.Target("Library/LaunchAgents/" + name + ".plist"), Kind: manifest.UnitLaunchd}
	}
	writePlist(t, home, string(unit("example.plain").Target), "example.plain", "\t<key>KeepAlive</key>\n\t<false/>\n")
	writePlist(t, home, string(unit("example.keep").Target), "example.keep", "\t<key>KeepAlive</key>\n\t<true/>\n")
	writePlist(t, home, string(unit("example.keepdict").Target), "example.keepdict", "\t<key>KeepAlive</key>\n\t<dict><key>SuccessfulExit</key><false/></dict>\n")
	writePlist(t, home, string(unit("example.runner").Target), "example.runner", "")
	bin := filepath.Join(home, "Library/LaunchAgents/example.binary.plist")
	if err := os.WriteFile(bin, []byte("bplist00\x00\x01"), 0o644); err != nil {
		t.Fatal(err)
	}

	c := &fakeCommander{}
	r := launchdReloader{c: c, uid: 501, getenv: func(k string) string { return env[k] }}
	if err := r.Reload(ctx, unit("example.plain"), home); err != nil {
		t.Fatalf("plain job: %v", err)
	}
	if len(c.argv) != 2 {
		t.Fatalf("plain job not reloaded: %v", c.argv)
	}
	never := unit("example.plain")
	never.Reload = manifest.ReloadNever
	for name, u := range map[string]manifest.Unit{
		"never":     never,
		"keepalive": unit("example.keep"),
		"keepdict":  unit("example.keepdict"),
		"self":      unit("example.runner"),
		"binary":    unit("example.binary"),
		"missing":   unit("example.missing"),
	} {
		c.argv = nil
		err := r.Reload(ctx, u, home)
		if _, ok := IsSkip(err); !ok {
			t.Errorf("%s: want a skip, got %v", name, err)
		}
		if len(c.argv) != 0 {
			t.Errorf("%s: ran %v", name, c.argv)
		}
	}

	// systemd: never skips, auto restarts.
	c = &fakeCommander{}
	sr := systemdReloader{c: c}
	svc := manifest.Unit{Target: ".config/systemd/user/example.service", Kind: manifest.UnitSystemd, Reload: manifest.ReloadNever}
	if _, ok := IsSkip(sr.Reload(ctx, svc, home)); !ok || len(c.argv) != 0 {
		t.Errorf("systemd never: %v", c.argv)
	}

	// The runner records a skip as a detail, not an error.
	run := &Runner{Units: r}
	res, _ := run.Run(ctx, Event{Units: []manifest.Unit{unit("example.keep")}}, nil, extexec.Request{Home: home})
	if len(res) != 1 || res[0].Error != "" || res[0].ExitCode != 0 || !strings.Contains(res[0].Detail, "KeepAlive") {
		t.Errorf("runner result: %+v", res)
	}
}

func TestReadPlist(t *testing.T) {
	for _, bad := range []string{"bplist00", "<plist><array/></plist>", "<plist><dict><key>Label</key>", "not xml <"} {
		if _, err := readPlist([]byte(bad)); err == nil {
			t.Errorf("readPlist(%q) accepted", bad)
		}
	}
}
