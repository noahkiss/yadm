package schedule

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// launchctlPrint is a synthetic `launchctl print gui/501/yadm-sync` with the
// given top-level lines spliced in, and nested blocks that repeat the keys
// the parser reads, which it must ignore.
func launchctlPrint(lines string) string {
	return `gui/501/yadm-sync = {
	active count = 0
	path = /opt/home/Library/LaunchAgents/yadm-sync.plist
	type = LaunchAgent
	state = not running

	program = /opt/yadm/bin/yadm
	arguments = {
		/opt/yadm/bin/yadm
		sync
		--auto
	}

	stdout path = /opt/state/schedule.log
	stderr path = /opt/state/schedule.log
	inherited environment = {
		SSH_AUTH_SOCK => /opt/run/agent.sock
	}

	default environment = {
		PATH => /usr/bin:/bin:/usr/sbin:/sbin
	}

	domain = gui/501 [100005]
	asid = 100005
	minimum runtime = 10
	exit timeout = 5
	run interval = 60 seconds
` + lines + `
	event triggers = {
		nested = {
			runs = 99
			last exit code = 78: EX_CONFIG
			properties = needs LWCR update
		}
	}

	spawn type = background (2)
	jetsam priority = 0
}
`
}

func TestParseLaunchctlPrint(t *testing.T) {
	for name, c := range map[string]struct {
		lines      string
		runs       int
		exit       int // -1: nil
		constraint bool
		broken     bool
	}{
		"broken": {
			lines: "\truns = 1432\n\tlast exit code = 78: EX_CONFIG\n\n\tproperties = runatload | inferred program | needs LWCR update | managed LWCR | has LWCR\n",
			runs:  1432, exit: 78, constraint: true, broken: true,
		},
		"exit 78 only": {
			lines: "\truns = 3\n\tlast exit code = 78: EX_CONFIG\n\tproperties = runatload | inferred program\n",
			runs:  3, exit: 78, broken: true,
		},
		"managed healthy": {
			lines: "\truns = 12\n\tlast exit code = 0\n\tproperties = runatload | inferred program | managed LWCR | has LWCR\n",
			runs:  12, exit: 0,
		},
		"flag only": {
			lines: "\truns = 1\n\tlast exit code = 0\n\tproperties = needs LWCR update\n",
			runs:  1, exit: 0, constraint: true, broken: true,
		},
		"never exited": {
			lines: "\truns = 0\n\tlast exit code = (never exited)\n\tproperties = runatload | inferred program\n",
			exit:  -1,
		},
		"lines missing": {exit: -1},
		"garbage":       {lines: "\truns = many\n\tlast exit code = soon: maybe\n\tproperties\n", exit: -1},
	} {
		st := Status{Installed: true}
		parseLaunchctlPrint([]byte(launchctlPrint(c.lines)), &st)
		if st.Runs != c.runs || st.NeedsConstraintUpdate != c.constraint {
			t.Errorf("%s: %+v", name, st)
		}
		switch {
		case c.exit < 0 && st.LastExit != nil:
			t.Errorf("%s: last exit %d, want none", name, *st.LastExit)
		case c.exit >= 0 && (st.LastExit == nil || *st.LastExit != c.exit):
			t.Errorf("%s: last exit %v, want %d", name, st.LastExit, c.exit)
		}
		if (st.Broken() != "") != c.broken {
			t.Errorf("%s: Broken() = %q", name, st.Broken())
		}
		if st.Log != "/opt/state/schedule.log" {
			t.Errorf("%s: log %q", name, st.Log)
		}
	}
	// An empty answer and /dev/null leave everything empty.
	st := Status{}
	parseLaunchctlPrint(nil, &st)
	parseLaunchctlPrint([]byte("gui/501/yadm-sync = {\n\tstdout path = /dev/null\n}\n"), &st)
	if st != (Status{}) {
		t.Errorf("empty: %+v", st)
	}
	// A schedule that is not installed is never broken.
	n := ExConfig
	if r := (Status{LastExit: &n, NeedsConstraintUpdate: true}).Broken(); r != "" {
		t.Errorf("not installed: %q", r)
	}
}

// Status reads the print output only when launchctl answered.
func TestLaunchdStatusReadsPrint(t *testing.T) {
	home := t.TempDir()
	plist := filepath.Join(home, "Library", "LaunchAgents", "yadm-sync.plist")
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(goldenPlist), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &fakeCmd{out: map[string]string{
		"launchctl print gui/501/yadm-sync": launchctlPrint("\truns = 7\n\tlast exit code = 78: EX_CONFIG\n\tproperties = needs LWCR update | managed LWCR | has LWCR\n"),
	}}
	s, err := New("darwin", Options{Home: home, UID: 501, Commander: c})
	if err != nil {
		t.Fatal(err)
	}
	st, _ := s.Status(context.Background())
	if !st.Loaded || st.Runs != 7 || !st.NeedsConstraintUpdate || st.Broken() == "" {
		t.Errorf("status = %+v", st)
	}
}
