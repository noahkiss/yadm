package model

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellQuoteRoundTrips(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	for _, s := range []string{
		".config/tool/config",
		".config/tool/new;touch INJECTED;.conf",
		"a b",
		"it's",
		"$(touch INJECTED)",
		"`touch INJECTED`",
		"x\ny",
		"*",
		"",
	} {
		cmd := exec.Command("sh", "-c", "printf '%s' "+ShellQuote(s))
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if string(out) != s {
			t.Errorf("%q came back as %q", s, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "INJECTED")); err == nil {
		t.Fatal("a quoted word ran a command")
	}
	if got := ShellQuote(".config/tool/config"); got != ".config/tool/config" {
		t.Errorf("safe word quoted: %s", got)
	}
}

func TestHasControl(t *testing.T) {
	for s, want := range map[string]bool{"a/b.conf": false, "a\nb": true, "a\rb": true, "a\x00b": true, "a\x1bb": true, "a b": false, "ü": false} {
		if HasControl(s) != want {
			t.Errorf("%q: want %v", strings.ToValidUTF8(s, "?"), want)
		}
	}
}
