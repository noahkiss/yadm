package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenLive renders this machine's real wiring from the real units
// file through the real yadm, without writing. It runs only when a
// contributor opts in with YADM_AGENTS_GOLDEN=1 and writes its report to
// YADM_AGENTS_GOLDEN_OUT (default: a temp directory), never into the
// repository. It fails when a harness refuses; differences are reported,
// since some are intended.
func TestGoldenLive(t *testing.T) {
	if os.Getenv("YADM_AGENTS_GOLDEN") != "1" {
		t.Skip("set YADM_AGENTS_GOLDEN=1 to render this machine's live wiring")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	c := &cli{}
	c.home = home
	c.resolvePaths()
	f, err := Load(c.units)
	if err != nil {
		t.Fatal(err)
	}
	ev := newYadmEval()
	rs, err := Gen(f, ev, GenOptions{Home: home, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	report := formatResults(rs, true)
	out := os.Getenv("YADM_AGENTS_GOLDEN_OUT")
	if out == "" {
		out = t.TempDir()
	}
	if err := os.WriteFile(filepath.Join(out, "golden.txt"), []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("report: %s\n%s", filepath.Join(out, "golden.txt"), report)
	for _, r := range rs {
		if r.Status == StatusRefused {
			t.Errorf("%s refused: %s", r.Harness, r.Reason)
		}
	}
}
