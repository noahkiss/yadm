package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
)

// TestNewRecoveryRefusesManaged: new-recovery refuses a directory that
// resolves into the source through a symlinked ancestor whose child does
// not exist yet, and one inside an owned root or a managed path, where the
// next sync would capture the secret. It creates nothing there.
func TestNewRecoveryRefusesManaged(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	a := fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	link := filepath.Join(root, "link")
	if err := os.Symlink(a.Source, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ arg, made, why string }{
		{filepath.Join(link, "missing", "rec"), filepath.Join(a.Source, "missing"), "outside"},
		{filepath.Join(a.Home, ".config", "shell", "rec"), filepath.Join(a.Home, ".config", "shell", "rec"), "manages"},
	} {
		if env, code, _ := yadm(t, "enclave", "new-recovery", c.arg); code != ExitUsage || !strings.Contains(env.Error.Message, c.why) {
			t.Fatalf("new-recovery %s: exit %d %+v", c.arg, code, env.Error)
		}
		if _, err := os.Stat(c.made); !os.IsNotExist(err) {
			t.Fatalf("a refused new-recovery created %s", c.made)
		}
	}
	// The same rules hold for --new-recovery.
	if env, code, _ := yadm(t, "enclave", "set-recovery", "--enclave", "personal", "--recovery-dir", a.State, "--new-recovery", filepath.Join(a.Config, "rec")); code != ExitUsage || !strings.Contains(env.Error.Message, "outside") {
		t.Fatalf("--new-recovery in the config directory: exit %d %+v", code, env.Error)
	}
}
