package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/sync"
)

// TestNetworkLockVisible: a held network lock makes sync and commit skip
// their network steps and say so; status lists an old lock and an active
// network backoff; the locked error names the holder.
func TestNetworkLockVisible(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	m := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	yadmOK(t, "apply")

	release, err := sync.FileNetLock(m.State).TryAcquire()
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(m.Home, ".config/tool/config"), "color = green\n")
	env := yadmOK(t, "commit", ".config/tool/config")
	cd := decode[map[string]any](t, env.Data)
	if pe, _ := cd["push_error"].(string); !strings.Contains(pe, "network") || cd["pushed"] == true {
		t.Errorf("commit with a busy network: %+v", cd)
	}
	env = yadmOK(t, "sync")
	rep := decode[sync.Report](t, env.Data)
	if !strings.Contains(rep.Network, "fetch skipped") || rep.Pushed {
		t.Errorf("sync with a busy network: network %q pushed %v", rep.Network, rep.Pushed)
	}
	release()
	env = yadmOK(t, "sync")
	if rep = decode[sync.Report](t, env.Data); !rep.Pushed || rep.Network != "" {
		t.Errorf("sync after release: network %q pushed %v", rep.Network, rep.Pushed)
	}
	if got := git(t, remote, "show", "main:files/.config/tool/config"); got != "color = green" {
		t.Errorf("remote holds %q", got)
	}

	// A holder record 30 s old in the sync lock, and a backoff ahead.
	rec := fmt.Sprintf(`{"pid":%d,"command":"yadm sync --auto","since":%q}`, os.Getpid(), time.Now().Add(-30*time.Second).Format(time.RFC3339))
	if err := os.WriteFile(filepath.Join(m.State, sync.LockFile), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	qp := filepath.Join(m.State, sync.QuickFile)
	q := map[string]any{}
	if b, err := os.ReadFile(qp); err == nil {
		_ = json.Unmarshal(b, &q)
	}
	q["net_failures"], q["net_retry_at"] = 2, time.Now().Add(10*time.Minute).Format(time.RFC3339)
	b, _ := json.Marshal(q)
	if err := os.WriteFile(qp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	env = yadmOK(t, "status")
	sd := decode[struct {
		Locks      []sync.HeldLock `json:"locks"`
		NetBackoff *time.Time      `json:"net_backoff_until"`
	}](t, env.Data)
	if len(sd.Locks) != 1 || sd.Locks[0].Lock != sync.LockSync || sd.Locks[0].Holder.PID != os.Getpid() {
		t.Errorf("status locks %+v", sd.Locks)
	}
	if sd.NetBackoff == nil {
		t.Error("status shows no network backoff")
	}
	out, _, _ := yadmRaw(t, "status")
	if !strings.Contains(out, "sync lock held") || !strings.Contains(out, "network backoff") {
		t.Errorf("status text:\n%s", out)
	}

	// Past the wait, the locked error names the holder.
	hooks.lockWait = 100 * time.Millisecond
	lrel, err := sync.FileLock(m.State).Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	env, code, _ := yadm(t, "commit", ".config/tool/config")
	lrel()
	if code != ExitLocked || env.Error == nil || !strings.Contains(env.Error.Message, fmt.Sprintf("pid %d", os.Getpid())) {
		t.Fatalf("locked commit: exit %d %+v", code, env.Error)
	}
}
