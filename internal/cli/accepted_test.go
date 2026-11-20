package cli

import (
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/sync"
)

// TestInitRecordsAcceptedStart: init records the clone's origin/main as the
// accepted remote, and a later sync of a normal fast-forward advances it.
func TestInitRecordsAcceptedStart(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, hookTree())
	m := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	start := model.CommitID(git(t, remote, "rev-parse", "main"))
	if id, ok := sync.ReadAccepted(m.State); !ok || id != start {
		t.Fatalf("record after init: %q %v, want %s", id, ok, start)
	}

	work := filepath.Join(root, "seed")
	writeFile(t, filepath.Join(work, "files/.config/tool/extra"), "extra\n")
	git(t, work, "add", "-A")
	git(t, work, "commit", "-q", "-m", "extra")
	git(t, work, "push", "-q", remote, "main")
	yadmOK(t, "sync")
	tip := model.CommitID(git(t, remote, "rev-parse", "main"))
	if id, _ := sync.ReadAccepted(m.State); id != tip {
		t.Fatalf("record after a fast-forward: %q, want %s", id, tip)
	}
}

// TestInitEmptyRemoteRecordsEmptyStart: a clone of an empty remote records
// the empty start, not no record.
func TestInitEmptyRemoteRecordsEmptyStart(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	git(t, root, "init", "-q", "--bare", "-b", "main", remote)
	m := useMachine(t, root, "a")
	yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
	if id, ok := sync.ReadAccepted(m.State); !ok || id != "" {
		t.Fatalf("record after an empty init: %q %v", id, ok)
	}
}
