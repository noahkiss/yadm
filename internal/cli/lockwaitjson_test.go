package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/noahkiss/yadm/internal/extexec"
)

// TestLockWaitUnderJSON: with --json, a command that waits for the lock
// prints nothing on stderr and one envelope on stdout. A command whose
// $YADM_PARENT_PID holds the lock exits 4 at once, whatever its
// --lock-wait.
func TestLockWaitUnderJSON(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, variantTree())
	a := kitMachine(t, root, remote, "a", "host-a")
	hooks.lockWait = 100 * time.Millisecond

	writeFile(t, filepath.Join(a.Home, ".config/one.conf"), "one\n")
	done := holdLock(t, a.State, 600*time.Millisecond)
	var out, errb bytes.Buffer
	code := Main([]string{"retag", ".config/one.conf", "work", "--json", "--lock-wait", "10s"}, &out, &errb, "test")
	<-done
	if code != ExitOK || errb.Len() != 0 {
		t.Fatalf("retag --json while the lock is held: exit %d, stderr %q", code, errb.String())
	}
	dec := json.NewDecoder(&out)
	var env Envelope
	if err := dec.Decode(&env); err != nil || !env.OK {
		t.Fatalf("stdout envelope: %v %+v", err, env)
	}
	if dec.More() {
		t.Fatal("stdout holds more than one envelope")
	}

	// A task or check of the process that holds the lock.
	t.Setenv(extexec.EnvParentPID, strconv.Itoa(os.Getpid()))
	writeFile(t, filepath.Join(a.Home, ".config/two.conf"), "two\n")
	done = holdLock(t, a.State, 3*time.Second)
	start := time.Now()
	out.Reset()
	errb.Reset()
	code = Main([]string{"retag", ".config/two.conf", "work", "--json", "--lock-wait", "10s"}, &out, &errb, "test")
	took := time.Since(start)
	<-done
	if code != ExitLocked || took > 2*time.Second || errb.Len() != 0 {
		t.Fatalf("retag under its parent's lock: exit %d after %v, stderr %q", code, took, errb.String())
	}
	if !strings.Contains(out.String(), "runs this command") {
		t.Fatalf("the error does not say the parent holds the lock:\n%s", out.String())
	}
}
