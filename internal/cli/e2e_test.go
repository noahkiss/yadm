package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/apply"
	"github.com/noahkiss/yadm/internal/model"
)

const e2eFleet = `schema = 1

[types.work]

[machines.m-aaaaaa000001]
name = "host-a"
types = ["work"]
os = "linux"
arch = "amd64"

[machines.m-bbbbbb000002]
name = "host-b"
types = ["work"]
os = "linux"
arch = "amd64"
`

const e2eManifest = `schema = 1

[[file]]
target = ".config/tool/config"
`

func e2eTree() map[string]string {
	return map[string]string{
		"fleet.toml":                "# synthetic fleet\n" + e2eFleet,
		"manifest.toml":             e2eManifest,
		"files/.config/tool/config": "color = blue\n",
	}
}

// TestEndToEnd drives the CLI on two fake machines that share one bare
// remote: init, apply, add a file, status, commit, push, then clone on a
// second machine and apply.
func TestEndToEnd(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, e2eTree())

	// Machine A.
	a := useMachine(t, root, "a")
	env := yadmOK(t, "init", remote, "--machine", "host-a")
	in := decode[initData](t, env.Data)
	if in.Machine != "m-aaaaaa000001" || !in.InFleet || !strings.HasPrefix(in.Recipient, "age1") || in.SignKey == "" {
		t.Fatalf("init data: %+v", in)
	}
	if !in.Schedule.Installed {
		t.Fatalf("init did not install the (fake) schedule: %+v", in.Schedule)
	}
	if _, code, _ := yadm(t, "init", remote, "--machine", "host-a"); code != ExitError {
		t.Fatalf("second init must refuse, got exit %d", code)
	}

	env = yadmOK(t, "apply")
	if got := readFile(t, filepath.Join(a.Home, ".config/tool/config")); got != "color = blue\n" {
		t.Fatalf("apply on a: %q", got)
	}

	// Add a file: a new source file and a manifest entry, committed and
	// pushed with plain git on the source clone.
	writeFile(t, filepath.Join(a.Source, "files/.config/tool/extra"), "extra = 1\n")
	writeFile(t, filepath.Join(a.Source, "manifest.toml"), e2eManifest+"\n[[file]]\ntarget = \".config/tool/extra\"\n")
	for _, args := range [][]string{{"git", "add", "-A"}, {"git", "commit", "-q", "-m", "add extra"}} {
		if _, stderr, code := yadmRaw(t, args...); code != 0 {
			t.Fatalf("yadm %v: exit %d %s", args, code, stderr)
		}
	}
	env = yadmOK(t, "managed", ".config/tool/extra")
	if md := decode[managedData](t, env.Data); !md.Managed || md.Source != "files/.config/tool/extra" {
		t.Fatalf("managed: %+v", md)
	}
	yadmOK(t, "apply")
	if got := readFile(t, filepath.Join(a.Home, ".config/tool/extra")); got != "extra = 1\n" {
		t.Fatalf("extra on a: %q", got)
	}

	// Edit a target: status reports drift.
	writeFile(t, filepath.Join(a.Home, ".config/tool/config"), "color = green\n")
	env = yadmOK(t, "status")
	st := decode[statusData](t, env.Data)
	if len(st.Drift) != 1 || st.Drift[0].Target != ".config/tool/config" || st.Drift[0].Kind != apply.DriftModified {
		t.Fatalf("status drift: %+v", st.Drift)
	}
	env = yadmOK(t, "diff")
	if s := mustJSON(t, env.Data); !strings.Contains(s, "+color = green") {
		t.Fatalf("diff: %s", s)
	}

	// Commit. While sync.Commit is a stub, it must answer with a clean
	// not_implemented envelope; the test then commits with plain git.
	env, code, _ := yadm(t, "commit", "-m", "green")
	switch code {
	case ExitOK, ExitAttention:
	case ExitNotImplemented:
		writeFile(t, filepath.Join(a.Source, "files/.config/tool/config"), "color = green\n")
		for _, args := range [][]string{{"git", "add", "-A"}, {"git", "commit", "-q", "-m", "green"}} {
			if _, stderr, code := yadmRaw(t, args...); code != 0 {
				t.Fatalf("yadm %v: exit %d %s", args, code, stderr)
			}
		}
	default:
		t.Fatalf("commit: exit %d %+v", code, env.Error)
	}
	if _, stderr, code := yadmRaw(t, "git", "push", "-q", "origin", "main"); code != 0 {
		t.Fatalf("push: %s", stderr)
	}

	// Machine B clones and applies.
	b := useMachine(t, root, "b")
	env = yadmOK(t, "clone", remote, "--machine", "host-b", "--no-schedule")
	if in := decode[initData](t, env.Data); in.Machine != "m-bbbbbb000002" || !in.Schedule.Skipped {
		t.Fatalf("clone data: %+v", in)
	}
	env = yadmOK(t, "apply")
	res := decode[apply.Result](t, env.Data)
	if len(res.Holds) != 0 {
		t.Fatalf("apply on b held: %+v", res.Holds)
	}
	if got := readFile(t, filepath.Join(b.Home, ".config/tool/config")); got != "color = green\n" {
		t.Fatalf("config on b: %q", got)
	}
	if got := readFile(t, filepath.Join(b.Home, ".config/tool/extra")); got != "extra = 1\n" {
		t.Fatalf("extra on b: %q", got)
	}
	env, code, _ = yadm(t, "status")
	if code != ExitOK || len(decode[statusData](t, env.Data).Drift) != 0 {
		t.Fatalf("status on b: exit %d %+v", code, env.Data)
	}

	// Query API on b.
	env = yadmOK(t, "machine")
	if md := decode[machineData](t, env.Data); md.ID != "m-bbbbbb000002" || md.Name != "host-b" {
		t.Fatalf("machine: %+v", md)
	}
	env = yadmOK(t, "why", filepath.Join(b.Home, ".config/tool/config"))
	if ex := decode[map[string]any](t, env.Data); ex["managed"] != true || ex["target"] != ".config/tool/config" {
		t.Fatalf("why: %+v", ex)
	}
	env = yadmOK(t, "where")
	if w := decode[Paths](t, env.Data); w.Source != b.Source {
		t.Fatalf("where: %+v", w)
	}
	env = yadmOK(t, "log")
	if cs := decode[map[string][]logCommit](t, env.Data)["commits"]; len(cs) < 2 {
		t.Fatalf("log: %+v", cs)
	}
	env = yadmOK(t, "hold", "list")
	if hs := decode[map[string][]model.Hold](t, env.Data)["holds"]; len(hs) != 0 {
		t.Fatalf("holds: %+v", hs)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	return string(decode[rawJSON](t, v))
}

type rawJSON []byte

func (r *rawJSON) UnmarshalJSON(b []byte) error { *r = append((*r)[:0], b...); return nil }
