package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (Envelope, int, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, &out, &errb, "test")
	var env Envelope
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not one JSON envelope: %v\n%s", err, out.String())
	}
	return env, code, errb.String()
}

func TestVersionJSON(t *testing.T) {
	env, code, stderr := run(t, "version", "--json")
	if code != ExitOK || !env.OK || env.Command != "version" || env.Schema != EnvelopeSchema {
		t.Fatalf("code=%d env=%+v", code, env)
	}
	if env.Data.(map[string]any)["version"] != "test" {
		t.Fatalf("data=%v", env.Data)
	}
	if stderr != "" {
		t.Fatalf("--json wrote to stderr: %q", stderr)
	}
}

// TestUninitializedMachine: commands that need a set-up machine fail with
// one clean envelope and point at init.
func TestUninitializedMachine(t *testing.T) {
	hermetic(t)
	useMachine(t, t.TempDir(), "x")
	for _, args := range [][]string{
		{"status"}, {"apply"}, {"machine"}, {"fleet", "list"}, {"hold", "list"}, {"check"},
	} {
		env, code, _ := yadm(t, args...)
		if code != ExitError || len(env.Next) == 0 || !strings.HasPrefix(env.Next[0], "yadm init") {
			t.Fatalf("%v: code=%d env=%+v", args, code, env)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	env, code, _ := run(t, "--json", "no-such-command-xyz")
	if code != ExitUsage || env.Error == nil || env.Error.Code != CodeUsage {
		t.Fatalf("code=%d env=%+v", code, env)
	}
	for _, args := range [][]string{{"--json"}, {"fleet", "--json"}, {"enclave", "--json"}} {
		env, code, _ = run(t, args...)
		if code != ExitUsage || env.Error == nil || env.Error.Code != CodeUsage || len(env.Next) == 0 {
			t.Fatalf("%v: code=%d env=%+v", args, code, env)
		}
	}
	env, code, _ = run(t, "apply", "--json", "--no-such-flag")
	if code != ExitUsage || env.Error == nil || env.Error.Code != CodeUsage {
		t.Fatalf("code=%d env=%+v", code, env)
	}
}
