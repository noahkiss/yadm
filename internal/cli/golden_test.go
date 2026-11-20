package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

var update = flag.Bool("update", false, "rewrite the golden envelopes in testdata/golden")

// volatileKeys are replaced by a placeholder wherever they appear.
var volatileKeys = map[string]bool{
	"go": true, "os": true, "arch": true, "recipient": true, "sign_key": true,
	"since": true, "when": true, "last_sync": true, "collected_at": true, "mtime": true,
	"started": true, "duration_ns": true, "author": true, "unit_path": true, "last_run": true,
	"detail": true,
}

var (
	reOID     = regexp.MustCompile(`\b[0-9a-f]{40}\b`)
	reHash    = regexp.MustCompile(`\b[0-9a-f]{64}\b`)
	reMID     = regexp.MustCompile(`\bm-[0-9a-f]{12}\b`)
	reTime    = regexp.MustCompile(`^\d{4}-\d\d-\d\dT`)
	reAge     = regexp.MustCompile(`\bage1[0-9a-z]{20,}`)
	reSignArg = regexp.MustCompile(`--sign-key \S+`)
)

// normalize rewrites an envelope so it is stable across runs and machines and
// names nothing local: temp paths, ids, hashes and times become placeholders.
func normalize(t *testing.T, raw []byte, root string) []byte {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var walk func(key string, v any) any
	walk = func(key string, v any) any {
		if s, ok := v.(string); ok && key == "when" && !reTime.MatchString(s) {
			return v // a condition, not a commit time
		}
		if volatileKeys[key] {
			if v == nil {
				return nil
			}
			return "<" + key + ">"
		}
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				x[k] = walk(k, e)
			}
			return x
		case []any:
			for i, e := range x {
				x[i] = walk("", e)
			}
			return x
		case string:
			s := strings.ReplaceAll(x, root, "$TMP")
			s = reHash.ReplaceAllString(s, "<sha256>")
			s = reOID.ReplaceAllString(s, "<oid>")
			s = reMID.ReplaceAllString(s, "<machine-id>")
			s = reAge.ReplaceAllString(s, "<recipient>")
			s = reSignArg.ReplaceAllString(s, "--sign-key <sign_key>")
			return s
		}
		return v
	}
	v = walk("", v)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func golden(t *testing.T, name string, raw []byte, root string) {
	t.Helper()
	got := normalize(t, raw, root)
	path := filepath.Join("testdata", "golden", name+".json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run go test ./internal/cli -run TestGolden -update)", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s envelope changed:\n--- want\n%s\n--- got\n%s", name, want, got)
	}
}

const goldenFleet = `schema = 1

[types.work]

[types.other]

[types.vault]
enclave = true

[machines.m-aaaaaa000001]
name = "host-a"
types = ["work", "vault"]
os = "linux"
arch = "amd64"

[machines.m-bbbbbb000002]
name = "host-b"
types = ["work"]
os = "linux"
arch = "amd64"

[machines.m-cccccc000003]
name = "host-c"
types = ["other"]
os = "linux"
arch = "amd64"

[collectors.packages]
command = ["echo", "tool-one"]
publish = "plain"
`

const goldenManifest = `schema = 1

[[file]]
target = ".config/tool/config"

[[file]]
target = ".config/tool/only-mac"
when = "os:darwin"

[[file]]
target = ".config/tool/retag-me"
when = "type:work"

[[file]]
target = ".config/tool/extra"

[tasks.bundle]
on = [".config/tool/config"]
command = ["pkg-tool", "bundle"]
`

// TestGolden records the envelope of every command that works without the
// sync package, plus the error envelopes of the contract. Commands backed by
// sync stubs are covered by TestEveryCommandOneEnvelope instead, so they do
// not pin stub behaviour.
func TestGolden(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, map[string]string{
		"fleet.toml":                   goldenFleet,
		"manifest.toml":                goldenManifest,
		"files/.config/tool/config":    "color = blue\n",
		"files/.config/tool/only-mac":  "mac\n",
		"files/.config/tool/retag-me":  "work only\n",
		"files/.config/tool/extra":     "extra\n",
		"files/.config/tool/unrelated": "x\n",
	})
	run := func(name string, wantCode int, args ...string) Envelope {
		t.Helper()
		env, code, raw := yadm(t, args...)
		if code != wantCode {
			t.Fatalf("%s: exit %d, want %d\n%s", name, code, wantCode, raw)
		}
		golden(t, name, raw, root)
		return env
	}

	useMachine(t, root, "fresh")
	run("version", ExitOK, "version")
	run("where", ExitOK, "where")
	run("status-not-initialized", ExitError, "status")
	run("usage-unknown-command", ExitUsage, "no-such-command-xyz")
	run("usage-group", ExitUsage, "fleet")
	run("usage-bad-flag", ExitUsage, "apply", "--no-such-flag")
	run("usage-args", ExitUsage, "why")
	run("legacy-alt", ExitUsage, "alt")
	run("legacy-encrypt", ExitUsage, "encrypt")
	run("explain-init", ExitOK, "explain", "init")
	run("explain-unknown", ExitUsage, "explain", "frobnicate")
	run("bisect-no-as", ExitUsage, "bisect")
	run("bisect", ExitNotImplemented, "bisect", "--as", "host-a")
	run("help-fleet", ExitOK, "fleet", "--help")

	legacy := filepath.Join(root, "legacy")
	git(t, root, "init", "-q", "-b", "main", legacy)
	writeFile(t, filepath.Join(legacy, ".config/app/settings##os.Linux"), "linux\n")
	writeFile(t, filepath.Join(legacy, ".config/app/settings##default"), "default\n")
	git(t, legacy, "add", "-A")
	git(t, legacy, "commit", "-q", "-m", "legacy")
	run("import", ExitOK, "import", legacy, "--output", filepath.Join(root, "imported"))

	bin := filepath.Join(root, "bin")
	writeFile(t, filepath.Join(bin, "yadm-hello"), "#!/bin/sh\ncat >/dev/null\necho '{\"schema\":1,\"ok\":true,\"items\":[\"x\"],\"message\":\"hi\",\"data\":{\"k\":1}}'\n")
	if err := os.Chmod(filepath.Join(bin, "yadm-hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	run("external", ExitOK, "hello", "world")

	a := useMachine(t, root, "a")
	run("init", ExitOK, "init", remote, "--machine", "host-a", "--allow-tasks")
	run("explain-apply", ExitOK, "explain", "apply")
	run("apply", ExitOK, "apply")
	run("apply-noop", ExitOK, "apply", "--dry-run")
	run("machine", ExitOK, "machine")
	run("why", ExitOK, "why", ".config/tool/only-mac")
	run("why-unmanaged", ExitOK, "why", ".config/other")
	run("managed", ExitOK, "managed", ".config/tool/config")
	run("managed-outside-home", ExitUsage, "managed", "/elsewhere/file")
	run("log", ExitOK, "log")
	run("log-patch", ExitNotImplemented, "log", "-p")
	run("task-list", ExitOK, "task", "list")
	run("collect", ExitOK, "collect")
	run("enclave-list", ExitOK, "enclave", "list")
	run("enclave-verify", ExitOK, "enclave", "verify")
	run("enclave-join-no-expect", ExitUsage, "enclave", "join", "vault")
	run("enclave-create-no-recovery", ExitUsage, "enclave", "create", "vault")
	run("enclave-create", ExitOK, "enclave", "create", "vault", "--new-recovery", filepath.Join(root, "recovery"))
	run("enclave-list-created", ExitOK, "enclave", "list")
	run("fleet-list", ExitOK, "fleet", "list")
	run("fleet-show", ExitOK, "fleet", "show", "host-a")
	run("fleet-diff", ExitOK, "fleet", "diff", "packages")
	run("fleet-diff-unknown", ExitUsage, "fleet", "diff", "nope")
	run("hold-list-empty", ExitOK, "hold", "list")
	run("conflicts-empty", ExitOK, "conflicts")
	run("hold-resolve-no-take", ExitUsage, "hold", "resolve", "abc")
	run("schedule-status", ExitOK, "schedule", "status")
	run("check", ExitError, "check")

	writeFile(t, filepath.Join(a.Home, ".config/tool/config"), "color = red\n")
	run("status-drift", ExitOK, "status")
	run("capture", ExitOK, "capture")
	run("diff", ExitOK, "diff")
	run("apply-drifted", ExitAttention, "apply")
	env := run("hold-list", ExitAttention, "hold", "list")
	run("status-held", ExitAttention, "status")
	hs := decode[map[string][]map[string]any](t, env.Data)["holds"]
	if len(hs) != 1 {
		t.Fatalf("holds: %v", hs)
	}
	run("hold-show", ExitOK, "hold", "show", hs[0]["id"].(string))

	// Retag a work-only file into the vault enclave: host-b loses it; host-c
	// never had it and is not listed.
	env = run("retag", ExitOK, "retag", ".config/tool/retag-me", "vault", "--enclave", "vault")
	if lost := decode[struct {
		RemovedOn []string `json:"removed_on"`
	}](t, env.Data).RemovedOn; len(lost) != 1 || lost[0] != "m-bbbbbb000002" {
		t.Fatalf("removed_on: %v", lost)
	}
	src := useMachineSource(a)
	if out := git(t, src, "ls-tree", "-r", "--name-only", "HEAD"); !strings.Contains(out, "sealed/vault/.config/tool/retag-me") || strings.Contains(out, "files/.config/tool/retag-me") {
		t.Fatalf("retag tree:\n%s", out)
	}

	// Adopt on host-b: one identical target, one differing, one missing.
	b := useMachine(t, root, "b")
	yadmOK(t, "init", remote, "--machine", "host-b", "--no-schedule")
	writeFile(t, filepath.Join(b.Home, ".config/tool/config"), "color = blue\n")
	writeFile(t, filepath.Join(b.Home, ".config/tool/retag-me"), "mine\n")
	run("adopt-dry-run", ExitAttention, "adopt", "--dry-run", "--allow-tasks")
	for _, p := range []string{
		filepath.Join(b.Home, ".config/tool/extra"),
		filepath.Join(b.State, "allowed.json"),
		filepath.Join(b.State, "state.json"),
		filepath.Join(b.Home, ".config/systemd/user/yadm-sync.timer"),
	} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("adopt --dry-run wrote %s", p)
		}
	}
	if got := readFile(t, filepath.Join(b.Home, ".config/tool/retag-me")); got != "mine\n" {
		t.Fatalf("adopt --dry-run changed a differing target: %q", got)
	}
	run("adopt", ExitAttention, "adopt", "--no-schedule")
	if got := readFile(t, filepath.Join(b.Home, ".config/tool/extra")); got != "extra\n" {
		t.Fatalf("adopt did not write the missing target: %q", got)
	}
	if got := readFile(t, filepath.Join(b.Home, ".config/tool/retag-me")); got != "mine\n" {
		t.Fatalf("adopt overwrote a differing target: %q", got)
	}
}

func useMachineSource(m machineDirs) string { return m.Source }

// TestEveryCommandOneEnvelope walks the command tree. Every command, with no
// arguments and with --help, prints exactly one envelope whose ok and error
// agree with the exit code, on a set-up machine and on a fresh one.
func TestEveryCommandOneEnvelope(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	remote := seedRemote(t, root, e2eTree())
	var paths [][]string
	var walk func(c *cobra.Command, prefix []string)
	walk = func(c *cobra.Command, prefix []string) {
		for _, s := range c.Commands() {
			p := append(append([]string{}, prefix...), s.Name())
			if s.Name() == "git" || s.Name() == "help" {
				continue
			}
			paths = append(paths, p)
			walk(s, p)
		}
	}
	walk(NewRoot("test"), nil)
	sort.Slice(paths, func(i, j int) bool { return strings.Join(paths[i], " ") < strings.Join(paths[j], " ") })
	if len(paths) < 50 {
		t.Fatalf("command tree has only %d commands", len(paths))
	}

	for _, setup := range []string{"fresh", "ready"} {
		useMachine(t, root, setup)
		if setup == "ready" {
			yadmOK(t, "init", remote, "--machine", "host-a", "--no-schedule")
			yadmOK(t, "apply")
		}
		for _, p := range paths {
			if p[0] == "init" || p[0] == "clone" || p[0] == "import" || (p[0] == "schedule" && len(p) > 1 && p[1] != "status") {
				continue // they change state; covered elsewhere
			}
			env, code, _ := yadm(t, p...)
			if env.Command == "" && len(p) > 0 && code != ExitUsage {
				t.Errorf("%s %v: empty command name", setup, p)
			}
			env, code, _ = yadm(t, append(p, "--help")...)
			if isLegacy(p[0]) {
				// A removed verb always exits non-zero with its replacement.
				if code != ExitUsage || len(env.Next) == 0 {
					t.Errorf("%s %v: exit %d next=%v", setup, p, code, env.Next)
				}
			} else if code != ExitOK {
				t.Errorf("%s %v --help: exit %d %+v", setup, p, code, env.Error)
			}
		}
	}
}

func isLegacy(name string) bool {
	for _, v := range legacyVerbs {
		if v.name == name {
			return true
		}
	}
	return false
}
