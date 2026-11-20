package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Minimal reproductions of soak findings. They run with YADM_E2E_REPRO=1
// and log what happened instead of failing, so the gate stays green while
// fixes land.

func hookEdit(m *Machine, target string) Result {
	payload, _ := json.Marshal(map[string]any{"session_id": "repro-" + m.Name, "tool_name": "Edit", "cwd": m.Home,
		"tool_input": map[string]string{"file_path": filepath.Join(m.Home, filepath.FromSlash(target))}})
	return m.RunIn(payload, "hook", "post-edit")
}

func TestReproConcurrentAppend(t *testing.T) {
	if os.Getenv("YADM_E2E_REPRO") == "" {
		t.Skip("set YADM_E2E_REPRO=1")
	}
	for _, target := range []string{".config/packages/Brewfile", synthSealed} {
		for _, via := range []string{"hook"} {
			t.Run(filepath.Base(target)+"-"+via, func(t *testing.T) {
				_, ms, _ := synthWorld(t)
				a, b := ms[0], ms[1]
				appendLine(a, target, "line-from-a")
				appendLine(b, target, "line-from-b")
				ra := commitVia(a, target, via)
				rb := commitVia(b, target, via)
				t.Logf("a %s: exit %d; b %s: exit %d %s", via, ra.Code, via, rb.Code, clip(rb.Stderr, 300))
				for _, m := range []*Machine{a, b} {
					m.Run("sync")
				}
				for _, m := range []*Machine{a, b} {
					got, _ := m.ReadHome(target)
					var reasons []string
					for _, h := range m.Holds() {
						reasons = append(reasons, h.Reason+" "+h.Target)
					}
					for _, h := range m.Holds() {
						if h.Reason != "conflict" {
							continue
						}
						f := filepath.Join(m.Root, "union")
						_ = os.WriteFile(f, []byte(string(got)+"line-from-a\n"), 0o600)
						r := m.Run("hold", "resolve", h.ID, "--take", f)
						t.Logf("%s: resolve conflict: %s", m.Name, r.Err())
						m.Run("sync")
						var after []string
						for _, h := range m.Holds() {
							after = append(after, h.Reason+" "+h.Target+" ("+clip(h.Detail, 100)+")")
						}
						got2, _ := m.ReadHome(target)
						t.Logf("%s: after resolve holds=%v has a=%v has b=%v", m.Name, after, contains(splitLines(got2), "line-from-a"), contains(splitLines(got2), "line-from-b"))
					}
					t.Logf("%s: has a=%v has b=%v holds=%v main=%v", m.Name,
						contains(splitLines(got), "line-from-a"), contains(splitLines(got), "line-from-b"), reasons, m.Main() == m.w.RemoteMain())
				}
			})
		}
	}
}

func commitVia(m *Machine, target, via string) Result {
	if via == "hook" {
		return hookEdit(m, target)
	}
	return m.Run("commit", target)
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
