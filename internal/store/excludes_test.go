package store

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGlobalExcludesDoNotApply: the user's global ignore rules, set by
// core.excludesFile or found at the XDG default, never hide a file in the
// source clone from git calls the tool runs. A .gitignore in the source
// still applies.
func TestGlobalExcludesDoNotApply(t *testing.T) {
	ctx := context.Background()
	for _, how := range []string{"core.excludesFile", "xdg default"} {
		t.Run(how, func(t *testing.T) {
			_, a, _ := seeded(t)
			cfgHome := t.TempDir()
			t.Setenv("XDG_CONFIG_HOME", cfgHome)
			ignore := filepath.Join(cfgHome, "git", "ignore")
			if how == "core.excludesFile" {
				ignore = filepath.Join(t.TempDir(), "global-ignore")
				global := filepath.Join(t.TempDir(), "gitconfig")
				if err := os.WriteFile(global, []byte("[core]\n\texcludesFile = "+ignore+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Setenv("GIT_CONFIG_GLOBAL", global)
			}
			for p, body := range map[string]string{
				ignore: "*.local/\n",
				filepath.Join(a.Dir(), "files/.local/libexec/dotfiles/new-script"): "#!/bin/sh\n",
				filepath.Join(a.Dir(), ".gitignore"):                               "*.tmp\n",
				filepath.Join(a.Dir(), "files/scratch.tmp"):                        "x\n",
			} {
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			const script = "files/.local/libexec/dotfiles/new-script"
			// Plain git honors the global rule: the setup reproduces the bug.
			if raw := rawGit(t, a.Dir(), "status", "--porcelain", "-uall"); strings.Contains(raw, script) {
				t.Fatalf("plain git does not ignore the file; the test setup is wrong:\n%s", raw)
			}
			out, err := Output(ctx, a.Dir(), "status", "--porcelain", "-uall")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), "?? "+script) {
				t.Fatalf("a global exclude hid %s from the clone:\n%s", script, out)
			}
			if strings.Contains(string(out), "scratch.tmp") {
				t.Fatalf("the source's own .gitignore stopped applying:\n%s", out)
			}
			var stdout, stderr bytes.Buffer
			if code, err := a.Git(ctx, nil, &stdout, &stderr, "add", "--", script); err != nil || code != 0 {
				t.Fatalf("yadm git add without -f: exit %d %v %s", code, err, stderr.String())
			}
		})
	}
}
