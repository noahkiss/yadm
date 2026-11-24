package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// landCommandFirst makes another process on this machine run a yadm
// command to completion after the command under test has checked its change
// and before it commits: the window a lock wait opens.
func landCommandFirst(t *testing.T, args ...string) {
	t.Helper()
	hooks.beforeCommit = func(ctx context.Context) {
		hooks.beforeCommit = nil
		var out, errb bytes.Buffer
		if code := Main(append(args, "--json"), &out, &errb, "test"); code != ExitOK {
			t.Errorf("other process: yadm %v: exit %d\n%s%s", args, code, out.String(), errb.String())
		}
	}
	t.Cleanup(func() { hooks.beforeCommit = nil })
}

// TestTrackVariantKeepsAConcurrentEdit: while track --variant waits for the
// lock, another process tracks a file. The variant's commit keeps that
// entry. When the other process adds the same variant first, track --variant
// is refused with exit 2 and commits nothing.
func TestTrackVariantKeepsAConcurrentEdit(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	tree := variantTree()
	tree["manifest.toml"] = variantManifest + `
[[file]]
target = ".config/app.toml"
when = "type:work"

[[file]]
target = ".config/other.toml"
when = "type:work"
`
	tree["files/.config/app.toml"] = "work\n"
	tree["files/.config/other.toml"] = "work\n"
	remote := seedRemote(t, root, tree)
	c := kitMachine(t, root, remote, "c", "host-c")
	const app = ".config/app.toml"
	writeFile(t, filepath.Join(c.Home, app), "home\n")
	writeFile(t, filepath.Join(c.Home, ".loose"), "l\n")

	landCommandFirst(t, "track", ".loose", "--when", "type:home")
	env, code, _ := yadm(t, "track", app, "--variant", "home", "--when", "type:home")
	if code != ExitOK {
		t.Fatalf("track --variant: exit %d %+v", code, env.Error)
	}
	man := git(t, remote, "show", "main:manifest.toml")
	if !strings.Contains(man, "target = '.loose'") || !strings.Contains(man, "source = 'files/.config/app.home.toml'") {
		t.Fatalf("the variant's commit lost the concurrent track:\n%s", man)
	}

	head := git(t, c.Source, "rev-parse", "main")
	const other = ".config/other.toml"
	writeFile(t, filepath.Join(c.Home, other), "home\n")
	landCommandFirst(t, "track", other, "--variant", "home", "--when", "type:home")
	env, code, _ = yadm(t, "track", other, "--variant", "home", "--when", "type:home")
	if code != ExitUsage || env.Error == nil || !strings.Contains(env.Error.Message, "already exists") {
		t.Fatalf("a variant another process added meanwhile: exit %d %+v", code, env.Error)
	}
	if n := git(t, c.Source, "rev-list", "--count", head+"..main"); n != "1" {
		t.Fatalf("want only the other process's commit, got %s", n)
	}
}
