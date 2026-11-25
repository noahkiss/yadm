package cli

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/fixture"
)

// TestList: yadm list prints the targets this machine manages, sorted, and
// with --as those of another fleet machine. It reads no file content, so no
// enclave plaintext reaches its output, and an unknown machine exits 2.
func TestList(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	fixtureMachine(t, root, remote, fx, fixture.HostA, true)
	yadmOK(t, "apply")

	type listOut struct {
		Machine string
		Targets []struct{ Target, Source, Scope string }
	}
	names := func(d listOut) []string {
		var out []string
		for _, x := range d.Targets {
			out = append(out, x.Target)
		}
		return out
	}
	env, code, raw := yadm(t, "list")
	if code != ExitOK {
		t.Fatalf("list: exit %d %+v", code, env.Error)
	}
	d := decode[listOut](t, env.Data)
	got := names(d)
	if d.Machine != string(fixture.HostA) || !slices.IsSorted(got) || !slices.Contains(got, ".config/notes/private.md") || slices.Contains(got, ".config/client-tool/token") {
		t.Fatalf("list on host-a: %+v", d)
	}
	for _, x := range d.Targets {
		if x.Target == ".config/notes/private.md" && (x.Scope != "personal" || x.Source != "sealed/personal/.config/notes/private.md") {
			t.Fatalf("sealed entry: %+v", x)
		}
	}
	env, code, rawAs := yadm(t, "list", "--as", string(fixture.HostC))
	if code != ExitOK {
		t.Fatalf("list --as: exit %d %+v", code, env.Error)
	}
	if got := names(decode[listOut](t, env.Data)); !slices.Contains(got, ".config/client-tool/token") || slices.Contains(got, ".config/notes/private.md") {
		t.Fatalf("list --as host-c: %v", got)
	}
	for _, o := range [][]byte{raw, rawAs} {
		for _, c := range fx.AllCanaries() {
			if bytes.Contains(o, c.Bytes()) {
				t.Fatal("list printed file content")
			}
		}
	}
	if _, code, _ := yadm(t, "list", "--as", "no-such-machine"); code != ExitUsage {
		t.Fatalf("list --as an unknown machine: exit %d", code)
	}

	var out, errb bytes.Buffer
	if code := Main([]string{"list"}, &out, &errb, "test"); code != ExitOK || !strings.Contains(out.String(), ".config/notes/private.md\n") {
		t.Fatalf("list text: exit %d\n%s%s", code, out.String(), errb.String())
	}
}
