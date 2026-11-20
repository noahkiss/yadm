package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

// resolvingStore is a fakeStore whose refs resolve to themselves, so the
// real Engine.Load can run on it.
type resolvingStore struct{ *fakeStore }

func (s resolvingStore) ResolveRef(_ context.Context, ref string) (model.CommitID, error) {
	return model.CommitID(ref), nil
}

const namedFleet = `schema = 1
[types.work]
[machines.m-test01]
name = "host-a"
types = ["work"]
os = "linux"
arch = "amd64"
`

// TestLoadNamedConditionsFromInclude proves Load reads conditions.include
// from the commit it loads and that templates see the named conditions.
func TestLoadNamedConditionsFromInclude(t *testing.T) {
	st := newFakeStore(t.TempDir())
	files := map[model.SourcePath][]byte{
		"fleet.toml": []byte(namedFleet),
		"manifest.toml": []byte(`schema = 1
[conditions]
include = ["conds/extra.toml"]
[[file]]
target = ".config/a"
when = "cond:linux.work"
[[file]]
target = ".config/b"
when = "!cond:linux.work"
`),
		"conds/extra.toml": []byte("[conditions]\nlinux.work = \"os:linux & type:work\"\n"),
		"files/.config/a":  []byte("a\n"),
		"files/.config/b":  []byte("b\n"),
	}
	for _, b := range files {
		st.blobs[blobID(b)] = b
	}
	st.commits["c1"] = files
	eng := New(Deps{Store: resolvingStore{st}, Self: "m-test01", State: FileStateDB(t.TempDir()), Home: t.TempDir(), User: "user"})
	snap, err := eng.Load(context.Background(), "c1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snap.Plan.Targets[".config/a"]; !ok {
		t.Error(".config/a not planned")
	}
	if _, ok := snap.Plan.Targets[".config/b"]; ok {
		t.Error(".config/b planned")
	}
	out, err := snap.Render.Render(".config/t", []byte("{% if cond:linux.work %}yes{% else %}no{% endif %}\n"), snap.Context)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "yes\n" {
		t.Errorf("template = %q", out)
	}

	// A missing include fails the load loudly.
	delete(files, "conds/extra.toml")
	if _, err := eng.Load(context.Background(), "c1"); err == nil || !strings.Contains(err.Error(), "conds/extra.toml") {
		t.Errorf("load without include: %v", err)
	}
}
