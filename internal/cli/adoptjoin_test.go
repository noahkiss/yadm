package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fixture"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// A member adopts before it joins its enclave: adopt cannot open the sealed
// target, so the stock tool's symlink stays. After `enclave join`, apply
// takes it over (the link's content equals the render) instead of holding
// it as drift.
func TestAdoptBeforeJoinLeavesNoHolds(t *testing.T) {
	hermetic(t)
	root := t.TempDir()
	fx := fixture.Build(t)
	remote := fixtureRemote(t, root, fx)
	const tok = ".config/client-tool/token"

	// The render a member gets, from a pinned copy of the machine.
	ref := fixtureMachine(t, filepath.Join(root, "ref"), remote, fx, fixture.HostC, true)
	yadmOK(t, "apply")
	render := readFile(t, filepath.Join(ref.Home, tok))

	// The real machine: init, a stock link to a variant with that content.
	c := fixtureMachine(t, filepath.Join(root, "real"), remote, fx, fixture.HostC, false)
	variant := filepath.Join(c.Home, ".config/client-tool/token##class.client")
	writeFile(t, variant, render)
	if err := os.Symlink("token##class.client", filepath.Join(c.Home, tok)); err != nil {
		t.Fatal(err)
	}
	yadm(t, "adopt", "--no-schedule", "--allow-tasks")
	if li, err := os.Lstat(filepath.Join(c.Home, tok)); err != nil || li.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("adopt replaced a sealed target it could not open: %v %v", li, err)
	}
	yadm(t, "sync")

	logs := fx.Logs["client"]
	fp, err := crypt.Fingerprint(logs[len(logs)-1])
	if err != nil {
		t.Fatal(err)
	}
	yadmOK(t, "enclave", "join", "client", "--expect", fp)
	yadm(t, "sync")

	env := yadmOK(t, "hold", "list")
	if hs := decode[map[string][]model.Hold](t, env.Data)["holds"]; len(hs) != 0 {
		for _, h := range hs {
			t.Errorf("hold after join: %s %s %s", h.Target, h.Reason, h.Detail)
		}
		t.FailNow()
	}
	li, err := os.Lstat(filepath.Join(c.Home, tok))
	if err != nil || !li.Mode().IsRegular() {
		t.Fatalf("link not materialized: %v %v", li, err)
	}
	if readFile(t, filepath.Join(c.Home, tok)) != render || readFile(t, variant) != render {
		t.Fatal("content or link target changed")
	}
	secrecytest.AssertRepoClean(t, remote, fx.AllCanaries()...)
}
