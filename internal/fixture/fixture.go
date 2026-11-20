// Package fixture builds the synthetic multi-machine source repository from
// testdata/fixture for tests. Every name and byte in it is fake.
//
// Inputs under testdata/fixture:
//
//   - source/: the plaintext part of a source tree (fleet.toml, manifest.toml,
//     files/...). Placeholders `@@SEAL:<enclave>:<keypath>@@` and
//     `@@REGION:<enclave>:<label>@@` mark sealed values and regions.
//   - enclave-plain/<enclave>/<target>: whole files to seal into
//     sealed/<enclave>/<target>.
//   - value-plain/<enclave>/<keypath> and region-plain/<enclave>/<label>: the
//     plaintext of sealed values and regions.
//
// Every `@@CANARY@@` in plaintext inputs becomes the enclave's canary, so a
// test can prove with package secrecytest that the plaintext stays inside
// the enclave.
//
// Build needs package crypt. Until crypt is implemented, Build skips the test.
package fixture

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// Machines in the fixture fleet.
const (
	HostA model.MachineID = "m-a1b2c3" // personal
	HostB model.MachineID = "m-d4e5f6" // work
	HostC model.MachineID = "m-g7h8i9" // work, client
)

// Enclaves in the fixture fleet and their members.
var Members = map[model.EnclaveName][]model.MachineID{
	"personal": {HostA},
	"client":   {HostC},
}

// Dir returns the absolute path of testdata/fixture.
func Dir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "fixture")
}

// LegacyDir returns the absolute path of testdata/legacy.
func LegacyDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata", "legacy")
}

// Fixture is a built source tree.
type Fixture struct {
	Root       string // source tree (not yet a git repository; tests choose how to commit it)
	Canaries   map[model.EnclaveName]secrecytest.Canary
	Identities map[model.MachineID]*crypt.Identity
	Recovery   *crypt.Identity
}

// AllCanaries returns every enclave canary.
func (f *Fixture) AllCanaries() []secrecytest.Canary {
	var out []secrecytest.Canary
	for _, c := range f.Canaries {
		out = append(out, c)
	}
	return out
}

// Build writes the fixture source tree into a temp directory.
func Build(t testing.TB) *Fixture {
	t.Helper()
	f := &Fixture{
		Root:       t.TempDir(),
		Canaries:   map[model.EnclaveName]secrecytest.Canary{},
		Identities: map[model.MachineID]*crypt.Identity{},
	}
	for e := range Members {
		f.Canaries[e] = secrecytest.NewCanary(t, string(e))
	}
	if err := copyTree(filepath.Join(Dir(), "source"), f.Root); err != nil {
		t.Fatal(err)
	}
	if err := f.seal(); err != nil {
		if errors.Is(err, model.ErrNotImplemented) {
			t.Skip("fixture: crypt is not implemented yet")
		}
		t.Fatal(err)
	}
	return f
}

// seal creates identities and enclave key logs, then seals every enclave input.
func (f *Fixture) seal() error {
	for _, id := range []model.MachineID{HostA, HostB, HostC} {
		ident, err := crypt.GenerateIdentity(id)
		if err != nil {
			return err
		}
		f.Identities[id] = ident
	}
	rec, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
	if err != nil {
		return err
	}
	f.Recovery = rec
	// Remaining steps, once crypt exists: for each enclave, crypt.Create by the
	// first member, Add the others, write keys/<enclave>/<seq>.toml, then seal
	// enclave-plain, value-plain and region-plain inputs (canary substituted)
	// and replace the placeholders in the source tree.
	return model.ErrNotImplemented
}

// Plaintext returns an input with @@CANARY@@ replaced by the enclave's canary.
func (f *Fixture) Plaintext(e model.EnclaveName, b []byte) []byte {
	return bytes.ReplaceAll(b, []byte("@@CANARY@@"), f.Canaries[e].Bytes())
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0o644)
	})
}
