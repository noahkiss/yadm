package fixture

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
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
	Logs       map[model.EnclaveName][]crypt.LogEntry // each enclave's key log, also written under keys/
	Rings      map[model.EnclaveName]*crypt.Keyring   // each enclave's keyring at its head
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
		Logs:       map[model.EnclaveName][]crypt.LogEntry{},
		Rings:      map[model.EnclaveName]*crypt.Keyring{},
	}
	for e := range Members {
		f.Canaries[e] = secrecytest.NewCanary(t, string(e))
	}
	if err := copyTree(filepath.Join(Dir(), "source"), f.Root); err != nil {
		t.Fatal(err)
	}
	if err := f.seal(); err != nil {
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
	enclaves := make([]model.EnclaveName, 0, len(Members))
	for e := range Members {
		enclaves = append(enclaves, e)
	}
	sort.Slice(enclaves, func(i, j int) bool { return enclaves[i] < enclaves[j] })
	for _, e := range enclaves {
		if err := f.createEnclave(e); err != nil {
			return fmt.Errorf("enclave %s: %w", e, err)
		}
		if err := f.sealFiles(e); err != nil {
			return fmt.Errorf("enclave %s: %w", e, err)
		}
	}
	return f.replacePlaceholders()
}

// createEnclave writes the key log: create by the first member, then add the others.
func (f *Fixture) createEnclave(e model.EnclaveName) error {
	ms := Members[e]
	by := f.Identities[ms[0]]
	pins := crypt.MemPins() // the creator's pins; tests pin machines with PinAll
	head, ring, err := crypt.Create(e, by, f.Recovery.Member(), pins)
	if err != nil {
		return err
	}
	log := []crypt.LogEntry{head}
	for _, m := range ms[1:] {
		if head, err = ring.Add(head, f.Identities[m].Member(), by, pins); err != nil {
			return err
		}
		log = append(log, head)
	}
	for _, entry := range log {
		b, err := crypt.MarshalLogEntry(entry)
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(f.Root, filepath.FromSlash(string(crypt.LogPath(e, entry.Seq)))), b); err != nil {
			return err
		}
	}
	f.Logs[e] = log
	f.Rings[e] = ring
	return nil
}

// sealFiles seals enclave-plain/<enclave>/<target> into sealed/<enclave>/<target>.
// The canary-substituted plaintext exists only in memory.
func (f *Fixture) sealFiles(e model.EnclaveName) error {
	src := filepath.Join(Dir(), "enclave-plain", string(e))
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		at := model.SourcePath("sealed/" + string(e) + "/" + filepath.ToSlash(rel))
		blob, err := f.Rings[e].SealFile(at, f.Plaintext(e, b))
		if err != nil {
			return err
		}
		return writeFile(filepath.Join(f.Root, "sealed", string(e), rel), blob)
	})
}

var placeholder = regexp.MustCompile(`@@(SEAL|REGION):([^:@]+):([^@]+)@@`)

// replacePlaceholders swaps @@SEAL:<enclave>:<keypath>@@ for a value token
// and @@REGION:<enclave>:<label>@@ for a "# yadm:sealed ..." line. Each
// token is bound to the file's source path and the concrete key path or
// label (crypt.PartName), as package rules binds it.
func (f *Fixture) replacePlaceholders() error {
	return filepath.WalkDir(f.Root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(f.Root, p)
		if err != nil {
			return err
		}
		source := model.SourcePath(filepath.ToSlash(rel))
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !placeholder.Match(b) {
			return nil
		}
		var ferr error
		out := placeholder.ReplaceAllFunc(b, func(m []byte) []byte {
			g := placeholder.FindSubmatch(m)
			kind, e, name := string(g[1]), model.EnclaveName(g[2]), string(g[3])
			ring, ok := f.Rings[e]
			if !ok {
				ferr = fmt.Errorf("%s: unknown enclave %q", p, e)
				return m
			}
			dir := map[string]string{"SEAL": "value-plain", "REGION": "region-plain"}[kind]
			plain, err := os.ReadFile(filepath.Join(Dir(), dir, string(e), name))
			if err != nil {
				ferr = err
				return m
			}
			var tok string
			if kind == "SEAL" {
				tok, err = ring.SealValue(crypt.PartName(source, name), f.Plaintext(e, plain))
			} else {
				tok, err = ring.SealRegion(crypt.PartName(source, name), f.Plaintext(e, plain))
				tok = "# " + tok
			}
			if err != nil {
				ferr = err
				return m
			}
			return []byte(tok)
		})
		if ferr != nil {
			return ferr
		}
		if placeholder.Match(out) {
			return fmt.Errorf("%s: unresolved placeholder", p)
		}
		return os.WriteFile(p, out, 0o644)
	})
}

func writeFile(p string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// PinAll writes a pin at each enclave's head into stateDir, as a machine has
// after create, add or `enclave join`. crypt.LoadSet opens no
// keyring for an unpinned enclave.
func (f *Fixture) PinAll(stateDir string) error {
	pins := crypt.FilePins(stateDir)
	for e, log := range f.Logs {
		p, err := crypt.PinOf(log[len(log)-1])
		if err != nil {
			return err
		}
		if err := pins.Set(e, p); err != nil {
			return err
		}
	}
	return nil
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
