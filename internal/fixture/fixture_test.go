package fixture

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
)

func readTOML(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := toml.Unmarshal(b, &v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	return v
}

// TestShape checks the static fixture is self-consistent, independent of any
// package that is still a stub.
func TestShape(t *testing.T) {
	src := filepath.Join(Dir(), "source")
	fl := readTOML(t, filepath.Join(src, "fleet.toml"))
	types := fl["types"].(map[string]any)
	for id, raw := range fl["machines"].(map[string]any) {
		m := raw.(map[string]any)
		for _, ty := range m["types"].([]any) {
			if _, ok := types[ty.(string)]; !ok {
				t.Errorf("machine %s: unknown type %v", id, ty)
			}
		}
	}
	for e := range Members {
		if te, ok := types[string(e)].(map[string]any); !ok || te["enclave"] != true {
			t.Errorf("enclave %s is not declared as an enclave type", e)
		}
	}

	mf := readTOML(t, filepath.Join(src, "manifest.toml"))
	for _, raw := range mf["file"].([]any) {
		e := raw.(map[string]any)
		target := e["target"].(string)
		var p string
		switch {
		case e["source"] != nil:
			p = filepath.Join(src, e["source"].(string))
		case e["enclave"] != nil:
			p = filepath.Join(Dir(), "enclave-plain", e["enclave"].(string), target)
		default:
			p = filepath.Join(src, "files", target)
		}
		if _, err := os.Stat(p); err != nil {
			t.Errorf("entry %s: source missing: %v", target, err)
		}
	}
	if _, err := os.Stat(filepath.Join(LegacyDir(), ".config", "yadm", "machines.tsv")); err != nil {
		t.Errorf("legacy fixture: %v", err)
	}
}

func decodeStrict(t *testing.T, p string, v any) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	d := toml.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		t.Fatalf("%s does not decode into the typed contract: %v", filepath.Base(p), err)
	}
}

// TestTypedContracts decodes the fixture files into the exported structs, so
// the documented formats and the Go types cannot drift apart.
func TestTypedContracts(t *testing.T) {
	src := filepath.Join(Dir(), "source")

	var fl fleet.File
	decodeStrict(t, filepath.Join(src, "fleet.toml"), &fl)
	if got := fl.Enclaves(); len(got) != 2 || got[0] != "client" || got[1] != "personal" {
		t.Errorf("enclaves: %v", got)
	}
	if c := fl.Collectors["client-tools"]; c.Publish.Mode != fleet.PublishSealed || c.Publish.Enclave != "client" {
		t.Errorf("publish: %+v", c.Publish)
	}
	if c := fl.Collectors["packages"]; c.Timeout.D() != 30*time.Second {
		t.Errorf("timeout: %v", c.Timeout)
	}
	if m := fl.Machines[HostC]; len(m.Types) != 2 || m.Facts["editor"] == "" {
		t.Errorf("machine: %+v", m)
	}

	var mf manifest.Manifest
	decodeStrict(t, filepath.Join(src, "manifest.toml"), &mf)
	if mf.Defaults.Quiet.D() != 2*time.Hour {
		t.Errorf("quiet: %v", mf.Defaults.Quiet)
	}
	if len(mf.Entries) == 0 || len(mf.Units) != 2 || len(mf.Roots) != 1 || len(mf.Checks) != 1 {
		t.Errorf("manifest: %d entries, %d units, %d roots, %d checks", len(mf.Entries), len(mf.Units), len(mf.Roots), len(mf.Checks))
	}
	if tk := mf.Tasks["cleanup-cache"]; len(tk.OnRemove) != 1 {
		t.Errorf("on_remove: %+v", tk)
	}
	if !mf.Tasks["first-setup"].FirstApply {
		t.Error("first_apply not decoded")
	}
	var sawSeal, sawMode bool
	for _, e := range mf.Entries {
		if e.Seal["sync.token"] == "personal" {
			sawSeal = true
		}
		if e.Target == ".ssh/config" && e.Mode == 0o600 {
			sawMode = true
		}
	}
	if !sawSeal || !sawMode {
		t.Errorf("seal=%v mode=%v", sawSeal, sawMode)
	}

	entry := `enclave = "personal"
seq = 1
prev = ""
epoch = 1
op = "create"
members = [{ machine = "m-a1b2c3", recipient = "age1example", sign_key = "AQID" }]
recovery = { machine = "recovery", recipient = "age1example", sign_key = "AQID" }
wrapped = "AQID"
signer = "m-a1b2c3"
sig = "AQID"
`
	var le crypt.LogEntry
	d := toml.NewDecoder(strings.NewReader(entry))
	d.DisallowUnknownFields()
	if err := d.Decode(&le); err != nil {
		t.Fatalf("key-log entry: %v", err)
	}
	if string(le.Sig) != "\x01\x02\x03" || le.Op != crypt.OpCreate {
		t.Errorf("entry: %+v", le)
	}
}

func TestBuild(t *testing.T) {
	f := Build(t)
	if len(f.Identities) != 3 {
		t.Fatalf("identities: %d", len(f.Identities))
	}
	// The key logs on disk parse and verify, and each enclave's members open them.
	for e, members := range Members {
		var log []crypt.LogEntry
		for seq := uint64(1); ; seq++ {
			b, err := os.ReadFile(filepath.Join(f.Root, string(crypt.LogPath(e, seq))))
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			entry, err := crypt.ParseLogEntry(b)
			if err != nil {
				t.Fatal(err)
			}
			log = append(log, entry)
		}
		head, err := crypt.VerifyLog(log, nil)
		if err != nil {
			t.Fatalf("%s: %v", e, err)
		}
		for _, m := range members {
			if _, err := crypt.Open(head, f.Identities[m]); err != nil {
				t.Errorf("%s: member %s cannot open: %v", e, m, err)
			}
		}
	}
	// No placeholder is left, and no canary is in the tree.
	err := filepath.WalkDir(f.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte("@@")) {
			t.Errorf("%s: placeholder left", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(filepath.Join(f.Root, "sealed", "personal", ".config", "notes", "private.md"))
	if err != nil || !crypt.IsSealedFile(sealed) {
		t.Fatalf("sealed file: %v", err)
	}
}
