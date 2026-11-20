package rules_test

// Regression tests for token substitution by a pusher who holds no key.
// Before the fix, a value token was bound to the seal pattern only and a
// region token to its label only, so both moved freely.

import (
	"errors"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
)

func realRing(t *testing.T) *crypt.Set {
	t.Helper()
	id, err := crypt.GenerateIdentity("m-a00001")
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := crypt.GenerateIdentity(crypt.RecoveryMachine)
	_, k, err := crypt.Create("personal", id, rec.Member(), crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	return &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": k}}
}

func TestAttackValueTokenSwappedWithinPattern(t *testing.T) {
	s := realRing(t)
	spec := rules.Spec{Source: "files/servers.json", Format: manifest.FormatJSON, Seal: map[string]model.EnclaveName{"servers.*.token": "personal"}}
	target := "{\n  \"servers\": {\n    \"prod\": { \"url\": \"https://prod.invalid\", \"token\": \"PROD-SECRET\" },\n    \"evil\": { \"url\": \"https://attacker.invalid\", \"token\": \"throwaway\" }\n  }\n}\n"
	src, vio, err := rules.ToSource([]byte(target), nil, spec, s)
	if err != nil || len(vio) > 0 {
		t.Fatal(err, vio)
	}
	if strings.Contains(string(src), "PROD-SECRET") {
		t.Fatal("not sealed")
	}
	lines := strings.Split(string(src), "\n")
	tok := func(l string) string { i := strings.Index(l, "yadm:1:"); return l[i : i+strings.Index(l[i:], "\"")] }
	a, b := tok(lines[2]), tok(lines[3])
	swapped := strings.NewReplacer(a, b, b, a).Replace(string(src))
	if out, err := rules.ToTarget([]byte(swapped), nil, spec, s); !errors.Is(err, crypt.ErrAuthFailed) {
		t.Fatalf("swapped tokens opened:\n%s\nerr %v", out, err)
	}

	// The same token in another file with the same pattern does not open.
	other := "{ \"servers\": { \"prod\": { \"token\": \"" + a + "\" } } }\n"
	ospec := spec
	ospec.Source = "files/other.json"
	if _, err := rules.ToTarget([]byte(other), nil, ospec, s); !errors.Is(err, crypt.ErrAuthFailed) {
		t.Fatalf("token opened in another file: %v", err)
	}
	// The honest source still opens.
	if out, err := rules.ToTarget(src, nil, spec, s); err != nil || string(out) != target {
		t.Fatalf("honest source: %v", err)
	}
	// No source path: sealing fails closed.
	nospec := spec
	nospec.Source = ""
	if _, _, err := rules.ToSource([]byte(target), nil, nospec, s); !errors.Is(err, rules.ErrNoSource) {
		t.Fatalf("seal without a source: %v", err)
	}
}

func TestAttackRegionTokenMovedToAnotherFile(t *testing.T) {
	s := realRing(t)
	spec := rules.Spec{Source: "files/.ssh/config", Regions: true}
	a := "# yadm:seal personal hosts\nHost private-box\n  HostName 192.0.2.10\n# yadm:end\n"
	src, vio, err := rules.ToSource([]byte(a), nil, spec, s)
	if err != nil || len(vio) > 0 {
		t.Fatal(err, vio)
	}
	tokLine := strings.Split(string(src), "\n")[1]
	other := "export X=1\n# yadm:seal personal hosts\n" + tokLine + "\n# yadm:end\n"
	ospec := rules.Spec{Source: "files/.config/shell/env.sh", Regions: true}
	if out, err := rules.ToTarget([]byte(other), nil, ospec, s); !errors.Is(err, crypt.ErrAuthFailed) {
		t.Fatalf("region opened in another file:\n%s\nerr %v", out, err)
	}
}
