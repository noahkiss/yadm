package rules_test

import (
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// After a rotate, Reseal moves every token of the enclave to the new epoch,
// leaves other enclaves' tokens alone, and keeps the plaintext.
func TestResealMovesTokensToTheCurrentEpoch(t *testing.T) {
	canary := secrecytest.NewCanary(t, "personal")
	a, err := crypt.GenerateIdentity("m-a00001")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := crypt.GenerateIdentity(crypt.RecoveryMachine)
	if err != nil {
		t.Fatal(err)
	}
	pins := crypt.MemPins()
	head, k1, err := crypt.Create("personal", a, rec.Member(), pins)
	if err != nil {
		t.Fatal(err)
	}
	_, ck, err := crypt.Create("client", a, rec.Member(), crypt.MemPins())
	if err != nil {
		t.Fatal(err)
	}
	old := &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": k1, "client": ck}}

	spec := rules.Spec{Source: "files/test", Format: manifest.FormatJSONC, Seal: map[string]model.EnclaveName{"sync.token": "personal", "other.token": "client"}, Regions: true}
	target := []byte("{\n  // yadm:seal personal hosts\n  // " + canary.String() + "\n  // yadm:end\n  \"sync\": {\"token\": \"v-" + canary.String() + "\"},\n  \"other\": {\"token\": \"client-value\"}\n}\n")
	src, vio, err := rules.ToSource(target, nil, spec, old)
	if err != nil || len(vio) > 0 {
		t.Fatalf("ToSource: %v %v", err, vio)
	}
	if !strings.Contains(string(src), "yadm:1:personal:1:") || !strings.Contains(string(src), "yadm:sealed 1 1 ") {
		t.Fatalf("not sealed at epoch 1: %s", src)
	}

	_, k2, err := k1.Rotate(head, a, pins)
	if err != nil {
		t.Fatal(err)
	}
	cur := &crypt.Set{Rings: map[model.EnclaveName]*crypt.Keyring{"personal": k2, "client": ck}}
	out, err := rules.Reseal(src, spec, "personal", cur)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "yadm:1:personal:1:") || strings.Contains(s, "yadm:sealed 1 1 ") {
		t.Fatalf("an epoch-1 personal token remains: %s", s)
	}
	if !strings.Contains(s, "yadm:1:personal:2:") || !strings.Contains(s, "yadm:sealed 1 2 ") {
		t.Fatalf("not resealed at epoch 2: %s", s)
	}
	if !strings.Contains(s, "yadm:1:client:1:") || strings.Contains(s, canary.String()) {
		t.Fatalf("client token moved or plaintext leaked: %s", s)
	}
	back, err := rules.ToTarget(out, nil, spec, cur)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(target) {
		t.Fatalf("resealed source does not open to the target:\n%s\nwant\n%s", back, target)
	}
	// Idempotent at the current epoch.
	again, err := rules.Reseal(out, spec, "personal", cur)
	if err != nil || string(again) != s {
		t.Fatalf("second reseal changed bytes: %v", err)
	}
	// A non-member cannot reseal.
	if _, err := rules.Reseal(out, spec, "personal", &crypt.Set{}); err == nil {
		t.Fatal("non-member resealed")
	}
}
