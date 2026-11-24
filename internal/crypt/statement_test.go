package crypt

import (
	"errors"
	"testing"
)

// TestStatementSignature: a statement verifies only under its signer's key
// and its own kind; a changed body or another kind fails.
func TestStatementSignature(t *testing.T) {
	a, err := GenerateIdentity("m-a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateIdentity("m-b")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"op":"pause"}`)
	sig, err := a.SignStatement("pause", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStatement(a.Member(), "pause", body, sig); err != nil {
		t.Fatalf("valid statement: %v", err)
	}
	for name, err := range map[string]error{
		"other key":  VerifyStatement(b.Member(), "pause", body, sig),
		"other kind": VerifyStatement(a.Member(), "resume", body, sig),
		"other body": VerifyStatement(a.Member(), "pause", []byte(`{"op":"resume"}`), sig),
		"no sig":     VerifyStatement(a.Member(), "pause", body, nil),
	} {
		if !errors.Is(err, ErrBadStatement) {
			t.Errorf("%s: want ErrBadStatement, got %v", name, err)
		}
	}
	if _, err := a.SignStatement("two words", body); err == nil {
		t.Error("a kind with a space was accepted")
	}
}
