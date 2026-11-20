package crypt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"io"
	"testing"

	"filippo.io/age"
	daead "github.com/tink-crypto/tink-go/v2/daead/subtle"
)

// TestDependencies pins the properties the construction relies on, so a
// dependency upgrade that changes them fails here first.
func TestDependencies(t *testing.T) {
	t.Run("aes-siv is deterministic and binds AD", func(t *testing.T) {
		k, err := hkdf.Key(sha256.New, bytes.Repeat([]byte{1}, EpochKeySize), nil, "yadm v1 file test", SIVKeySize)
		if err != nil {
			t.Fatal(err)
		}
		s, err := daead.NewAESSIV(k)
		if err != nil {
			t.Fatal(err)
		}
		c1, _ := s.EncryptDeterministically([]byte("plaintext"), []byte("ad"))
		c2, _ := s.EncryptDeterministically([]byte("plaintext"), []byte("ad"))
		if !bytes.Equal(c1, c2) {
			t.Fatal("AES-SIV output is not deterministic")
		}
		if len(c1) != len("plaintext")+16 {
			t.Fatalf("unexpected overhead: %d", len(c1)-len("plaintext"))
		}
		if _, err := s.DecryptDeterministically(c1, []byte("other")); err == nil {
			t.Fatal("AES-SIV accepted wrong AD")
		}
	})
	t.Run("age x25519 wrap", func(t *testing.T) {
		member, _ := age.GenerateX25519Identity()
		outsider, _ := age.GenerateX25519Identity()
		var buf bytes.Buffer
		w, err := age.Encrypt(&buf, member.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("epoch keys"))
		w.Close()
		if _, err := age.Decrypt(bytes.NewReader(buf.Bytes()), outsider); err == nil {
			t.Fatal("outsider unwrapped")
		}
		r, err := age.Decrypt(bytes.NewReader(buf.Bytes()), member)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := io.ReadAll(r); string(b) != "epoch keys" {
			t.Fatal("round trip")
		}
	})
	t.Run("ed25519", func(t *testing.T) {
		pub, priv, _ := ed25519.GenerateKey(nil)
		if !ed25519.Verify(pub, []byte("entry"), ed25519.Sign(priv, []byte("entry"))) {
			t.Fatal("verify")
		}
	})
}
