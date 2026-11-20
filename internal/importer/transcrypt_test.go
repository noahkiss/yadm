package importer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

// transcryptEncrypt produces a blob in transcrypt's format, so tests can
// build a legacy repository that holds only ciphertext.
func transcryptEncrypt(pt []byte, password string, salt [8]byte) []byte {
	key, iv := evpBytesToKey([]byte(password), salt[:])
	block, _ := aes.NewCipher(key)
	n := aes.BlockSize - len(pt)%aes.BlockSize
	padded := append(append([]byte{}, pt...), bytes.Repeat([]byte{byte(n)}, n)...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	raw := append(append([]byte("Salted__"), salt[:]...), ct...)
	enc := base64.StdEncoding.EncodeToString(raw)
	var out bytes.Buffer
	for len(enc) > 64 {
		out.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	out.WriteString(enc + "\n")
	return out.Bytes()
}

func TestTranscryptRoundTrip(t *testing.T) {
	for _, pt := range [][]byte{nil, []byte("x"), []byte(strings.Repeat("sixteen bytes!!\n", 9))} {
		blob := transcryptEncrypt(pt, "test-password", [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if !isTranscrypt(blob) {
			t.Fatal("blob lacks the transcrypt magic")
		}
		got, err := transcryptDecrypt(blob, "test-password")
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("round trip: %q %v", got, err)
		}
		if _, err := transcryptDecrypt(blob, "wrong"); err == nil {
			// A wrong key yields valid padding about 1 time in 256; this
			// fixed salt and password are known not to.
			t.Fatal("wrong password decrypted")
		}
	}
}

// TestTranscryptMatchesOpenSSL checks the format against the openssl command
// transcrypt itself runs, when openssl is installed.
func TestTranscryptMatchesOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	pt := []byte("line one\nline two\n")
	// Binary output; OpenSSL 3 omits the salt header with -S, and transcrypt
	// then prepends it itself before base64 encoding.
	cmd := exec.Command("openssl", "enc", "-e", "-aes-256-cbc", "-md", "MD5", "-pass", "pass:test-password", "-S", "0102030405060708")
	cmd.Stdin = bytes.NewReader(pt)
	raw, err := cmd.Output()
	if err != nil {
		t.Skipf("openssl enc failed: %v", err)
	}
	if !bytes.HasPrefix(raw, []byte("Salted__")) {
		raw = append([]byte("Salted__\x01\x02\x03\x04\x05\x06\x07\x08"), raw...)
	}
	out := []byte(base64.StdEncoding.EncodeToString(raw))
	got, err := transcryptDecrypt(out, "test-password")
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("decrypt openssl output: %q %v", got, err)
	}
	mine := transcryptEncrypt(pt, "test-password", [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
	if !bytes.Equal(bytes.Join(bytes.Fields(mine), nil), out) {
		t.Fatalf("encrypt differs from openssl:\n%s\n%s", mine, out)
	}
}
