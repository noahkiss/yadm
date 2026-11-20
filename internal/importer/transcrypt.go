package importer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
)

// transcryptMagic is how a transcrypt blob begins: base64 of "Salted__".
var transcryptMagic = []byte("U2FsdGVk")

func isTranscrypt(b []byte) bool { return bytes.HasPrefix(b, transcryptMagic) }

// errDecrypt never carries key material.
var errDecrypt = errors.New("transcrypt decryption failed: wrong password or corrupt ciphertext")

// evpBytesToKey derives an AES-256 key and IV the way OpenSSL's `enc -md MD5`
// does: one MD5 iteration per block over (previous block, password, salt).
func evpBytesToKey(password, salt []byte) (key, iv []byte) {
	var out, prev []byte
	for len(out) < 48 {
		h := md5.New()
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:32], out[32:48]
}

// transcryptDecrypt opens one blob written by transcrypt's clean filter:
// base64 of "Salted__", an 8-byte salt and AES-256-CBC ciphertext with PKCS#7
// padding.
func transcryptDecrypt(blob []byte, password string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields(blob), nil)))
	if err != nil {
		return nil, fmt.Errorf("transcrypt blob is not base64: %v", err)
	}
	if len(raw) < 16 || string(raw[:8]) != "Salted__" {
		return nil, errors.New("transcrypt blob has no salt header")
	}
	salt, ct := raw[8:16], raw[16:]
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errDecrypt
	}
	key, iv := evpBytesToKey([]byte(password), salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	n := int(pt[len(pt)-1])
	if n == 0 || n > aes.BlockSize || n > len(pt) {
		return nil, errDecrypt
	}
	for _, c := range pt[len(pt)-n:] {
		if int(c) != n {
			return nil, errDecrypt
		}
	}
	return pt[:len(pt)-n], nil
}
