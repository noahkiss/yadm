package rules

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/noahkiss/yadm/internal/model"
)

// fakeSealer is a deterministic, reversible stand-in for crypt.Set. Tokens
// bind the enclave and the key path or label, and never contain plaintext.
type fakeSealer struct {
	members map[model.EnclaveName]bool
}

var errFakeNotMember = errors.New("fake: not a member")

func member(es ...model.EnclaveName) *fakeSealer {
	m := map[model.EnclaveName]bool{}
	for _, e := range es {
		m[e] = true
	}
	return &fakeSealer{members: m}
}

func (f *fakeSealer) CanOpen(e model.EnclaveName) bool { return f.members[e] }

func stream(bind string, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		h := sha256.Sum256([]byte(bind + "\x00" + string(rune('a'+i%26)) + string(rune(i))))
		out = append(out, h[:]...)
	}
	return out[:n]
}

func xor(b []byte, bind string) []byte {
	k := stream(bind, len(b))
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[i] ^ k[i]
	}
	return out
}

func (f *fakeSealer) SealValue(e model.EnclaveName, keyPath string, pt []byte) (string, error) {
	if !f.members[e] {
		return "", errFakeNotMember
	}
	return "yadm:1:" + string(e) + ":1:" + base64.RawURLEncoding.EncodeToString(xor(pt, "v\x00"+string(e)+"\x00"+keyPath)), nil
}

func (f *fakeSealer) OpenValue(e model.EnclaveName, keyPath, token string) ([]byte, error) {
	if !f.members[e] {
		return nil, errFakeNotMember
	}
	pre := "yadm:1:" + string(e) + ":1:"
	if !strings.HasPrefix(token, pre) {
		return nil, errors.New("fake: token for another enclave")
	}
	b, err := base64.RawURLEncoding.DecodeString(token[len(pre):])
	if err != nil {
		return nil, err
	}
	return xor(b, "v\x00"+string(e)+"\x00"+keyPath), nil
}

func (f *fakeSealer) SealRegion(e model.EnclaveName, label string, body []byte) (string, error) {
	if !f.members[e] {
		return "", errFakeNotMember
	}
	return "yadm:sealed 1 1 " + base64.StdEncoding.EncodeToString(xor(body, "r\x00"+string(e)+"\x00"+label)), nil
}

func (f *fakeSealer) OpenRegion(e model.EnclaveName, label, token string) ([]byte, error) {
	if !f.members[e] {
		return nil, errFakeNotMember
	}
	const pre = "yadm:sealed 1 1 "
	if !strings.HasPrefix(token, pre) {
		return nil, errors.New("fake: bad region token")
	}
	b, err := base64.StdEncoding.DecodeString(token[len(pre):])
	if err != nil {
		return nil, err
	}
	return xor(b, "r\x00"+string(e)+"\x00"+label), nil
}
