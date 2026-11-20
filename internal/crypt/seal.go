package crypt

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	daead "github.com/tink-crypto/tink-go/v2/daead/subtle"

	"github.com/noahkiss/yadm/internal/model"
)

// cipher returns the AES-SIV instance for one purpose and epoch.
func (k *Keyring) cipher(p Purpose, epoch model.Epoch) (*daead.AESSIV, error) {
	if k == nil {
		return nil, ErrNotMember
	}
	key, ok := k.keys[epoch]
	if !ok {
		return nil, fmt.Errorf("%w: %s epoch %d", ErrUnknownEpoch, k.Enclave, epoch)
	}
	sub, err := hkdf.Key(sha256.New, key, nil, "yadm v1 "+string(p)+" "+string(k.Enclave), SIVKeySize)
	if err != nil {
		return nil, err
	}
	return daead.NewAESSIV(sub)
}

func (k *Keyring) seal(p Purpose, epoch model.Epoch, pt, ad []byte) ([]byte, error) {
	c, err := k.cipher(p, epoch)
	if err != nil {
		return nil, err
	}
	return c.EncryptDeterministically(pt, ad)
}

func (k *Keyring) open(p Purpose, epoch model.Epoch, ct, ad []byte) ([]byte, error) {
	if k != nil && epoch < k.Min {
		return nil, fmt.Errorf("%w: %s epoch %d is below %d", ErrRetiredEpoch, k.Enclave, epoch, k.Min)
	}
	c, err := k.cipher(p, epoch)
	if err != nil {
		return nil, err
	}
	pt, err := c.DecryptDeterministically(ct, ad)
	if err != nil {
		return nil, ErrAuthFailed
	}
	if pt == nil {
		pt = []byte{}
	}
	return pt, nil
}

// fileHeader is the container header:
// magic, version, uint16 BE enclave length, enclave, uint32 BE epoch.
func fileHeader(e model.EnclaveName, epoch model.Epoch) []byte {
	h := []byte(FileMagic)
	h = append(h, FormatV2)
	h = binary.BigEndian.AppendUint16(h, uint16(len(e)))
	h = append(h, e...)
	return binary.BigEndian.AppendUint32(h, uint32(epoch))
}

// partAD is the AD of a value or region: a purpose tag, then the enclave,
// the epoch and the key path or label, each string length-prefixed, so no two
// distinct inputs share an AD.
func partAD(p Purpose, e model.EnclaveName, epoch model.Epoch, name string) []byte {
	ad := []byte("yadm v1 " + string(p) + "\x00")
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(e)))
	ad = append(ad, e...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(epoch))
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(name)))
	return append(ad, name...)
}

// fileAD is the AD of a whole file: the container header, then the source
// path, length-prefixed. The path is not stored in the container.
func fileAD(header []byte, path model.SourcePath) []byte {
	ad := append([]byte(nil), header...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(path)))
	return append(ad, path...)
}

// PartName is the name a sealed value or region is bound to: the source path
// of the file that holds it, a NUL, then the concrete key path (escaped and
// dot-joined, never a pattern) or the region label. A git path holds no NUL,
// so the split is unambiguous.
func PartName(source model.SourcePath, keyOrLabel string) string {
	return string(source) + "\x00" + keyOrLabel
}

// SealFile seals a whole file under the current epoch. AD is the container
// header (magic, version, enclave, epoch) and the source path the blob is
// stored at; the purpose selects the subkey. A blob moved to another path
// fails to open, so a rename needs a member to reseal it.
func (k *Keyring) SealFile(path model.SourcePath, plaintext []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrNotMember
	}
	if len(k.Enclave) > 0xffff {
		return nil, fmt.Errorf("enclave name too long")
	}
	if path == "" {
		return nil, fmt.Errorf("seal: a source path is required")
	}
	h := fileHeader(k.Enclave, k.Current)
	ct, err := k.seal(PurposeFile, k.Current, plaintext, fileAD(h, path))
	if err != nil {
		return nil, err
	}
	return append(h, ct...), nil
}

// FileEpoch returns the enclave and epoch a container names, without
// opening it.
func FileEpoch(container []byte) (model.EnclaveName, model.Epoch, bool) {
	if !IsSealedFile(container) {
		return "", 0, false
	}
	rest := container[len(FileMagic):]
	if len(rest) < 3 || rest[0] != FormatV2 {
		return "", 0, false
	}
	n := int(binary.BigEndian.Uint16(rest[1:3]))
	rest = rest[3:]
	if len(rest) < n+4 {
		return "", 0, false
	}
	return model.EnclaveName(rest[:n]), model.Epoch(binary.BigEndian.Uint32(rest[n : n+4])), true
}

// OpenFile opens a container stored at path, sealed under an epoch from
// k.Min to the current one.
func (k *Keyring) OpenFile(path model.SourcePath, container []byte) ([]byte, error) {
	if k == nil {
		return nil, ErrNotMember
	}
	if !IsSealedFile(container) {
		return nil, ErrNotSealed
	}
	rest := container[len(FileMagic):]
	if len(rest) < 3 || rest[0] != FormatV2 {
		return nil, ErrNotSealed
	}
	n := int(binary.BigEndian.Uint16(rest[1:3]))
	rest = rest[3:]
	if len(rest) < n+4 {
		return nil, ErrNotSealed
	}
	enclave := model.EnclaveName(rest[:n])
	epoch := model.Epoch(binary.BigEndian.Uint32(rest[n : n+4]))
	if enclave != k.Enclave {
		return nil, fmt.Errorf("%w: container is sealed for %q, keyring is %q", ErrNotMember, enclave, k.Enclave)
	}
	hlen := len(container) - len(rest) + n + 4
	return k.open(PurposeFile, epoch, container[hlen:], fileAD(container[:hlen], path))
}

// SealValue seals one structured value. AD binds name: package rules passes
// the source path and the concrete key path (rules.PartName), so a token
// moved to another key or another file fails to open.
func (k *Keyring) SealValue(keyPath string, plaintext []byte) (string, error) {
	if k == nil {
		return "", ErrNotMember
	}
	ct, err := k.seal(PurposeValue, k.Current, plaintext, partAD(PurposeValue, k.Enclave, k.Current, keyPath))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%s:%d:%s", ValuePrefix, k.Enclave, k.Current, base64.RawURLEncoding.EncodeToString(ct)), nil
}

// OpenValue opens a value token for a key path.
func (k *Keyring) OpenValue(keyPath, token string) ([]byte, error) {
	if k == nil {
		return nil, ErrNotMember
	}
	t, ok := ParseValueToken(token)
	if !ok {
		return nil, ErrNotSealed
	}
	if t.Enclave != k.Enclave {
		return nil, fmt.Errorf("%w: token is sealed for %q, keyring is %q", ErrNotMember, t.Enclave, k.Enclave)
	}
	return k.open(PurposeValue, t.Epoch, t.Body, partAD(PurposeValue, k.Enclave, t.Epoch, keyPath))
}

// ParseValueToken parses "yadm:1:<enclave>:<epoch>:<base64url>".
func ParseValueToken(s string) (ValueToken, bool) {
	rest, ok := strings.CutPrefix(s, ValuePrefix)
	if !ok {
		return ValueToken{}, false
	}
	parts := strings.SplitN(rest, ":", 3)
	if len(parts) != 3 || checkEnclaveName(model.EnclaveName(parts[0])) != nil {
		return ValueToken{}, false
	}
	epoch, ok := parseEpoch(parts[1])
	if !ok {
		return ValueToken{}, false
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(body) < 16 {
		return ValueToken{}, false
	}
	return ValueToken{Enclave: model.EnclaveName(parts[0]), Epoch: epoch, Body: body}, true
}

func parseEpoch(s string) (model.Epoch, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return model.Epoch(n), true
}

// SealRegion seals one text region body. AD binds name: package rules
// passes the source path and the region label (rules.PartName). The
// token is "yadm:sealed 1 <epoch> <base64>", without any comment prefix; the
// enclave is named by the region's opening marker, not the token.
func (k *Keyring) SealRegion(label string, body []byte) (string, error) {
	if k == nil {
		return "", ErrNotMember
	}
	ct, err := k.seal(PurposeRegion, k.Current, body, partAD(PurposeRegion, k.Enclave, k.Current, label))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%d %s", RegionPrefix, k.Current, base64.StdEncoding.EncodeToString(ct)), nil
}

// OpenRegion opens a region token.
func (k *Keyring) OpenRegion(label, token string) ([]byte, error) {
	if k == nil {
		return nil, ErrNotMember
	}
	rest, ok := strings.CutPrefix(token, RegionPrefix)
	if !ok {
		return nil, ErrNotSealed
	}
	es, b64, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, ErrNotSealed
	}
	epoch, ok := parseEpoch(es)
	if !ok {
		return nil, ErrNotSealed
	}
	ct, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(ct) < 16 {
		return nil, ErrNotSealed
	}
	return k.open(PurposeRegion, epoch, ct, partAD(PurposeRegion, k.Enclave, epoch, label))
}
