package crypt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
)

// ErrBadStatement means a signed statement's signature does not verify
// under the member key it names.
var ErrBadStatement = errors.New("signed statement does not verify")

// statementPrefix separates statement signatures from key-log signatures:
// a key-log entry is signed over its bare canonical TOML, which never
// starts with this prefix, so no signature is valid as both.
const statementPrefix = "yadm v1 statement "

// statementMessage is the signed message of a statement of one kind.
func statementMessage(kind string, body []byte) ([]byte, error) {
	if kind == "" || strings.ContainsAny(kind, " \n\x00") {
		return nil, fmt.Errorf("statement kind %q is not a single word", kind)
	}
	msg := make([]byte, 0, len(statementPrefix)+len(kind)+1+len(body))
	msg = append(msg, statementPrefix...)
	msg = append(msg, kind...)
	msg = append(msg, '\n')
	return append(msg, body...), nil
}

// SignStatement signs body as a statement of the given kind (a single word,
// such as "pause") with this machine's Ed25519 key, the key its key-log
// entries carry as sign_key. The kind is part of the signed message, so a
// signature for one kind never verifies as another, nor as a key-log entry.
func (id *Identity) SignStatement(kind string, body []byte) ([]byte, error) {
	msg, err := statementMessage(kind, body)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(id.sign, msg), nil
}

// VerifyStatement checks a statement signature against a member's sign_key.
// The caller decides which keys to trust.
func VerifyStatement(m Member, kind string, body, sig []byte) error {
	pub, err := m.publicKey()
	if err != nil {
		return err
	}
	msg, err := statementMessage(kind, body)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("%w: %s by %s", ErrBadStatement, kind, m.Machine)
	}
	return nil
}
