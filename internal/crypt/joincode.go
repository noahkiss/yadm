package crypt

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/noahkiss/yadm/internal/model"
)

// The join code is a short form of an entry fingerprint that a human reads
// off one screen and types on another (design section 7.2). It holds 40
// bits, so it is derived through a slow, memory-hard KDF: each guess an
// attacker makes while grinding a forged entry costs one full argon2id run.
const (
	joinCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford base32: no I, L, O, U
	joinCodeLen      = 8                                  // characters; 5 bytes, 40 bits
	joinCodeSalt     = "yadm v1 join code"                // fixed domain separation
)

// JoinCodeCost is the argon2id cost of one join code.
type JoinCodeCost struct {
	Time    uint32 // passes
	Memory  uint32 // KiB
	Threads uint8
}

// DefaultJoinCodeCost takes about 0.6 s and 256 MiB on a current laptop.
var DefaultJoinCodeCost = JoinCodeCost{Time: 3, Memory: 256 * 1024, Threads: 1}

var joinCodeCost = DefaultJoinCodeCost

// SetJoinCodeCostForTest lowers the KDF cost so tests stay fast. It is a test
// hook, never set outside tests; the returned function restores the cost.
func SetJoinCodeCostForTest(c JoinCodeCost) (restore func()) {
	old := joinCodeCost
	joinCodeCost = c
	return func() { joinCodeCost = old }
}

// JoinCode derives the join code of an entry fingerprint (hex), formatted
// as XXXX-XXXX.
func JoinCode(fingerprint string) (string, error) {
	fp, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(fingerprint)))
	if err != nil || len(fp) != 32 {
		return "", fmt.Errorf("%w: not an entry fingerprint", ErrInvalidLog)
	}
	c := joinCodeCost
	k := argon2.IDKey(fp, []byte(joinCodeSalt), c.Time, c.Memory, c.Threads, 5)
	var v uint64
	for _, b := range k {
		v = v<<8 | uint64(b)
	}
	out := make([]byte, joinCodeLen)
	for i := joinCodeLen - 1; i >= 0; i-- {
		out[i] = joinCodeAlphabet[v&31]
		v >>= 5
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// ParseJoinCode normalizes a typed code to XXXX-XXXX. It ignores case,
// dashes and spaces, and reads O as 0 and I or L as 1, as Crockford base32
// does.
func ParseJoinCode(s string) (string, error) {
	var b []byte
	for _, r := range strings.ToUpper(s) {
		switch {
		case r == '-' || r == ' ':
			continue
		case r == 'O':
			r = '0'
		case r == 'I' || r == 'L':
			r = '1'
		}
		if r > 127 || !strings.ContainsRune(joinCodeAlphabet, r) {
			return "", fmt.Errorf("join code %q: %q is not a code character", s, r)
		}
		b = append(b, byte(r))
	}
	if len(b) != joinCodeLen {
		return "", fmt.Errorf("join code %q: want %d characters, got %d", s, joinCodeLen, len(b))
	}
	return string(b[:4]) + "-" + string(b[4:]), nil
}

// JoinWithCode pins an enclave's key log from a join code received out of
// band. The one candidate is the newest `add` entry whose subject is self,
// the joining machine: the code must match that entry, or nothing is
// pinned. One candidate means one KDF run per join, and a forged log gets
// one guess, not one per entry it holds. On a match it pins as Join does.
func JoinWithCode(entries []LogEntry, code string, self model.MachineID, pins PinStore) (LogEntry, error) {
	want, err := ParseJoinCode(code)
	if err != nil {
		return LogEntry{}, err
	}
	if len(entries) == 0 {
		return LogEntry{}, fmt.Errorf("%w: empty key log", ErrInvalidLog)
	}
	var cand *LogEntry
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Op == OpAdd && entries[i].Subject == self {
			cand = &entries[i]
			break
		}
	}
	if cand == nil {
		return LogEntry{}, fmt.Errorf("%w: no entry of %s adds %s, so no join code applies; join with --expect <fingerprint> from the member that wrote the entry", ErrBrokenChain, entries[0].Enclave, self)
	}
	fp, err := Fingerprint(*cand)
	if err != nil {
		return LogEntry{}, err
	}
	got, err := JoinCode(fp)
	if err != nil {
		return LogEntry{}, err
	}
	// The message never shows the local code: the local log is what a
	// writer controls.
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return LogEntry{}, fmt.Errorf("%w: the entry of %s that adds %s does not match join code %s", ErrBrokenChain, entries[0].Enclave, self, want)
	}
	return Join(entries, fp, pins)
}
