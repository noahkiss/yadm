package crypt

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

var lowCost = JoinCodeCost{Time: 1, Memory: 64, Threads: 1}

// TestJoinCodeKnownAnswer pins the production derivation: a change to the
// KDF, its cost, the salt or the encoding changes this code and fails here.
func TestJoinCodeKnownAnswer(t *testing.T) {
	if joinCodeCost != DefaultJoinCodeCost {
		t.Fatal("join code cost is not the default")
	}
	start := time.Now()
	got, err := JoinCode(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("one join code at the default cost: %v", time.Since(start))
	if got != "JJ64-9PTW" {
		t.Fatalf("join code = %s", got)
	}
}

func TestJoinCodeFormat(t *testing.T) {
	defer SetJoinCodeCostForTest(lowCost)()
	re := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$`)
	seen := map[string]bool{}
	for i := range 64 {
		fp := strings.Repeat("0", 62) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16])
		a, err := JoinCode(fp)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := JoinCode(strings.ToUpper(fp))
		if a != b {
			t.Fatalf("not deterministic: %s %s", a, b)
		}
		if !re.MatchString(a) {
			t.Fatalf("bad format: %s", a)
		}
		seen[a] = true
	}
	if len(seen) < 60 {
		t.Fatalf("codes collide: %d distinct of 64", len(seen))
	}
	for _, bad := range []string{"", "xyz", strings.Repeat("a", 63), strings.Repeat("a", 66)} {
		if _, err := JoinCode(bad); err == nil {
			t.Fatalf("JoinCode(%q) accepted", bad)
		}
	}
}

func TestParseJoinCode(t *testing.T) {
	for in, want := range map[string]string{
		"ABCD-EFGH":   "ABCD-EFGH",
		"abcdefgh":    "ABCD-EFGH",
		" ab cd-efgh": "ABCD-EFGH",
		"o1il-0000":   "0111-0000",
	} {
		if got, err := ParseJoinCode(in); err != nil || got != want {
			t.Fatalf("ParseJoinCode(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "ABCD-EFG", "ABCD-EFGHJ", "ABCD-EFGU", "ABCD-EFG!", "ABCD-EFGé"} {
		if _, err := ParseJoinCode(bad); err == nil {
			t.Fatalf("ParseJoinCode(%q) accepted", bad)
		}
	}
}

// TestJoinWithCode: the right code pins; a wrong code, or the code of
// another entry, pins nothing.
func TestJoinWithCode(t *testing.T) {
	defer SetJoinCodeCostForTest(lowCost)()
	w := newWorld(t) // 1 create(A), 2 add(B), 3 add(C)
	code := func(e LogEntry) string {
		fp, err := Fingerprint(e)
		if err != nil {
			t.Fatal(err)
		}
		c, err := JoinCode(fp)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	cB, cC := code(w.log[1]), code(w.log[2])

	refused := func(name, c string, self LogEntry) {
		t.Helper()
		pins := MemPins()
		if _, err := JoinWithCode(w.log, c, self.Subject, pins); !errors.Is(err, ErrBrokenChain) {
			t.Fatalf("%s: %v", name, err)
		}
		if p, _ := pins.Get("personal"); p != nil {
			t.Fatalf("%s pinned %+v", name, p)
		}
	}
	wrong := []byte(strings.ReplaceAll(cC, "-", ""))
	wrong[0] = joinCodeAlphabet[(strings.IndexByte(joinCodeAlphabet, wrong[0])+1)%32]
	refused("wrong code", string(wrong), w.log[2])
	refused("another entry's code", cB, w.log[2])
	refused("create's code", code(w.log[0]), w.log[2])
	if _, err := JoinWithCode(w.log, "nope", hostC, MemPins()); err == nil || errors.Is(err, ErrBrokenChain) {
		t.Fatalf("malformed code: %v", err)
	}
	if _, err := JoinWithCode(w.log, cC, evil, MemPins()); !errors.Is(err, ErrBrokenChain) || !strings.Contains(err.Error(), "--expect") {
		t.Fatalf("no add for this machine: %v", err)
	}

	pins := MemPins()
	head, err := JoinWithCode(w.log, strings.ToLower(strings.ReplaceAll(cC, "-", "")), hostC, pins)
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := pins.Get("personal"); head.Seq != 3 || p == nil || *p != *mustPin(t, w.log[2]) {
		t.Fatalf("join pinned %+v head %d", p, head.Seq)
	}
	// B joins with its own add entry's code, though C was added after it.
	pins = MemPins()
	if _, err := JoinWithCode(w.log, cB, hostB, pins); err != nil {
		t.Fatal(err)
	}
	if p, _ := pins.Get("personal"); p == nil || *p != *mustPin(t, w.log[1]) {
		t.Fatalf("B pinned %+v", p)
	}
}
