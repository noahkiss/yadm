package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/secrecytest"
)

// keep, drop and volatile keep keys on this machine. A pushed manifest that
// removes or widens them would make capture commit those keys, so apply and
// capture hold the target until the change is allowed here.
func TestSec2LocalKeysWeakenedAreHeld(t *testing.T) {
	const tgt model.Target = ".config/app/settings.json"
	files := map[model.SourcePath]string{"files/.config/app/settings.json": "{\n  \"theme\": \"dark\"\n}\n"}
	entry := func(keep, drop, volatile []string) manifest.Entry {
		return manifest.Entry{Target: tgt, Format: manifest.FormatJSON, Keep: keep, Drop: drop, Volatile: volatile}
	}
	cases := []struct {
		name         string
		before, next manifest.Entry
		why          string // "" means not weaker
	}{
		{"keep removed", entry([]string{"theme"}, nil, nil), entry(nil, nil, nil), "keep was removed"},
		{"keep gained a key", entry([]string{"theme"}, nil, nil), entry([]string{"theme", "session"}, nil, nil), "keep gained session"},
		{"drop removed", entry(nil, []string{"recent"}, nil), entry(nil, nil, nil), "drop lost recent"},
		{"volatile removed", entry(nil, nil, []string{"window"}), entry(nil, nil, nil), "volatile lost window"},
		{"volatile narrowed", entry(nil, nil, []string{"window", "zoom"}), entry(nil, nil, []string{"zoom"}), "volatile lost window"},
		{"keep narrowed", entry([]string{"theme", "font"}, nil, nil), entry([]string{"theme"}, nil, nil), ""},
		{"drop widened", entry(nil, []string{"recent"}, nil), entry(nil, []string{"recent", "history"}, nil), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			canary := secrecytest.NewCanary(t, "machine-local key")
			w := newWorld(t)
			w.apply(w.commit(files, tc.before))
			c := w.commit(files, tc.next)
			r := w.apply(c)
			a := actionOf(r, tgt)
			if tc.why == "" {
				if a.Kind == ActHold {
					t.Fatalf("a stronger spec was held: %+v", a)
				}
				return
			}
			if a.Kind != ActHold {
				t.Fatalf("weaker spec applied: %+v", a)
			}
			if h := holdFor(r.Holds, tgt, model.HoldSealGuard); h == nil || !strings.Contains(h.Detail, tc.why) {
				t.Fatalf("no seal_guard hold naming %q: %+v", tc.why, r.Holds)
			}
			// The app writes a local key; capture holds too.
			w.write(tgt, "{\n  \"theme\": \"dark\",\n  \"session\": \""+canary.String()+"\"\n}\n")
			cp := scanCapture(t, w)
			if ch := leakedIn(cp, canary); ch != nil {
				t.Fatalf("local key staged at %s", ch.Path)
			}
			if holdFor(cp.Holds, tgt, model.HoldSealGuard) == nil {
				t.Fatalf("capture did not hold: %+v", cp.Holds)
			}
			if !strings.Contains(w.read(tgt), canary.String()) {
				t.Fatal("apply overwrote the held target")
			}
			// Once allowed here, the new spec applies.
			if err := w.eng.AllowProtection(context.Background(), c, tgt); err != nil {
				t.Fatal(err)
			}
			w.write(tgt, files["files/.config/app/settings.json"])
			if a := actionOf(w.apply(c), tgt); a.Kind == ActHold {
				t.Fatalf("allowed spec still held: %+v", a)
			}
		})
	}
}

// A new keep/drop/volatile entry over a file yadm never wrote is held for a
// decision, even when the render equals the live file. Adopt, the user's
// own switch, takes it over.
func TestSec2NewLocalKeysEntryOverUnmanagedFileHeld(t *testing.T) {
	const tgt model.Target = ".config/app/creds.json"
	for _, en := range []manifest.Entry{
		{Target: tgt, Format: manifest.FormatJSON, Keep: []string{"managed"}},
		{Target: tgt, Format: manifest.FormatJSON, Drop: []string{"auth"}},
		{Target: tgt, Format: manifest.FormatJSON, Volatile: []string{"auth"}},
	} {
		w := newWorld(t)
		live := "{}\n"
		w.write(tgt, live)
		c := w.commit(map[model.SourcePath]string{"files/.config/app/creds.json": live}, en)
		r := w.apply(c)
		if a := actionOf(r, tgt); a.Kind != ActHold || holdFor(r.Holds, tgt, model.HoldNeedsDecision) == nil {
			t.Fatalf("%+v: not held for a decision: %+v %+v", en, a, r.Holds)
		}
		if _, ok := w.state().Targets[tgt]; ok {
			t.Fatalf("%+v: recorded as managed", en)
		}
		res, err := w.eng.Adopt(context.Background(), c, AdoptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if a := actionOf(res, tgt); a.Kind == ActHold {
			t.Fatalf("%+v: adopt held: %+v", en, a)
		}
	}
}
