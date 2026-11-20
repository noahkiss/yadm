package apply

import (
	"context"
	"os"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// A `merge = "union"` target appended here while its source gained other
// lines is written as the line union, not held; the next capture commits
// the union. This holds for a sealed union file on a member too.
func TestApplyMergesUnionFile(t *testing.T) {
	for _, tc := range []struct {
		name    string
		source  model.SourcePath
		enclave model.EnclaveName
	}{
		{"plain", "files/.log", ""},
		{"sealed", "sealed/personal/.log", "personal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t, "personal")
			entry := manifest.Entry{Target: ".log", Merge: manifest.MergeUnion, Enclave: tc.enclave}
			c := w.commit(map[model.SourcePath]string{tc.source: "one\ntwo\n"}, entry)
			w.apply(c)
			if err := os.Chmod(w.path(".log"), 0o640); err != nil { // a stricter mode stays allowed
				t.Fatal(err)
			}
			w.write(".log", "one\ntwo\nlocal\n")
			if err := os.Chmod(w.path(".log"), 0o640); err != nil {
				t.Fatal(err)
			}

			// Another machine appended "remote" and removed "one".
			c2 := w.commit(map[model.SourcePath]string{tc.source: "two\nremote\n"}, entry)
			res := w.apply(c2)
			if len(res.Holds) != 0 {
				t.Fatalf("holds: %+v", res.Holds)
			}
			if got, want := w.read(".log"), "two\nremote\nlocal\n"; got != want {
				t.Fatalf("target = %q, want %q", got, want)
			}

			ds, err := w.eng.Scan(ctx, ScanOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if d := driftOf(ds, ".log"); d.Kind != DriftModified {
				t.Fatalf("scan after the union: %+v, want modified", ds)
			}
			cp, err := w.eng.Capture(ctx, ds)
			if err != nil {
				t.Fatal(err)
			}
			if len(cp.Holds) != 0 || len(cp.Changes) != 1 || cp.Changes[0].Path != tc.source {
				t.Fatalf("capture: changes %+v holds %+v", cp.Changes, cp.Holds)
			}
			got := cp.Changes[0].Blob
			if tc.enclave != "" {
				if string(got) == "two\nremote\nlocal\n" {
					t.Fatal("a sealed union file was captured as plaintext")
				}
				if got, err = (fakeCrypto{members: map[model.EnclaveName]bool{"personal": true}}).OpenFile(tc.enclave, tc.source, got); err != nil {
					t.Fatal(err)
				}
			}
			if string(got) != "two\nremote\nlocal\n" {
				t.Fatalf("captured %q", got)
			}
		})
	}
}

// Without a source change a union target's local edit is ordinary drift:
// apply leaves it for capture. A file whose union cannot be computed
// (binary) is held as before.
func TestApplyUnionHoldsWhatItCannotMerge(t *testing.T) {
	w := newWorld(t)
	entry := manifest.Entry{Target: ".log", Merge: manifest.MergeUnion}
	c := w.commit(map[model.SourcePath]string{"files/.log": "one\n"}, entry)
	w.apply(c)
	w.write(".log", "one\x00bin\n")
	c2 := w.commit(map[model.SourcePath]string{"files/.log": "one\nremote\n"}, entry)
	res := w.apply(c2)
	if len(res.Holds) != 1 || res.Holds[0].Reason != model.HoldDrifted {
		t.Fatalf("binary union: holds %+v", res.Holds)
	}
	if got := w.read(".log"); got != "one\x00bin\n" {
		t.Fatalf("binary union target overwritten: %q", got)
	}
}
