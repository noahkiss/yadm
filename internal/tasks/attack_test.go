package tasks

import (
	"context"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// A gate without a staging directory never falls back to the system temp
// directory, where a crash would leave plaintext others can list: every
// check that matches holds its targets and runs nothing.
func TestGateWithoutStagingDirFailsClosed(t *testing.T) {
	checks := map[string]manifest.CheckDef{"scan": {Paths: []string{"**"}, Command: []string{"scan"}}}
	allow := allowAll(t, extexec.KindCheck, map[string]any{"scan": checks["scan"]})
	staged := []Staged{{Target: ".netrc", Scope: "personal", Plaintext: []byte("secret")}}
	ex := &fakeExec{}
	for _, g := range []Gate{NewGate(checks, ex, allow), NewGateIn(checks, ex, allow, "")} {
		pass, holds, _ := g.Check(context.Background(), staged, extexec.Request{})
		if len(pass) != 0 || len(holds) != 1 || holds[0].Reason != model.HoldCheckFailed {
			t.Fatalf("pass %v holds %+v", pass, holds)
		}
	}
	if len(ex.reqs) != 0 {
		t.Fatalf("a check ran without a staging directory: %d", len(ex.reqs))
	}
}
