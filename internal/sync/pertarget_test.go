package sync

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/extexec"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

// batchGate behaves like one broad check: it fails every file it is given
// when any of them holds "bad", and fails untrusted files as a whole.
type batchGate struct{ calls int }

func (g *batchGate) Check(_ context.Context, staged []tasks.Staged, _ extexec.Request) ([]model.Target, []model.Hold, []tasks.Verdict) {
	g.calls++
	bad, untrusted := false, false
	for _, s := range staged {
		bad = bad || strings.Contains(string(s.Plaintext), "bad")
		untrusted = untrusted || strings.Contains(string(s.Plaintext), "untrusted")
	}
	var pass []model.Target
	var holds []model.Hold
	var vs []tasks.Verdict
	for _, s := range staged {
		switch {
		case untrusted:
			holds = append(holds, model.Hold{ID: "u-" + string(s.Target), Target: s.Target, Reason: model.HoldTaskUntrusted})
		case bad:
			holds = append(holds, model.Hold{ID: "b-" + string(s.Target), Target: s.Target, Reason: model.HoldCheckFailed})
			vs = append(vs, tasks.Verdict{Target: s.Target, Check: "scan", Pass: false})
		default:
			pass = append(pass, s.Target)
			vs = append(vs, tasks.Verdict{Target: s.Target, Check: "scan", Pass: true})
		}
	}
	return pass, holds, vs
}

func TestPerTargetGate(t *testing.T) {
	ctx := context.Background()
	staged := []tasks.Staged{
		{Target: "a", Plaintext: []byte("fine")},
		{Target: "b", Plaintext: []byte("bad")},
		{Target: "c", Plaintext: []byte("fine")},
	}
	g := &batchGate{}
	pass, holds, vs := PerTarget(g).Check(ctx, staged, extexec.Request{})
	if len(pass) != 2 || len(holds) != 1 || holds[0].Target != "b" {
		t.Fatalf("pass %v holds %+v", pass, holds)
	}
	if g.calls != 4 {
		t.Errorf("calls %d, want 1 batch + 3 singles", g.calls)
	}
	fails := 0
	for _, v := range vs {
		if !v.Pass {
			fails++
			if v.Target != "b" {
				t.Errorf("verdict %+v", v)
			}
		}
	}
	if fails != 1 || len(vs) != 3 {
		t.Errorf("verdicts %+v", vs)
	}

	// All pass: one run.
	g = &batchGate{}
	if pass, _, _ := PerTarget(g).Check(ctx, []tasks.Staged{staged[0], staged[2]}, extexec.Request{}); len(pass) != 2 || g.calls != 1 {
		t.Errorf("clean batch: pass %v calls %d", pass, g.calls)
	}
	// Untrusted holds every match; no split.
	g = &batchGate{}
	un := append([]tasks.Staged{{Target: "d", Plaintext: []byte("untrusted")}}, staged[0])
	if pass, holds, _ := PerTarget(g).Check(ctx, un, extexec.Request{}); len(pass) != 0 || len(holds) != 2 || g.calls != 1 {
		t.Errorf("untrusted: pass %v holds %v calls %d", pass, holds, g.calls)
	}
	// Wrapping twice does not split twice.
	if _, ok := PerTarget(PerTarget(g)).(perTarget); !ok {
		t.Error("double wrap")
	}
}
