package model

import (
	"testing"
	"time"
)

func TestKeepSinceStableID(t *testing.T) {
	t0 := time.Date(2030, 1, 1, 9, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)
	first := KeepSince(nil, Hold{Task: "bundle", Reason: HoldTaskUntrusted}, t0)
	if !first.Since.Equal(t0) || first.ID != HoldID(first) || first.ID == "" {
		t.Fatalf("first: %+v", first)
	}
	again := KeepSince([]Hold{first}, Hold{Task: "bundle", Reason: HoldTaskUntrusted, Since: t1}, t1)
	if again.ID != first.ID || !again.Since.Equal(t0) {
		t.Fatalf("id moved: %+v vs %+v", again, first)
	}
	other := KeepSince([]Hold{first}, Hold{Target: ".x", Reason: HoldTaskUntrusted}, t1)
	if other.ID == first.ID || !other.Since.Equal(t1) {
		t.Fatalf("matched another hold: %+v", other)
	}
	if HoldID(Hold{Task: "a", Reason: HoldDrifted, Since: t0}) == HoldID(Hold{Target: "a", Reason: HoldDrifted, Since: t0}) {
		t.Fatal("task and target holds share an id")
	}
	local := t0.In(time.FixedZone("x", 3600))
	if HoldID(Hold{Target: "a", Reason: HoldDrifted, Since: local}) != HoldID(Hold{Target: "a", Reason: HoldDrifted, Since: t0}) {
		t.Fatal("id depends on the time zone")
	}
}
