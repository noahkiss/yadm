package cli

import (
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

// TestHoldSubject: a hold that names a target and a task is shown by its
// target alone, not the two glued together.
func TestHoldSubject(t *testing.T) {
	for _, c := range []struct {
		h    model.Hold
		want string
	}{
		{model.Hold{Target: ".config/x", Task: "manifest-guard"}, ".config/x"},
		{model.Hold{Task: "key-log"}, "key-log"},
		{model.Hold{Target: ".config/y"}, ".config/y"},
	} {
		if got := holdSubject(c.h); got != c.want {
			t.Errorf("holdSubject(%+v) = %q, want %q", c.h, got, c.want)
		}
	}
}
