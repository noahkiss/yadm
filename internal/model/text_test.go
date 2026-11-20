package model

import (
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

func TestTextTypesInTOML(t *testing.T) {
	var v struct {
		Quiet Duration `toml:"quiet"`
		Sig   Base64   `toml:"sig"`
	}
	if err := toml.Unmarshal([]byte("quiet = \"2h\"\nsig = \"AQID\"\n"), &v); err != nil {
		t.Fatal(err)
	}
	if v.Quiet.D() != 2*time.Hour || string(v.Sig) != "\x01\x02\x03" {
		t.Fatalf("%+v", v)
	}
	out, err := toml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	w := v
	if err := toml.Unmarshal(out, &w); err != nil || w.Quiet != v.Quiet || string(w.Sig) != string(v.Sig) {
		t.Fatalf("round trip: %q %v", out, err)
	}
}
