package rules

import (
	"bytes"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// A short sealed value is caught when it reappears as a whole quoted string,
// and not when it only occurs inside other text.
func TestLeakCheckShortValues(t *testing.T) {
	s := member(personal)
	spec := Spec{Source: testSource, Format: manifest.FormatJSON, Seal: map[string]model.EnclaveName{"pin": personal}}
	live := []byte("{\n  \"pin\": \"4711\",\n  \"note\": \"call 47110\"\n}\n")
	src := mustSource(t, live, nil, spec, s)
	if bytes.Contains(src, []byte(`"4711"`)) {
		t.Fatalf("short value not sealed: %s", src)
	}
	// Inside other text: no hold.
	edited := bytes.Replace(live, []byte("call 47110"), []byte("call 47111"), 1)
	if _, vio, err := ToSource(edited, src, spec, s); err != nil || len(vio) > 0 {
		t.Fatalf("substring flagged: %v %v", vio, err)
	}
	// As a whole string at another key: held.
	copied := bytes.Replace(live, []byte(`"call 47110"`), []byte(`"4711"`), 1)
	out, vio, err := ToSource(copied, src, spec, s)
	if err != nil || out != nil || len(vio) == 0 || vio[0].Kind != SealedValueLeaked {
		t.Fatalf("short leak missed: %v %v", vio, err)
	}
	// TOML literal strings count too.
	tspec := Spec{Source: testSource, Format: manifest.FormatTOML, Seal: map[string]model.EnclaveName{"pin": personal}}
	tlive := []byte("pin = \"4711\"\nnote = \"x\"\n")
	tsrc := mustSource(t, tlive, nil, tspec, s)
	tcopied := []byte("pin = \"4711\"\nnote = '4711'\n")
	if out, vio, err := ToSource(tcopied, tsrc, tspec, s); err != nil || out != nil || len(vio) == 0 {
		t.Fatalf("toml literal leak missed: %v %v", vio, err)
	}
}

// On a first capture a region line that also stands outside the region is
// not a leak: nothing was sealed before.
func TestFirstCaptureRegionLineElsewhere(t *testing.T) {
	s := member(personal)
	live := []byte("Host a\n  User example-user\n\n# yadm:seal personal hosts\nHost b\n  User example-user\n  HostName 192.0.2.77\n# yadm:end\n")
	src, vio, err := ToSource(live, nil, regionSpec, s)
	if err != nil || len(vio) > 0 {
		t.Fatalf("first capture held: %v %v", vio, err)
	}
	if strings.Contains(string(src), "Host b") {
		t.Fatalf("region not sealed: %s", src)
	}
	// Later, copying a region line out is a leak.
	moved := []byte("Host a\n  User example-user\n  HostName 192.0.2.77\n\n# yadm:seal personal hosts\nHost b\n  User example-user\n  HostName 192.0.2.77\n# yadm:end\n")
	if out, vio, _ := ToSource(moved, src, regionSpec, s); out != nil || len(vio) == 0 || vio[0].Kind != SealedValueLeaked {
		t.Fatalf("moved region line missed: %v", vio)
	}
}
