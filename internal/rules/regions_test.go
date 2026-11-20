package rules

import (
	"bytes"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/secrecytest"
)

func sshLive(secret, eol string) string {
	s := `Host *
  ServerAliveInterval 60

Host git.example.invalid
  User git

# yadm:seal personal hosts
Host private-box
  HostName 192.0.2.10
  User example
  # ` + secret + `
# yadm:end

Host last
  User other`
	return strings.ReplaceAll(s, "\n", eol)
}

var regionSpec = Spec{Regions: true}

func TestRegions(t *testing.T) {
	for name, eol := range map[string]string{"lf": "\n", "crlf": "\r\n"} {
		t.Run(name, func(t *testing.T) {
			c := secrecytest.NewCanary(t, "personal")
			s := member(personal)
			live := []byte(sshLive(c.String(), eol))
			src := mustSource(t, live, nil, regionSpec, s)
			assertNoCanary(t, c, "source", src)
			if bytes.Contains(src, []byte("private-box")) || !bytes.Contains(src, []byte("# yadm:sealed 1 1 ")) {
				t.Fatalf("source:\n%s", src)
			}
			if eol == "\r\n" && bytes.Count(src, []byte("\n")) != bytes.Count(src, []byte("\r\n")) {
				t.Fatalf("CRLF lost: %q", src)
			}
			if bytes.HasSuffix(src, []byte("\n")) {
				t.Fatal("missing final newline was added")
			}
			if got := mustTarget(t, src, nil, regionSpec, s); !bytes.Equal(got, live) {
				t.Fatalf("member target:\n%q", got)
			}
			nm := member()
			tgt := mustTarget(t, src, nil, regionSpec, nm)
			assertNoCanary(t, c, "non-member target", tgt)
			if !bytes.Contains(tgt, []byte("# yadm:seal personal hosts"+eol+"# yadm:end")) {
				t.Fatalf("non-member target:\n%q", tgt)
			}
			if back := mustSource(t, tgt, src, regionSpec, nm); !bytes.Equal(back, src) {
				t.Fatalf("non-member capture:\n%q", back)
			}
			// A non-member edits outside the region.
			edited := bytes.Replace(tgt, []byte("ServerAliveInterval 60"), []byte("ServerAliveInterval 30"), 1)
			back := mustSource(t, edited, src, regionSpec, nm)
			if want := bytes.Replace(src, []byte("ServerAliveInterval 60"), []byte("ServerAliveInterval 30"), 1); !bytes.Equal(back, want) {
				t.Fatalf("non-member edit:\n%q", back)
			}
			// A member edits inside the region: only the token line changes.
			medit := bytes.Replace(live, []byte("User example"), []byte("User example2"), 1)
			msrc := mustSource(t, medit, src, regionSpec, s)
			assertNoCanary(t, c, "source", msrc)
			if bytes.Equal(msrc, src) || len(splitLines(msrc)) != len(splitLines(src)) {
				t.Fatalf("member region edit:\n%q", msrc)
			}
		})
	}
}

func TestRegionGuard(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	s := member(personal)
	live := []byte(sshLive(c.String(), "\n"))
	src := mustSource(t, live, nil, regionSpec, s)
	nm := member()
	nmTarget := mustTarget(t, src, nil, regionSpec, nm)

	cases := map[string]struct {
		target []byte
		s      Sealer
		kind   ViolationKind
	}{
		"end marker gone":      {bytes.Replace(live, []byte("# yadm:end\n"), nil, 1), s, RegionMarkerLost},
		"both markers gone":    {bytes.Replace(bytes.Replace(live, []byte("# yadm:end\n"), nil, 1), []byte("# yadm:seal personal hosts\n"), nil, 1), s, RegionMarkerLost},
		"label changed":        {bytes.Replace(live, []byte("personal hosts"), []byte("personal other"), 1), s, RegionMarkerLost},
		"stray end":            {append(append([]byte(nil), live...), []byte("\n# yadm:end\n")...), s, RegionMarkerLost},
		"nested start":         {bytes.Replace(live, []byte("Host private-box"), []byte("# yadm:seal personal x\nHost private-box"), 1), s, RegionMarkerLost},
		"line copied out":      {bytes.Replace(live, []byte("Host last"), []byte("Host last\n  # "+c.String()), 1), s, SealedValueLeaked},
		"non-member writes":    {bytes.Replace(nmTarget, []byte("hosts\n# yadm:end"), []byte("hosts\nHost guess\n# yadm:end"), 1), nm, RegionNotMember},
		"non-member new":       {append(append([]byte(nil), nmTarget...), []byte("\n# yadm:seal personal more\n# yadm:end\n")...), nm, RegionNotMember},
		"non-member drops end": {bytes.Replace(nmTarget, []byte("# yadm:end\n"), nil, 1), nm, RegionMarkerLost},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertViolation(t, tc.target, src, regionSpec, tc.s, tc.kind, c)
		})
	}
}

func TestRegionsWithJSONC(t *testing.T) {
	c := secrecytest.NewCanary(t, "personal")
	spec := settingsSpec
	spec.Regions = true
	live := []byte(strings.Replace(liveSettings("plain-token-0001"), "  \"telemetry\": false,\n", "  // yadm:seal personal extra\n  \"editor.secret\": \""+c.String()+"\",\n  // yadm:end\n  \"telemetry\": false,\n", 1))
	s := member(personal)
	src := mustSource(t, live, nil, Spec{Format: spec.Format, Regions: true, Drop: spec.Drop}, s)
	assertNoCanary(t, c, "source", src)
	if !bytes.Contains(src, []byte("  // yadm:sealed 1 1 ")) {
		t.Fatalf("source:\n%s", src)
	}
}
