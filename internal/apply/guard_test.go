package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/tasks"
)

func guardSnap(roots []manifest.Root, entries ...manifest.Entry) *Snapshot {
	p := &manifest.Plan{Targets: map[model.Target]manifest.Resolved{}, Roots: roots}
	for i, e := range entries {
		p.Targets[e.Target] = manifest.Resolved{Target: e.Target, Entry: e, Index: i}
	}
	return &Snapshot{Plan: p}
}

func TestGuardRefusesWeakerProtection(t *testing.T) {
	ctx := context.Background()
	allow := tasks.FileAllowList(t.TempDir())
	g := &Guard{List: allow}
	from := guardSnap(nil,
		manifest.Entry{Target: ".config/notes/private.md", Enclave: "personal"},
		manifest.Entry{Target: ".config/tool/settings.json", Format: manifest.FormatJSON, Seal: map[string]model.EnclaveName{"token": "personal"}},
		manifest.Entry{Target: ".ssh/config", Regions: true},
		manifest.Entry{Target: ".config/shell/aliases.sh"},
	)
	same := guardSnap(nil, entriesOf(from)...)
	if ok, detail, err := g.Allow(ctx, from, same); !ok || err != nil {
		t.Fatalf("unchanged manifest refused: %s %v", detail, err)
	}
	// Stronger is fine; a new plain target is fine.
	stronger := guardSnap(nil, append(entriesOf(from),
		manifest.Entry{Target: ".config/new.sh"})...)
	stronger.Plan.Targets[".config/shell/aliases.sh"] = manifest.Resolved{Target: ".config/shell/aliases.sh", Entry: manifest.Entry{Target: ".config/shell/aliases.sh", Enclave: "personal"}}
	if ok, detail, _ := g.Allow(ctx, from, stronger); !ok {
		t.Fatalf("stronger manifest refused: %s", detail)
	}
	cases := map[string]manifest.Entry{
		"no longer sealed": {Target: ".config/notes/private.md"},
		"moved from":       {Target: ".config/notes/private.md", Enclave: "client"},
		"seal token":       {Target: ".config/tool/settings.json", Format: manifest.FormatJSON},
		"regions":          {Target: ".ssh/config"},
	}
	for want, e := range cases {
		to := guardSnap(nil, entriesOf(from)...)
		to.Plan.Targets[e.Target] = manifest.Resolved{Target: e.Target, Entry: e}
		ok, detail, err := g.Allow(ctx, from, to)
		if ok || err != nil || !strings.Contains(detail, want) || !strings.Contains(detail, "yadm protection allow "+string(e.Target)) {
			t.Errorf("%s: ok=%v detail=%q err=%v", want, ok, detail, err)
			continue
		}
		// The local allow releases exactly this weakening.
		if err := allow.Allow(KindProtection, string(e.Target), protectionHash(e.Target, protOf(e))); err != nil {
			t.Fatal(err)
		}
		if ok, detail, _ := g.Allow(ctx, from, to); !ok {
			t.Errorf("%s: still refused after allow: %s", want, detail)
		}
	}
	// No allow list: nothing weaker is allowed.
	to := guardSnap(nil, entriesOf(from)...)
	to.Plan.Targets[".ssh/config"] = manifest.Resolved{Target: ".ssh/config", Entry: manifest.Entry{Target: ".ssh/config"}}
	if ok, _, _ := (&Guard{}).Allow(ctx, from, to); ok {
		t.Error("guard without allow list accepted a weaker manifest")
	}
}

func TestGuardRefusesRootOverProtectedPath(t *testing.T) {
	ctx := context.Background()
	allow := tasks.FileAllowList(t.TempDir())
	g := &Guard{List: allow}
	from := guardSnap([]manifest.Root{{Path: ".config/private", Enclave: "personal"}},
		manifest.Entry{Target: ".config/notes/private.md", Enclave: "personal"},
		manifest.Entry{Target: ".config/shell/aliases.sh"},
	)
	// A plain root over plain files only is apply's business (root_untrusted).
	to := guardSnap(append(from.Plan.Roots, manifest.Root{Path: ".config/shell"}), entriesOf(from)...)
	if ok, detail, _ := g.Allow(ctx, from, to); !ok {
		t.Fatalf("plain root over plain files refused: %s", detail)
	}
	for _, r := range []manifest.Root{
		{Path: ".config/notes"},               // covers a sealed file
		{Path: ".config"},                     // wraps an enclave root
		{Path: ".config/private/inner"},       // inside an enclave root
		{Path: ".config/notes", Enclave: "x"}, // another enclave
	} {
		to := guardSnap(append(append([]manifest.Root{}, from.Plan.Roots...), r), entriesOf(from)...)
		ok, detail, _ := g.Allow(ctx, from, to)
		if ok || !strings.Contains(detail, "yadm root allow "+string(r.Path)) {
			t.Errorf("root %+v: ok=%v detail=%q", r, ok, detail)
			continue
		}
		if err := allow.Allow(KindRoot, string(r.Path), rootHash(r)); err != nil {
			t.Fatal(err)
		}
		if ok, detail, _ := g.Allow(ctx, from, to); !ok {
			t.Errorf("root %+v still refused after allow: %s", r, detail)
		}
	}
	// The enclave root turning plain is refused too.
	to = guardSnap([]manifest.Root{{Path: ".config/private"}}, entriesOf(from)...)
	if ok, _, _ := (&Guard{List: tasks.FileAllowList(t.TempDir())}).Allow(ctx, from, to); ok {
		t.Error("enclave root turned plain was accepted")
	}
}

func entriesOf(s *Snapshot) []manifest.Entry {
	var out []manifest.Entry
	for _, r := range s.Plan.Targets {
		out = append(out, r.Entry)
	}
	return out
}
