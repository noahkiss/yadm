package apply

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// TestCaptureTemplateWithKeep: a template entry with keep rules captures
// through the rules and the template patcher. An app-owned key edit commits
// nothing; a kept literal edit patches the template and keeps its
// expressions; an edit on a rendered expression is held with a patch.
func TestCaptureTemplateWithKeep(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	w.eng.Rules = pkgRules{}
	w.eng.Text = pkgText{}
	const tg = model.Target(".config/app/settings.json")
	tmpl := "{\n  \"name\": \"{{ machine.name }}\",\n  \"theme\": \"dark\"\n}\n"
	entry := manifest.Entry{Target: tg, Template: true, Format: manifest.FormatJSON, Keep: []string{"name", "theme"}}
	c := w.commit(map[model.SourcePath]string{"files/" + model.SourcePath(tg): tmpl}, entry)
	if _, err := w.eng.Apply(ctx, c, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := w.read(tg); !strings.Contains(got, `"name": "host-a"`) {
		t.Fatalf("applied:\n%s", got)
	}
	capture := func(content string) Capture {
		t.Helper()
		w.tick(1e9)
		if err := os.WriteFile(w.path(tg), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ds, err := w.eng.Scan(ctx, ScanOptions{FullHash: true})
		if err != nil {
			t.Fatal(err)
		}
		cp, err := w.eng.Capture(ctx, ds)
		if err != nil {
			t.Fatal(err)
		}
		return cp
	}

	// The app adds its own key: nothing to commit, no hold.
	appEdit := "{\n  \"name\": \"host-a\",\n  \"theme\": \"dark\",\n  \"window\": {\"x\": 3}\n}\n"
	if cp := capture(appEdit); len(cp.Changes) != 0 || len(cp.Holds) != 0 {
		t.Fatalf("app-owned edit: changes %+v holds %+v", cp.Changes, cp.Holds)
	}

	// A kept literal edit patches the template; the expression stays.
	cp := capture(strings.Replace(appEdit, `"dark"`, `"light"`, 1))
	if len(cp.Holds) != 0 || len(cp.Changes) != 1 {
		t.Fatalf("kept edit: changes %+v holds %+v", cp.Changes, cp.Holds)
	}
	got := string(cp.Changes[0].Blob)
	if !strings.Contains(got, `"theme": "light"`) || !strings.Contains(got, "{{ machine.name }}") || strings.Contains(got, "window") {
		t.Fatalf("patched template:\n%s", got)
	}

	// An edit on the rendered expression is held for review with a patch.
	cp = capture(strings.Replace(appEdit, `"host-a"`, `"host-z"`, 1))
	if len(cp.Changes) != 0 || len(cp.Holds) != 1 || cp.Holds[0].Reason != model.HoldRenderedEdit || cp.Holds[0].Patch == "" {
		t.Fatalf("expression edit: changes %+v holds %+v", cp.Changes, cp.Holds)
	}
}
