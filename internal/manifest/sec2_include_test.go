package manifest

import (
	"testing"

	"github.com/noahkiss/yadm/internal/model"
)

// A target whose source is a conditions.include file never auto-commits:
// it decides which machines get which entries, as manifest.toml does.
func TestSec2ConditionsIncludeTargetProtected(t *testing.T) {
	src := "schema = 1\n\n[conditions]\ninclude = [\"files/.config/tool/conds.toml\"]\n\n[[file]]\ntarget = \".config/tool/conds.toml\"\n\n[[file]]\ntarget = \".config/tool/other\"\n"
	m, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.LoadIncludes(readMap(map[string]string{"files/.config/tool/conds.toml": "[conditions]\ntool.work = \"type:work\"\n"})); err != nil {
		t.Fatal(err)
	}
	p, err := m.Resolve(ctxFor(t, "m-d4e5f6"), []model.SourcePath{"files/.config/tool/conds.toml", "files/.config/tool/other"}, fixtureVocab(t))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Protected(".config/tool/conds.toml") {
		t.Error("include target not protected")
	}
	if p.Protected(".config/tool/other") {
		t.Error("other target protected")
	}
}
