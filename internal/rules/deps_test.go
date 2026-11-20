package rules

import (
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
	"github.com/tidwall/sjson"
)

// TestDependencies records what the format libraries do and do not do, so the
// rules implementation knows which parts it must own.
func TestDependencies(t *testing.T) {
	t.Run("sjson set keeps comments and spacing", func(t *testing.T) {
		in := "{\n  // owned by the app\n  \"a\": 1,\n  \"b\": {\"c\": 2}\n}\n"
		out, err := sjson.Set(in, "b.c", 3)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Replace(in, `"c": 2`, `"c": 3`, 1)
		if out != want {
			t.Fatalf("sjson.Set changed more than the value:\n%q", out)
		}
	})
	t.Run("sjson delete also removes the comment above the key", func(t *testing.T) {
		in := "{\n  // owned by the app\n  \"a\": 1,\n  \"b\": 2\n}\n"
		out, err := sjson.Delete(in, "a")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "owned by the app") {
			t.Skip("sjson now keeps the comment; the rules package can drop its workaround")
		}
		// Known caveat: deletion owns the preceding comment. Rules must
		// decide comment ownership itself before calling Delete.
	})
	t.Run("go-toml decodes and its unstable parser keeps comments", func(t *testing.T) {
		src := []byte("a = 1 # trailing\n[t]\nb = [1,\n  2]\n")
		var v map[string]any
		if err := toml.Unmarshal(src, &v); err != nil {
			t.Fatal(err)
		}
		p := unstable.Parser{KeepComments: true}
		p.Reset(src)
		var kinds []unstable.Kind
		for p.NextExpression() {
			kinds = append(kinds, p.Expression().Kind)
		}
		if p.Error() != nil {
			t.Fatal(p.Error())
		}
		if len(kinds) < 3 {
			t.Fatalf("expected key-value, comment and table expressions, got %v", kinds)
		}
		// Known caveat: an expression node's own range is empty for key-values;
		// byte spans come from its child key and value nodes. The TOML span
		// editor in this package is our code.
	})
}
