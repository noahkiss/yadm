package cli

import (
	"io"
	"slices"
	"testing"

	"github.com/spf13/pflag"
)

// TestGlobalFlagValueIsNotACommand: the value of a global flag given as a
// separate argument (`--lock-wait 5s`) is never taken as the command name,
// for a built-in command or an external one, and a plugin gets only the
// arguments after its name. Every global flag that takes a value is covered.
func TestGlobalFlagValueIsNotACommand(t *testing.T) {
	root := (&app{stdout: io.Discard, stderr: io.Discard}).root()
	valued := map[string]string{"lock-wait": "5s"}
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.NoOptDefVal == "" && f.Value.Type() != "bool" {
			if _, ok := valued[f.Name]; !ok {
				t.Errorf("global flag --%s takes a value; add it to this test", f.Name)
			}
		}
	})
	for name, val := range valued {
		if _, _, ok := externalName(root, []string{"--" + name, val, "status"}); ok {
			t.Errorf("--%s %s status: taken as an external command", name, val)
		}
		n, rest, ok := externalName(root, []string{"--" + name, val, "greet", "x"})
		if !ok || n != "greet" || !slices.Equal(rest, []string{"x"}) {
			t.Errorf("--%s %s greet x: name %q rest %v ok %v", name, val, n, rest, ok)
		}
		if got := pluginArgs(root, []string{"--" + name, val, "greet", "x", "--json"}); !slices.Equal(got, []string{"x", "--json"}) {
			t.Errorf("--%s %s greet: plugin args %v", name, val, got)
		}
		if n, _, _ := externalName(root, []string{"--" + name + "=" + val, "greet"}); n != "greet" {
			t.Errorf("--%s=%s greet: name %q", name, val, n)
		}
	}
	if n, _, _ := externalName(root, []string{"--json", "greet"}); n != "greet" {
		t.Errorf("--json greet: name %q", n)
	}
}
