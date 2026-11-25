package main

import (
	"fmt"
	"regexp"
	"strings"
)

// The normalized action vocabulary of docs/hooks.md. A rule names actions,
// never harness tool names; each adapter maps them to its own matchers.
var actions = []string{"shell", "file_read", "file_write", "file_edit", "web_fetch", "web_search", "mcp_call", "agent_spawn"}

// serverName is an MCP server name as harnesses spell it in tool names.
// It lands inside a matcher regex, so nothing else may pass.
var serverName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func checkAction(a string) error {
	base, server, hasServer := strings.Cut(a, ":")
	for _, x := range actions {
		if base == x {
			if hasServer && base != "mcp_call" {
				return fmt.Errorf("action %q: only mcp_call takes a server", a)
			}
			if hasServer && !serverName.MatchString(server) {
				return fmt.Errorf("action %q: a server name uses letters, digits, _ and -", a)
			}
			return nil
		}
	}
	return fmt.Errorf("unknown action %q (known: %s, mcp_call:<server>)", a, strings.Join(actions, ", "))
}

// splitActions separates plain actions from MCP servers. all reports a bare
// mcp_call, which covers every server.
func splitActions(as []string) (plain []string, servers []string, all bool) {
	for _, a := range as {
		base, server, _ := strings.Cut(a, ":")
		switch {
		case base != "mcp_call":
			plain = append(plain, base)
		case server == "":
			all = true
		default:
			servers = append(servers, server)
		}
	}
	return plain, servers, all
}

// Entry is one handler in a harness's wiring: one command on one event
// under one matcher.
type Entry struct {
	Event   string
	Matcher string
	Command string
	Timeout int64
	Extra   map[string]any
	Unit    string // the unit that produced it; empty when read from a live file
}

// Wiring is what an adapter owns in its file.
type Wiring struct {
	Entries []Entry
	Values  map[string]string // other owned scalar keys, such as a mod list
}

// Adapter knows one harness's wiring format. Harness names are open
// strings: an adapter registers one, and a cell naming a harness with no
// adapter is reported by verify, not rejected by the parser.
type Adapter interface {
	Name() string
	// DefaultConfig is the owned file, relative to home; "" means the
	// units file must name it in [harness.<name>] config.
	DefaultConfig() string
	// Create reports whether gen may create a missing file. Adapters that
	// own keys inside an app's config never create it.
	Create() bool
	Events() map[string]bool
	ToolEvents() map[string]bool
	Effects() map[string]bool
	// Wires reports whether gen writes wiring for a unit of this kind.
	Wires(kind string) bool
	// Unmapped lists the actions this harness has no tool for.
	Unmapped(acts []string) []string
	Render(units []Resolved) (Wiring, error)
	// Load reads the owned wiring from file bytes.
	Load(b []byte) (Wiring, error)
	// Apply returns b with the owned keys replaced by w.
	Apply(b []byte, w Wiring, prev Wiring) ([]byte, error)
	// Rows flattens wiring into comparable lines. Two wirings with the
	// same rows behave the same in this harness.
	Rows(w Wiring) []string
	// Unowned parses b with the owned keys removed, so gen can prove an
	// edit left everything else alone. nil means the adapter owns the file.
	Unowned(b []byte) (any, error)
}

// orderer is an adapter whose handler order carries meaning: Order fits
// rendered wiring to the live file's order.
type orderer interface {
	Order(live, w Wiring) Wiring
}

var registry = map[string]Adapter{}

func register(a Adapter) { registry[a.Name()] = a }

func init() {
	register(claudeAdapter{})
	register(codexAdapter{})
	register(routeAdapter{name: "opencode"})
	register(routeAdapter{name: "pi"})
}

func adapterFor(h string) (Adapter, bool) {
	a, ok := registry[h]
	return a, ok
}

func setOf(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// wiredUnits lists the enabled units an adapter writes, in units-file order.
func wiredUnits(a Adapter, units []Resolved) []Resolved {
	var out []Resolved
	for _, u := range units {
		if !u.Enabled || u.Via != "" || !a.Wires(u.Kind) {
			continue
		}
		out = append(out, u)
	}
	return out
}
