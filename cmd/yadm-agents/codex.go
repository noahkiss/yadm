package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/noahkiss/yadm/internal/rules"
	"github.com/pelletier/go-toml/v2"
)

// codexAdapter owns each `hooks.<Event>` array of tables in Codex's
// config.toml by name. It never touches `hooks.state`, where Codex keeps
// its hook-trust records, or any other key.
//
// Codex keys trust by event and position and hashes each handler, so
// Order keeps every live handler at its position and appends new ones.
type codexAdapter struct{}

func (codexAdapter) Name() string          { return "codex" }
func (codexAdapter) DefaultConfig() string { return ".codex/config.toml" }
func (codexAdapter) Create() bool          { return false }
func (codexAdapter) Events() map[string]bool {
	return setOf("SessionStart", "SessionEnd", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
		"PermissionRequest", "Stop", "Interrupt")
}
func (codexAdapter) ToolEvents() map[string]bool {
	return setOf("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest")
}
func (codexAdapter) Effects() map[string]bool { return setOf("", "none", "deny", "context") }
func (codexAdapter) Wires(kind string) bool   { return kind == "guard" || kind == "hook" }

var codexTools = map[string]string{
	"shell":      "^Bash$",
	"file_write": "^apply_patch$",
	"file_edit":  "^apply_patch$",
}

func (codexAdapter) Unmapped(acts []string) []string {
	var out []string
	for _, a := range acts {
		base, _, _ := strings.Cut(a, ":")
		if base != "mcp_call" && codexTools[base] == "" {
			out = append(out, a)
		}
	}
	return out
}

// codexMatchers joins a unit's actions into one anchored regex.
func codexMatchers(acts []string) []string {
	plain, servers, all := splitActions(acts)
	var parts []string
	seen := map[string]bool{}
	for _, a := range plain {
		if t := codexTools[a]; t != "" && !seen[t] {
			seen[t] = true
			parts = append(parts, t)
		}
	}
	switch {
	case all:
		parts = append(parts, "^mcp__.*")
	case len(servers) > 0:
		parts = append(parts, "^mcp__("+strings.Join(servers, "|")+")__.*")
	}
	if len(parts) == 0 {
		return nil // no tool this harness has; the unit is not wired here
	}
	return []string{strings.Join(parts, "|")}
}

func (a codexAdapter) Render(units []Resolved) (Wiring, error) {
	var w Wiring
	for _, u := range wiredUnits(a, units) {
		for _, ev := range u.On {
			cmd := u.Command(ev, false)
			if cmd == "" {
				return w, fmt.Errorf("unit %q: no script or run", u.Unit)
			}
			for _, m := range eventMatchers(a, u, ev, codexMatchers) {
				w.Entries = append(w.Entries, Entry{Event: ev, Matcher: m, Command: cmd, Timeout: u.TimeoutFor(ev), Extra: u.Extra, Unit: u.Unit})
			}
		}
	}
	return w, nil
}

// Order keeps live handlers where they are, identified by matcher and
// command, and appends handlers the live file lacks in unit order.
func (codexAdapter) Order(live, w Wiring) Wiring {
	key := func(e Entry) string { return e.Event + "\x00" + e.Matcher + "\x00" + e.Command }
	pending := map[string][]int{}
	var events []string
	byEvent := map[string][]Entry{}
	for i, e := range w.Entries {
		pending[key(e)] = append(pending[key(e)], i)
	}
	used := make([]bool, len(w.Entries))
	add := func(e Entry) {
		if _, ok := byEvent[e.Event]; !ok {
			events = append(events, e.Event)
		}
		byEvent[e.Event] = append(byEvent[e.Event], e)
	}
	for _, e := range live.Entries {
		if idx := pending[key(e)]; len(idx) > 0 {
			pending[key(e)] = idx[1:]
			used[idx[0]] = true
			add(w.Entries[idx[0]])
		}
	}
	for i, e := range w.Entries {
		if !used[i] {
			add(e)
		}
	}
	out := Wiring{Values: w.Values}
	for _, ev := range events {
		out.Entries = append(out.Entries, byEvent[ev]...)
	}
	return out
}

// trustedLevel is the value Codex writes for a trusted project.
const trustedLevel = "trusted"

// TrustKey names a project's trust entry in Wiring.Values. Load reads every
// project's entry, so one gen does not own is carried as it is.
func (codexAdapter) TrustKey(abs string) string { return trustPrefix + abs }

const trustPrefix = "projects:"

func (codexAdapter) Load(b []byte) (Wiring, error) {
	w := Wiring{Values: map[string]string{}}
	var doc map[string]any
	if err := toml.Unmarshal(b, &doc); err != nil {
		return w, err
	}
	if ps, ok := doc["projects"].(map[string]any); ok {
		for p, v := range ps {
			if t, ok := v.(map[string]any); ok {
				if lv, ok := t["trust_level"].(string); ok {
					w.Values[trustPrefix+p] = lv
				}
			}
		}
	}
	hooks, _ := doc["hooks"].(map[string]any)
	for _, ev := range sortedKeys(hooks) {
		if ev == "state" {
			continue
		}
		groups, ok := hooks[ev].([]any)
		if !ok {
			return w, fmt.Errorf("hooks.%s is not an array of tables", ev)
		}
		for gi, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				return w, fmt.Errorf("hooks.%s[%d] is not a table", ev, gi)
			}
			matcher, _ := gm["matcher"].(string)
			hs, _ := gm["hooks"].([]any)
			for _, h := range hs {
				hm, ok := h.(map[string]any)
				if !ok {
					return w, fmt.Errorf("hooks.%s[%d].hooks holds a non-table", ev, gi)
				}
				w.Entries = append(w.Entries, entryFrom(ev, matcher, hm))
			}
		}
	}
	return w, nil
}

var bareKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (codexAdapter) Apply(b []byte, w Wiring, prev Wiring) ([]byte, error) {
	var src strings.Builder
	owned := map[string]bool{}
	for _, e := range prev.Entries {
		owned[e.Event] = true
	}
	for _, e := range w.Entries {
		if !bareKey.MatchString(e.Event) || e.Event == "state" {
			return nil, fmt.Errorf("event %q cannot be a Codex hooks table", e.Event)
		}
		owned[e.Event] = true
		fmt.Fprintf(&src, "[[hooks.%s]]\n", e.Event)
		if e.Matcher != "" {
			fmt.Fprintf(&src, "matcher = %s\n", tomlString(e.Matcher))
		}
		fmt.Fprintf(&src, "[[hooks.%s.hooks]]\ntype = \"command\"\ncommand = %s\n", e.Event, tomlString(e.Command))
		if e.Timeout > 0 {
			fmt.Fprintf(&src, "timeout = %d\n", e.Timeout)
		}
		for _, k := range sortedKeys(e.Extra) {
			if !bareKey.MatchString(k) {
				return nil, fmt.Errorf("extra key %q is not a bare TOML key", k)
			}
			v, err := tomlValue(e.Extra[k])
			if err != nil {
				return nil, fmt.Errorf("extra %s: %w", k, err)
			}
			fmt.Fprintf(&src, "%s = %s\n", k, v)
		}
		src.WriteString("\n")
	}
	var keep []string
	for _, ev := range sortedKeys(owned) {
		keep = append(keep, "hooks."+ev)
	}
	// Trust entries: only the ones that change. A project table that holds
	// nothing but its trust level is owned whole, so removing the entry
	// leaves no empty table behind.
	var live map[string]any
	if err := toml.Unmarshal(b, &live); err != nil {
		return nil, err
	}
	lps, _ := live["projects"].(map[string]any)
	keys := map[string]bool{}
	for k := range w.Values {
		keys[k] = true
	}
	for k := range prev.Values {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		p, ok := strings.CutPrefix(k, trustPrefix)
		if !ok || w.Values[k] == prev.Values[k] {
			continue
		}
		if v := w.Values[k]; v != "" {
			fmt.Fprintf(&src, "[projects.%s]\ntrust_level = %s\n\n", tomlString(p), tomlString(v))
		}
		path := "projects." + escapeKeyPath(p)
		if t, ok := lps[p].(map[string]any); ok && (len(t) > 1 || (len(t) == 1 && t["trust_level"] == nil)) {
			path += ".trust_level"
		}
		keep = append(keep, path)
	}
	return rules.ToTarget([]byte(src.String()), b, rules.Spec{Format: "toml", Keep: keep}, nil)
}

func tomlValue(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return tomlString(x), nil
	case bool:
		return strconv.FormatBool(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10), nil
		}
		return strconv.FormatFloat(x, 'g', -1, 64), nil
	}
	return "", fmt.Errorf("unsupported value type %T", v)
}

// tomlString spells s as a TOML literal string when it holds a quote or a
// backslash and can, and as a basic string otherwise.
func tomlString(s string) string {
	if strings.ContainsAny(s, `"\`) && !strings.ContainsAny(s, "'\n\r") {
		return "'" + s + "'"
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (codexAdapter) Rows(w Wiring) []string {
	pos := map[string]int{}
	var rows []string
	for _, e := range w.Entries {
		rows = append(rows, fmt.Sprintf("%s\t#%d\t%s\t%s\t%s", e.Event, pos[e.Event], e.Matcher, e.Command, handlerTail(e)))
		pos[e.Event]++
	}
	for _, k := range sortedKeys(w.Values) {
		if w.Values[k] != "" {
			rows = append(rows, fmt.Sprintf("value\t%s\t%s", k, w.Values[k]))
		}
	}
	sort.Strings(rows)
	return rows
}

func (codexAdapter) Unowned(b []byte) (any, error) {
	var doc map[string]any
	if err := toml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	if hooks, ok := doc["hooks"].(map[string]any); ok {
		for k := range hooks {
			if k != "state" {
				delete(hooks, k)
			}
		}
		if len(hooks) == 0 {
			delete(doc, "hooks")
		}
	}
	// Trust levels are compared as rows (every project's, owned or not), so
	// the rest of each project table is what must stay.
	if ps, ok := doc["projects"].(map[string]any); ok {
		for p, v := range ps {
			if t, ok := v.(map[string]any); ok {
				delete(t, "trust_level")
				if len(t) == 0 {
					delete(ps, p)
				}
			}
		}
		if len(ps) == 0 {
			delete(doc, "projects")
		}
	}
	return doc, nil
}

// escapeKeyPath escapes one key for a rules key path.
func escapeKeyPath(k string) string {
	return strings.NewReplacer(`\`, `\\`, ".", `\.`, "*", `\*`).Replace(k)
}
