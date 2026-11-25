package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/noahkiss/yadm/internal/rules"
)

// claudeAdapter owns `.hooks` and `env.CLAUDE_CODE_PLUGIN_DIRS` in Claude
// Code's settings.json. Claude Code rewrites the rest of the file at run
// time, so every other key stays byte for byte.
type claudeAdapter struct{}

const claudeModsKey = "env.CLAUDE_CODE_PLUGIN_DIRS"

var claudeTools = map[string][]string{
	"shell":       {"Bash"},
	"file_read":   {"Read", "Glob", "Grep"},
	"file_write":  {"Write"},
	"file_edit":   {"Edit", "MultiEdit", "NotebookEdit"},
	"web_fetch":   {"WebFetch"},
	"web_search":  {"WebSearch"},
	"agent_spawn": {"Agent", "Task"},
}

func (claudeAdapter) Name() string          { return "claude" }
func (claudeAdapter) DefaultConfig() string { return ".claude/settings.json" }
func (claudeAdapter) Create() bool          { return false }
func (claudeAdapter) Events() map[string]bool {
	return setOf("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "Notification",
		"UserPromptSubmit", "Stop", "StopFailure", "SubagentStart", "SubagentStop", "PreCompact", "PostCompact",
		"SessionStart", "SessionEnd")
}
func (claudeAdapter) ToolEvents() map[string]bool {
	return setOf("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest")
}
func (claudeAdapter) Effects() map[string]bool {
	return setOf("", "none", "deny", "ask", "context", "rewrite")
}
func (claudeAdapter) Wires(kind string) bool {
	return kind == "guard" || kind == "hook" || kind == "mod"
}

func (claudeAdapter) Unmapped(acts []string) []string {
	var out []string
	for _, a := range acts {
		base, _, _ := strings.Cut(a, ":")
		if base != "mcp_call" && claudeTools[base] == nil {
			out = append(out, a)
		}
	}
	return out
}

// claudeMatchers turns actions into Claude matchers: one exact-name list,
// and one regex for MCP tools. Claude reads a matcher of only letters,
// digits, `_` and `|` as exact names and anything else as a regex, so the
// two never share a matcher.
func claudeMatchers(acts []string) []string {
	plain, servers, all := splitActions(acts)
	var names []string
	seen := map[string]bool{}
	for _, a := range plain {
		for _, t := range claudeTools[a] {
			if !seen[t] {
				seen[t] = true
				names = append(names, t)
			}
		}
	}
	var out []string
	if len(names) > 0 {
		out = append(out, strings.Join(names, "|"))
	}
	switch {
	case all:
		out = append(out, "mcp__.*")
	case len(servers) > 0:
		out = append(out, "^mcp__("+strings.Join(servers, "|")+")__.*")
	}
	return out
}

func eventMatchers(a Adapter, u Resolved, ev string, fromActions func([]string) []string) []string {
	if m, ok := u.MatchFor(ev); ok {
		return []string{m}
	}
	if a.ToolEvents()[ev] && len(u.Actions) > 0 {
		return fromActions(u.Actions)
	}
	return []string{""}
}

func (a claudeAdapter) Render(units []Resolved) (Wiring, error) {
	w := Wiring{Values: map[string]string{}}
	var mods []string
	sawMod := false
	for _, u := range units {
		if u.Kind == "mod" && u.Via == "" {
			sawMod = true
		}
	}
	for _, u := range wiredUnits(a, units) {
		if u.Kind == "mod" {
			if u.Dir == "" {
				return w, fmt.Errorf("unit %q: a mod needs dir", u.Unit)
			}
			mods = append(mods, u.Dir)
			continue
		}
		for _, ev := range u.On {
			cmd := u.Command(ev, true)
			if cmd == "" {
				return w, fmt.Errorf("unit %q: no script or run", u.Unit)
			}
			for _, m := range eventMatchers(a, u, ev, claudeMatchers) {
				w.Entries = append(w.Entries, Entry{Event: ev, Matcher: m, Command: cmd, Timeout: u.TimeoutFor(ev), Extra: u.Extra, Unit: u.Unit})
			}
		}
	}
	if sawMod {
		w.Values[claudeModsKey] = strings.Join(mods, ":")
	}
	return w, nil
}

// claudeOwned lists the owned key paths. The mod list is owned whenever
// the units file defines a mod for Claude, so a machine with every mod
// off still clears it.
func claudeOwned(w Wiring) []string {
	keep := []string{"hooks"}
	if _, ok := w.Values[claudeModsKey]; ok {
		keep = append(keep, claudeModsKey)
	}
	return keep
}

func (claudeAdapter) Load(b []byte) (Wiring, error) {
	w := Wiring{Values: map[string]string{}}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return w, err
	}
	if env, ok := doc["env"].(map[string]any); ok {
		if v, ok := env["CLAUDE_CODE_PLUGIN_DIRS"].(string); ok {
			w.Values[claudeModsKey] = v
		}
	}
	hooks, _ := doc["hooks"].(map[string]any)
	for _, ev := range sortedKeys(hooks) {
		groups, ok := hooks[ev].([]any)
		if !ok {
			return w, fmt.Errorf("hooks.%s is not an array", ev)
		}
		for gi, g := range groups {
			gm, ok := g.(map[string]any)
			if !ok {
				return w, fmt.Errorf("hooks.%s[%d] is not an object", ev, gi)
			}
			matcher, _ := gm["matcher"].(string)
			hs, _ := gm["hooks"].([]any)
			for _, h := range hs {
				hm, ok := h.(map[string]any)
				if !ok {
					return w, fmt.Errorf("hooks.%s[%d].hooks holds a non-object", ev, gi)
				}
				w.Entries = append(w.Entries, entryFrom(ev, matcher, hm))
			}
		}
	}
	return w, nil
}

func entryFrom(ev, matcher string, hm map[string]any) Entry {
	e := Entry{Event: ev, Matcher: matcher}
	e.Command, _ = hm["command"].(string)
	switch t := hm["timeout"].(type) {
	case float64:
		e.Timeout = int64(t)
	case int64:
		e.Timeout = t
	}
	for k, v := range hm {
		switch k {
		case "command", "timeout":
			continue
		case "type":
			if v == "command" {
				continue
			}
		}
		if e.Extra == nil {
			e.Extra = map[string]any{}
		}
		e.Extra[k] = v
	}
	return e
}

// hooksJSON renders the `.hooks` object: events in first-use order, one
// group per (event, matcher) in first-use order, handlers in unit order.
func hooksJSON(entries []Entry) []byte {
	type group struct {
		matcher string
		hs      []Entry
	}
	var events []string
	groups := map[string][]*group{}
	for _, e := range entries {
		gs, ok := groups[e.Event]
		if !ok {
			events = append(events, e.Event)
		}
		var g *group
		for _, x := range gs {
			if x.matcher == e.Matcher {
				g = x
			}
		}
		if g == nil {
			g = &group{matcher: e.Matcher}
			groups[e.Event] = append(gs, g)
		}
		g.hs = append(g.hs, e)
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, ev := range events {
		if i > 0 {
			buf.WriteByte(',')
		}
		writeJSON(&buf, ev)
		buf.WriteString(":[")
		for j, g := range groups[ev] {
			if j > 0 {
				buf.WriteByte(',')
			}
			buf.WriteByte('{')
			if g.matcher != "" {
				buf.WriteString(`"matcher":`)
				writeJSON(&buf, g.matcher)
				buf.WriteByte(',')
			}
			buf.WriteString(`"hooks":[`)
			for k, h := range g.hs {
				if k > 0 {
					buf.WriteByte(',')
				}
				buf.WriteString(`{"type":"command","command":`)
				writeJSON(&buf, h.Command)
				if h.Timeout > 0 {
					fmt.Fprintf(&buf, `,"timeout":%d`, h.Timeout)
				}
				for _, k := range sortedKeys(h.Extra) {
					buf.WriteByte(',')
					writeJSON(&buf, k)
					buf.WriteByte(':')
					writeJSON(&buf, h.Extra[k])
				}
				buf.WriteByte('}')
			}
			buf.WriteString("]}")
		}
		buf.WriteByte(']')
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

func writeJSON(buf *bytes.Buffer, v any) {
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	buf.Truncate(buf.Len() - 1) // Encode appends a newline
}

func (claudeAdapter) Apply(b []byte, w Wiring, _ Wiring) ([]byte, error) {
	var src bytes.Buffer
	src.WriteString(`{"hooks":`)
	src.Write(hooksJSON(w.Entries))
	if v, ok := w.Values[claudeModsKey]; ok && v != "" {
		src.WriteString(`,"env":{"CLAUDE_CODE_PLUGIN_DIRS":`)
		writeJSON(&src, v)
		src.WriteByte('}')
	}
	src.WriteByte('}')
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, src.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	return rules.ToTarget(pretty.Bytes(), b, rules.Spec{Format: "json", Keep: claudeOwned(w)}, nil)
}

func (claudeAdapter) Rows(w Wiring) []string {
	var rows []string
	for _, e := range w.Entries {
		for _, t := range matcherTokens(e.Matcher) {
			rows = append(rows, fmt.Sprintf("%s\t%s\t%s\t%s", e.Event, t, e.Command, handlerTail(e)))
		}
	}
	for _, k := range sortedKeys(w.Values) {
		if w.Values[k] != "" {
			rows = append(rows, fmt.Sprintf("value\t%s\t%s", k, w.Values[k]))
		}
	}
	sort.Strings(rows)
	return rows
}

func handlerTail(e Entry) string {
	s := ""
	if e.Timeout > 0 {
		s = fmt.Sprintf("timeout=%d", e.Timeout)
	}
	for _, k := range sortedKeys(e.Extra) {
		var buf bytes.Buffer
		writeJSON(&buf, normNum(e.Extra[k]))
		s += " " + k + "=" + buf.String()
	}
	return strings.TrimSpace(s)
}

// normNum makes TOML integers and JSON numbers compare equal.
func normNum(v any) any {
	switch x := v.(type) {
	case int64:
		return float64(x)
	case int:
		return float64(x)
	}
	return v
}

// matcherTokens splits a matcher into the alternatives it matches: top-level
// `|` outside parentheses, with ^ and $ anchors dropped. An empty matcher is
// "*" (every tool or source).
func matcherTokens(m string) []string {
	if m == "" || m == "*" {
		return []string{"*"}
	}
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(m); i++ {
		switch m[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
		case '|':
			if depth == 0 {
				out = append(out, m[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, m[start:])
	for i, t := range out {
		out[i] = strings.TrimSuffix(strings.TrimPrefix(t, "^"), "$")
	}
	return out
}

func (claudeAdapter) Unowned(b []byte) (any, error) {
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	delete(doc, "hooks")
	if env, ok := doc["env"].(map[string]any); ok {
		delete(env, "CLAUDE_CODE_PLUGIN_DIRS")
		if len(env) == 0 {
			delete(doc, "env")
		}
	}
	return doc, nil
}
