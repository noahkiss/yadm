package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// tripwire is the SessionStart check. It reads only local files: the state
// gen left and each harness's live file. It never runs yadm, never reads
// stdin, and always exits 0, so it cannot break or slow a session start.
func tripwire(args []string, stdout, stderr io.Writer) (code int) {
	format := "text"
	defer func() {
		if r := recover(); r != nil {
			emitTrip(stdout, format, []string{fmt.Sprintf("yadm-agents: tripwire failed (%v); required guards are unchecked", r)})
			code = 0
		}
	}()
	fs := flag.NewFlagSet("tripwire", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var harness, home, state string
	fs.StringVar(&harness, "harness", "", "check only this harness")
	fs.StringVar(&format, "format", "text", "text, or hook (SessionStart hook JSON)")
	fs.StringVar(&home, "home", "", "home directory (default $YADM_HOME, then $HOME)")
	fs.StringVar(&state, "state", "", "state file (default ~/.local/state/yadm-agents/state.json)")
	if err := fs.Parse(args); err != nil {
		return 0
	}
	if home == "" {
		home = os.Getenv("YADM_HOME")
	}
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	if state == "" {
		state = statePath(home)
	}
	emitTrip(stdout, format, Tripwire(home, state, harness))
	return 0
}

// emitTrip prints the lines as text or as SessionStart hook JSON, each
// line cleaned first: the harness decodes the JSON and shows the text on
// a terminal, so JSON escaping alone would not stop a control character.
func emitTrip(w io.Writer, format string, lines []string) {
	if len(lines) == 0 {
		return
	}
	clean := make([]string, len(lines))
	for i, l := range lines {
		clean[i] = printable(l)
	}
	text := strings.Join(clean, "\n")
	if format == "hook" {
		b, _ := json.Marshal(map[string]any{
			"systemMessage":      text,
			"hookSpecificOutput": map[string]string{"hookEventName": "SessionStart", "additionalContext": text},
		})
		fmt.Fprintln(w, string(b))
		return
	}
	fmt.Fprintln(w, text)
}

// printable escapes control and format characters (a newline, an escape
// sequence, a bidi override), so text from a file cannot break a line or
// drive the terminal.
func printable(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`\ufffd`)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

const tripPrefix = "yadm-agents: REQUIRED GUARD MISSING"

// Tripwire compares the required units gen last planned with what each
// harness's live file wires, and returns one line per missing guard.
// harness "" checks every harness gen recorded.
func Tripwire(home, state, harness string) []string {
	st, err := readState(state)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return []string{fmt.Sprintf("yadm-agents: no gen state at %s; required guards are unchecked. Run `yadm-agents gen`.", state)}
	case err != nil:
		return []string{fmt.Sprintf("yadm-agents: unreadable gen state (%v); required guards are unchecked. Run `yadm-agents gen`.", err)}
	}
	var out []string
	if st.Failed != "" {
		out = append(out, fmt.Sprintf("yadm-agents: the last gen failed (%s); required guards may not match the units file. Run `yadm-agents gen`.", st.Failed))
	}
	hs := sortedKeys(st.Harness)
	if harness != "" {
		if _, ok := st.Harness[harness]; !ok {
			return append(out, fmt.Sprintf("yadm-agents: gen has no record for %s; its required guards are unchecked. Run `yadm-agents gen`.", harness))
		}
		hs = []string{harness}
	}
	for _, h := range hs {
		out = append(out, tripOne(home, h, st.Harness[h])...)
	}
	return out
}

func tripOne(home, h string, rec HarnessState) []string {
	var out []string
	if rec.Refused != "" {
		out = append(out, fmt.Sprintf("yadm-agents: the last gen refused %s (%s); its required guards may be unwired. Run `yadm-agents gen`.", h, rec.Refused))
	}
	if len(rec.Required) == 0 || rec.Target == "" {
		return out
	}
	shown := "~/" + rec.Target
	each := func(format string, args ...any) {
		for _, x := range rec.Required {
			out = append(out, fmt.Sprintf("%s on %s: %s %s", tripPrefix, h, x.Unit, fmt.Sprintf(format, args...)))
		}
	}
	a, ok := adapterFor(h)
	if !ok {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(home, filepath.FromSlash(rec.Target)))
	if err != nil {
		each("is not loaded: cannot read %s (%v)", shown, errors.Unwrap(err))
		return out
	}
	live, err := a.Load(b)
	if err != nil {
		each("is not loaded: %s does not parse (%v)", shown, err)
		return out
	}
	covered := map[string]bool{}
	for _, e := range live.Entries {
		for _, k := range coverKeys(e) {
			covered[k] = true
		}
	}
	for _, x := range rec.Required {
		if x.Script != "" {
			if _, err := os.Stat(filepath.Join(home, filepath.FromSlash(x.Script))); err != nil {
				out = append(out, fmt.Sprintf("%s on %s: %s: its script ~/%s is missing.", tripPrefix, h, x.Unit, x.Script))
				continue
			}
		}
		var gaps []string
		for _, hd := range x.Handlers {
			e := Entry{Event: hd.Event, Matcher: hd.Matcher, Command: hd.Command}
			if coveredBy(covered, e) {
				continue
			}
			for _, k := range coverKeys(e) {
				if !covered[k] {
					ev, rest, _ := strings.Cut(k, "\t")
					tool, _, _ := strings.Cut(rest, "\t")
					gaps = append(gaps, ev+" "+tool)
				}
			}
		}
		if len(gaps) > 0 {
			out = append(out, fmt.Sprintf("%s on %s: %s is not wired for %s in %s. Run `yadm-agents gen`.", tripPrefix, h, x.Unit, strings.Join(uniq(sorted(gaps)), ", "), shown))
		}
	}
	return out
}

func sorted(xs []string) []string {
	sort.Strings(xs)
	return xs
}
