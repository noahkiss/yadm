// Command yadm-agents wires every coding-agent harness on a machine from one
// owner-edited units file: one matrix of unit × harness × machine.
//
// # Units file
//
// Default path: $YADM_AGENTS_UNITS, else $XDG_CONFIG_HOME/yadm-agents/units.toml
// (~/.config/yadm-agents/units.toml). yadm manages it as the target
// .config/yadm-agents/units.toml; when XDG_CONFIG_HOME moves the default away
// from it, a check or task that yadm hands that target fails and names both
// paths instead of reading the wrong copy. TOML, schema 1:
//
//	schema = 1
//
//	[harness.<name>]            # optional adapter settings
//	config = "~/<file>"         # the file the adapter owns keys in
//
//	[[unit]]                    # order matters, see below
//	name     = "guard-a"        # letters, digits, _ and -; no dots
//	kind     = "guard"          # open string: guard, hook, mod, plugin, extension, ...
//	required = true             # gen and verify refuse to lose it
//	first    = true             # leads every route list it is on
//	effect   = "deny"           # deny | ask | context | rewrite | none
//	script   = "~/hooks/a.sh"   # the check; gen quotes it per harness
//	args     = ["{harness}"]    # appended to script
//	run      = "..."            # verbatim command instead of script + args
//	on       = ["PreToolUse"]   # events, Claude Code hook event names
//	actions  = ["shell"]        # docs/hooks.md vocabulary, plus mcp_call:<server> (letters, digits, _ and -)
//	match    = "startup"        # raw matcher, or { <event> = "<matcher>" }
//	timeout  = 10               # seconds, or { "*" = 5, <event> = 2 }
//	extra    = { k = "v" }      # handler fields passed through verbatim
//	dir      = "~/mods/x"       # a mod's directory, or a dir file unit
//	file     = "~/plugins/x.ts" # a file unit
//	via      = "<unit>"         # another unit (a plugin file) wires this one here
//	note     = "why"            # why a harness differs; verify wants one for an unmapped action
//
//	[unit.harness.<name>]       # overrides any field above for one harness
//
//	[conditions]                # one cell per unit × harness
//	"guard-a.claude" = "true"
//	"guard-a.codex"  = "type:home & cond:has-tool"
//
// A cell is a yadm condition. `{harness}` and `{event}` in run and args are
// replaced. A unit with no cell for a harness is off there. A `[conditions]`
// name that is not `<unit>.<harness>` is a helper other cells may use as
// `cond:<name>`; yadm-agents inlines the file's own names and leaves the
// rest to yadm, so the same table can be loaded into the manifest with
// conditions.include, where file units say `when = "cond:<unit>.<harness>"`.
//
// # Adapters
//
// Each harness has an adapter (adapter.go). It declares its events, tool
// events, effects and the unit kinds it wires; maps actions to its matchers;
// renders, loads and applies its owned keys; and flattens wiring into rows
// that compare equal when the harness behaves the same. A harness or kind
// with no adapter is reported by verify and shown in the matrix, never
// rejected by the parser.
//
//	claude    .claude/settings.json: `.hooks` and env.CLAUDE_CODE_PLUGIN_DIRS
//	          (mods, in unit order). Claude runs matching hooks in parallel,
//	          so rows ignore grouping and order.
//	codex     .codex/config.toml: each hooks.<Event> table by name, never
//	          hooks.state. Codex keys hook trust by event and position, so
//	          gen keeps every live handler at its position and appends new ones.
//	opencode  a route file (config required): event, Claude tool name and the
//	pi        guard scripts a shared runner script runs, in unit order with
//	          units marked first ahead. Only route lists have an order that
//	          first sets; Claude ignores order and Codex keeps live positions.
//
// # Commands
//
// gen writes this machine's wiring. For each harness it evaluates the cells
// (through `yadm eval`), renders, compares rows with the live file and
// writes only on change, atomically, with every other key byte for byte. It
// then re-reads the result and fails closed unless the owned wiring is the
// plan and everything else is unchanged. It refuses a harness, keeping the
// live file, when: a cell does not evaluate; a unit names an event or effect
// its harness lacks; a required unit renders nothing or its script is
// missing; the result would hold no handler where the file has some; a live
// handler matches no unit (unless --prune); or a required unit's live
// handler would go or lose an event or tool it covers (unless --allow-drop;
// a required unit whose cell was removed still counts). It never creates an
// app's config file, never writes outside home, writes a symlinked file
// through its link, and never overwrites a route file it did not write. --dry-run writes nothing; --diff prints the rows; --as <machine>
// renders another machine (implies --dry-run), treating a file the manifest
// does not give that machine as missing.
//
// verify is the commit check: the file parses; every cell names a real
// unit; every wired cell asks only for events and effects its harness has
// and renders; a via names a real unit; required units name a script that exists (or is
// staged); every condition evaluates. Unknown harnesses, unknown kinds,
// unmapped actions without a note, and a unit marked first that another
// first unit keeps from leading a route list are warnings.
//
// matrix prints unit × harness × machine as a table, JSON, or a parity
// report (one line per script: harness[tokens]). For file units it compares
// each cell with what `yadm manifest --fleet --json` delivers.
//
// # Invocation
//
// As a plugin (`[plugins.<name>]`, then `yadm plugin allow <name>`), as a
// plain command, or as `yadm-agents` on PATH. Under the exec contract
// (YADM_KIND task, check or subcommand) it reads the request on stdin and
// prints one response object; as a check it reads the staged units file
// and exits 0 with ok in the response. It imports only the packages
// docs/extensions.md allows, and asks yadm for every condition.
package main
