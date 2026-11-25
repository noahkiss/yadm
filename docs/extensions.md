# Extensions

An extension is a separate `yadm-<name>` executable. `yadm <name>` runs it, and the manifest can run it as a task, check or collector. A plugin is an executable that a `[plugins.<name>]` manifest table declares; `yadm <name>` runs it with stdio passed through (see Plugins below). This page lists what an extension may rely on. `docs/design.md` holds the full behaviour; the section numbers below point there.

## Rules for every extension

- The core is harness-agnostic. No package under `internal/` names a coding-agent harness; a test enforces it. Harness specifics live in the extension, and harness hook wiring is documented in `docs/hooks.md`.
- A first-party extension lives in `cmd/yadm-<name>`. It may import only `internal/cond`, `internal/rules`, `internal/extexec`, `internal/model` and `internal/render`. A test enforces this with `go list`. Everything else goes through the commands below.
- An extension never reads enclave plaintext from the source clone. It reads targets in `$HOME` like any program on the machine, and asks yadm for everything else.

## First-party extensions

- `yadm-agents` generates every coding-agent harness's hook wiring on a machine from one units file, and shows the unit × harness × machine matrix. `cmd/yadm-agents/doc.go` states its contract.

## Exec contract (section 12.4)

- Request on stdin: `schema = 1`, with `kind` (`subcommand`, `task`, `check`, `collector`, `nudge`, `notify`, `busy`, `news`), `name`, `session` (news), `machine`, `home`, `source`, `commit`, `changed`, `removed`, `trigger` and `args`; a check also gets `staged` and `entries`.
- The same context is in the environment: `YADM_KIND`, `YADM_NAME`, `YADM_MACHINE`, `YADM_MACHINE_NAME`, `YADM_TYPES`, `YADM_OS`, `YADM_ARCH`, `YADM_HOME`, `YADM_SOURCE`, `YADM_COMMIT`, `YADM_JSON`, `YADM_PARENT_PID`, `YADM_SESSION` (news), `YADM_FACT_<KEY>`.
- Response on stdout, on exit 0: one JSON object with `schema = 1`, `ok`, `items`, `data`, `message`, `next`; or one item per line.
- A task's `trigger` is `paths`, `remove`, `first-apply`, `fact` or `render`.

## Plugins (section 12.6)

```toml
[plugins.todo]
command = ["bin/todo"]                  # relative to $HOME, then fixed arguments
when = "type:personal"
summary = "Per-machine to-dos"
news = ["bin/todo", "list", "--brief"]  # optional
```

- `yadm todo <args>` runs `$HOME/bin/todo <args>` in the caller's directory. Stdin, stdout, stderr, the terminal, every argument (`--json` included) and the exit code pass through unchanged. No request goes to stdin and yadm prints no envelope.
- The environment is the exec contract's, with `YADM_KIND=plugin`, `YADM_JSON=1` only under `--json`, `YADM_ENCLAVES`, `YADM_ON_DEMAND` and `YADM_PLUGIN_STATE` (a private directory for the plugin's own state).
- A plugin runs only after `yadm plugin allow <name>` on each machine. The allow covers the definition and the bytes of each executable it names, so every edit of the script needs a new allow; until then `yadm <name>` exits 6. The hash does not cover files the script reads or sources.
- `news` runs at session start under the exec contract (`kind = "news"`), with a 3 s timeout and at most 5 lines, kept in order. Print one line per item, or one JSON response whose `message` and `items` become the lines.
- A plugin may call `yadm` itself: `yadm commit --expect-enclave <e> <path>...` commits a file only when it seals for that enclave, and `yadm lease take` keeps hooks off a file while the plugin edits it.

## JSON contracts

| Contract | Schema | Where |
|---|---|---|
| Command envelope `{schema, command, ok, data, next, error}` and exit codes | 1 | section 14.1 |
| Exec request and response | 1 | section 12.4 |
| `yadm manifest --json` data | 1 (`data.schema`) | section 4 |
| `yadm eval --json` data | 1 (`data.schema`) | section 5.1 |
| Status record (`refs/yadm/status/<machine>`) | 1 | section 11 |
| Hold objects | within envelope schema 1 | section 14.1 |
| Review notes (`refs/yadm/notes/review`) | 1 | section 9.6 |

Fields are only added within a schema version. An extension ignores fields it does not know.

## Queries

- `yadm manifest --json [--as <machine> | --fleet]`: resolved entries per machine with target, source, `when` and `when_expanded`, mode, enclave, scope, merge and a rules summary, plus roots, applying tasks and every task's `outputs`. Read-only; it prints no plaintext.
- `yadm eval '<cond>' --json [--as <machine>]`: `result`, `expanded`, `names`. For another machine, `unavailable` lists the collectors it published neither `plain` nor `sealed:<enclave>` for an enclave this machine is a member of; their terms read false.
- `yadm why <path> --json`, `yadm managed <path> --json`, `yadm machine --json`, `yadm where --json`.
- `yadm status --json`: `generated` lists the files task outputs cover.

## What an extension can declare in the manifest

- **Named conditions** (section 5.1): a `[conditions]` table, and `conditions.include` to load the `[conditions]` table of the extension's own config file. Use dotted names in the extension's namespace, such as `tool.gui`. Conditions say `cond:tool.gui`.
- **Task triggers** (section 12.1): `on_fact = ["<collector>", "fact:<key>"]` and `on_render = true` rerun a generator when its inputs change.
- **Task outputs** (sections 8.2 and 12.1): `outputs = ["<target glob>"]` marks generated files. They are never captured, committed or gated.
- **Predicate drops** (section 6): `drop = ["hooks.*[?command~=yadm-tool run]"]` keeps the array elements a generator writes into an app's config local to each machine, while the user's own elements stay in the repository.
- **Review notes** (section 9.6): `yadm review note <commit> --why "<text>"` records why a commit was made. A note on an enclave commit is sealed to that enclave.
