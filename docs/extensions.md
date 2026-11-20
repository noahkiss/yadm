# Extensions

An extension is a separate `yadm-<name>` executable. `yadm <name>` runs it, and the manifest can run it as a task, check or collector. This page lists what an extension may rely on. `docs/design.md` holds the full behaviour; the section numbers below point there.

## Rules for every extension

- The core is harness-agnostic. No package under `internal/` names a coding-agent harness; a test enforces it. Harness specifics live in the extension, and harness hook wiring is documented in `docs/hooks.md`.
- A first-party extension lives in `cmd/yadm-<name>`. It may import only `internal/cond`, `internal/rules`, `internal/extexec`, `internal/model` and `internal/render`. A test enforces this with `go list`. Everything else goes through the commands below.
- An extension never reads enclave plaintext from the source clone. It reads targets in `$HOME` like any program on the machine, and asks yadm for everything else.

## Exec contract (section 12.4)

- Request on stdin: `schema = 1`, with `kind` (`subcommand`, `task`, `check`, `collector`, `nudge`, `notify`, `busy`), `name`, `machine`, `home`, `source`, `commit`, `changed`, `removed`, `trigger` and `args`.
- The same context is in the environment: `YADM_KIND`, `YADM_NAME`, `YADM_MACHINE`, `YADM_MACHINE_NAME`, `YADM_TYPES`, `YADM_OS`, `YADM_ARCH`, `YADM_HOME`, `YADM_SOURCE`, `YADM_COMMIT`, `YADM_JSON`, `YADM_FACT_<KEY>`.
- Response on stdout, on exit 0: one JSON object with `schema = 1`, `ok`, `items`, `data`, `message`, `next`; or one item per line.
- A task's `trigger` is `paths`, `remove`, `first-apply`, `fact` or `render`.

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
- `yadm eval '<cond>' --json [--as <machine>]`: `result`, `expanded`, `names`. For another machine, `unavailable` lists the collectors it did not publish `plain`; their terms read false.
- `yadm why <path> --json`, `yadm managed <path> --json`, `yadm machine --json`, `yadm where --json`.
- `yadm status --json`: `generated` lists the files task outputs cover.

## What an extension can declare in the manifest

- **Named conditions** (section 5.1): a `[conditions]` table, and `conditions.include` to load the `[conditions]` table of the extension's own config file. Use dotted names in the extension's namespace, such as `tool.gui`. Conditions say `cond:tool.gui`.
- **Task triggers** (section 12.1): `on_fact = ["<collector>", "fact:<key>"]` and `on_render = true` rerun a generator when its inputs change.
- **Task outputs** (sections 8.2 and 12.1): `outputs = ["<target glob>"]` marks generated files. They are never captured, committed or gated.
- **Predicate drops** (section 6): `drop = ["hooks.*[?command~=yadm-tool run]"]` keeps the array elements a generator writes into an app's config local to each machine, while the user's own elements stay in the repository.
- **Review notes** (section 9.6): `yadm review note <commit> --why "<text>"` records why a commit was made. A note on an enclave commit is sealed to that enclave.
