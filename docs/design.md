# yadm design

This document specifies how `yadm` works. The Go package docs (`go doc ./internal/...`) hold the exact types; this document holds the behaviour and the reasons.

## 1. Model

- The user's dotfiles live in one git repository, shared by every machine.
- Each machine keeps a **source clone** of that repository outside `$HOME`. The tool reads the source, renders it for this machine and writes plain files into `$HOME` (**apply**). It reads edits back from `$HOME` into the source (**capture**).
- Nothing in `$HOME` is a symlink or a git worktree. A target is rewritten only when its bytes change.
- A **machine type** is user data in the fleet file. The tool hard-codes no type name.
- Any type may be an **enclave**. Files of an enclave are sealed in the repository. Only member machines can open them.
- The tool does all sealing itself, in memory. It installs no git filter, textconv or merge driver.

## 2. On-disk layout

### 2.1 Per machine

| Path | Content |
|---|---|
| `$XDG_DATA_HOME/yadm/source` | The source clone. Default `~/.local/share/yadm/source`. |
| `$XDG_STATE_HOME/yadm/` | State: `state.json`, private indexes, `lock`, `backup/`, `pins/<enclave>`, `allowed.json`, `leases/`, identity keys. Default `~/.local/state/yadm/`. |
| `$XDG_STATE_HOME/yadm/identity.age.key` | This machine's age X25519 identity, mode 0600. |
| `$XDG_STATE_HOME/yadm/identity.sign.key` | This machine's Ed25519 signing key, mode 0600. |
| `$XDG_CONFIG_HOME/yadm/machine.toml` | Local identity: machine id, remote, notify and busy commands. Untracked. |

`yadm where --json` prints the three directories.

`machine.toml`:

```toml
machine = "m-a1b2c3"
remote  = "git@git.example.invalid:user/dotfiles.git"
notify  = ["yadm-notify"]          # optional, extexec contract
busy    = ["yadm-busy-probe"]      # optional, extexec contract
```

### 2.2 Source tree

```
fleet.toml                       registry: types, machines, collectors
manifest.toml                    which file goes where, rules, tasks, checks, units
files/<target>                   plaintext sources (default location)
sealed/<enclave>/<target>        whole-file sealed sources
keys/<enclave>/<seq>.toml        the enclave's signed key log
```

An entry may point anywhere under `files/` or `sealed/<enclave>/` with `source =`, which is how variants of one target coexist.

## 3. Fleet file

`fleet.toml` declares types, machines and collectors.

```toml
schema = 1

[types.personal]
enclave = true          # files of this type are sealed for members

[types.work]            # a plain type

[types.client]
enclave = true

[machines.m-a1b2c3]     # key: random machine id, never a hostname
name = "host-a"
nicknames = ["laptop-a"]
types = ["personal"]    # one or more
os = "darwin"
arch = "arm64"

[machines.m-a1b2c3.facts]   # declared facts, free form
editor = "editor-one"

[collectors.packages]       # observed facts, see section 12
command = ["pkg-tool", "list", "--names"]
timeout = "30s"
when = "os:darwin"
publish = "plain"           # local | plain | sealed:<enclave>
```

Rules:

- Names, nicknames and ids are unique across the fleet.
- A hostname is not an identity. Store it as a fact if a template needs it.
- The fleet file never grants enclave membership. The key log does (section 7). `yadm check` reports where `types` and key-log membership disagree.
- Fleet entries are plaintext to every machine. Facts that must stay private belong in a sealed file of an enclave, not here.

## 4. Manifest

`manifest.toml` maps targets (paths relative to `$HOME`) to sources and rules.

```toml
schema = 1

[defaults]
quiet = "2h"                      # auto-commit quiet period

[[file]]
target = ".config/shell/aliases.sh"           # source: files/.config/shell/aliases.sh

[[file]]
target = ".gitconfig"
source = "files/.gitconfig.tmpl"
template = true

[[file]]
target = ".config/shell/os.sh"
source = "files/.config/shell/os-darwin.sh"
when = "os:darwin"

[[file]]
target = ".config/shell/os.sh"
source = "files/.config/shell/os-linux.sh"
when = "os:linux"

[[file]]
target = ".config/notes/private.md"           # source: sealed/personal/.config/notes/private.md
enclave = "personal"
when = "type:personal"

[[file]]
target = ".config/editor/settings.json"
format = "jsonc"
keep = ["editor.*", "terminal.font"]
drop = ["window.state", "recent"]
seal = { "sync.token" = "personal" }
quiet = "0s"

[[file]]
target = ".ssh/config"
regions = true
mode = 0o600

[[unit]]
target = "Library/LaunchAgents/example.helper.plist"
kind = "launchd"

[[root]]
path = ".config/shell"            # new files here are reported

[tasks.package-bundle]
on = [".config/packages/list"]
command = ["pkg-tool", "bundle", "--file", ".config/packages/list"]
timeout = "10m"

[checks.secret-scan]
paths = ["**"]
command = ["secret-check"]
```

Resolution for one machine:

- An entry applies when its `when` condition is true. An empty `when` applies everywhere.
- Two applying entries for one target are a **collision**. Every command that resolves the manifest fails on it, and `yadm check` lists it.
- Without `source`, the source is `files/<target>`, or `sealed/<enclave>/<target>` when `enclave` is set.
- A target glob (`.config/tool/**`) expands against the source tree.
- `mode` defaults to 0644, 0755 for an executable source, and 0600 for any file with `enclave` set.
- `review = true` excludes an entry from auto-commit. Its changes wait for `yadm commit`.

`yadm why <path> --json` returns the winning entry, every entry that named the path but did not apply (with the reason), whether the path is protected and which owned root contains it.

## 5. Conditions and templates

### 5.1 Conditions

One condition language serves `when`, tasks, checks, collectors and template `{% if %}`.

```
type:work   os:darwin   arch:arm64   machine:host-a
fact:editor             fact:editor=editor-one
observed:packages=tool-one
!   &   |   ( )   true   false
```

- `machine:` matches a name or nickname.
- Parsing checks every type, fact key and collector name against the fleet. A typo fails at load time.
- A fact key the fleet knows but this machine lacks evaluates `fact:k` and `fact:k=v` to false.

### 5.2 Templates

The engine is deliberately tiny and strict.

```
{{ home }}  {{ user }}
{{ machine.id }}  {{ machine.name }}  {{ machine.os }}  {{ machine.arch }}
{{ machine.facts.KEY }}      declared fact; missing is an error
{{ observed.COLLECTOR }}     observed items joined by newlines; missing is an error
{% if COND %} … {% elif COND %} … {% else %} … {% endif %}
{# comment #}
```

- A directive alone on a line consumes that line's newline.
- Anything else inside `{{ }}` or `{% %}` fails the render with file, line and column. There are no filters, loops or includes.
- A render reads only this machine's own Context: the source commit, its fleet entry, `$HOME`, the user, and its own observed facts from local state. It never reads another machine's status ref, so renders are reproducible and the capture round-trip check is sound.

## 6. Intra-file rules

The keep, drop and seal engines are core. The key lists for each app are user content in the manifest.

| Rule | Formats | Source holds | Target on a member | Target on a non-member |
|---|---|---|---|---|
| `keep` | JSON, JSONC, TOML | Only the listed keys | Repo keys merged into the live file; app keys untouched | Same |
| `drop` | JSON, JSONC, TOML | Never the listed keys | Live values untouched | Same |
| `seal` | JSON, JSONC, TOML | A value token `yadm:1:<enclave>:<epoch>:<base64url>` | Plaintext value | Key absent |
| `regions` | Any text with line comments | One line `# yadm:sealed 1 <epoch> <base64>` between markers | Plaintext body between markers | Markers with nothing between |

Region markers in a target, after any comment prefix:

```
# yadm:seal personal hosts
Host private-box
  HostName 192.0.2.10
# yadm:end
```

Behaviour:

- Key paths name nested keys separated by dots, with `*` for any one segment: `mcp.servers.*.env.TOKEN`. A literal dot or star inside a key is escaped with a backslash: the JSON key `"files.exclude"` is the path `files\.exclude`. Arrays are indexed by number. A path that names an object or table covers everything below it.
- Edits are byte-level. A no-op round trip returns identical bytes. A change touches only the bytes of the values it changes.
- JSON edits use `sjson`. The TOML span editor is this project's code, on go-toml's `unstable` parser. Every edit re-parses its output and fails closed.
- `sjson.Delete` also removes a comment directly above the key. The rules package decides comment ownership before it deletes.
- **Seal guard.** Capture refuses, and holds the file with `seal_guard`, when the target lost a sealed key or its parent, when a sealed plaintext appears outside its seal path, or when region markers are gone or unbalanced. A capture never commits a sealed part as plaintext.
- A non-member's capture puts the stored tokens back from the source, because it cannot see them.
- Deterministic sealing keeps tokens byte-stable when other lines change, so git merges files with sealed parts line by line.
- YAML and plist move as whole files.

## 7. Enclaves: encryption and key lifecycle

### 7.1 Construction

| Item | Choice |
|---|---|
| Cipher | AES-SIV (RFC 5297), 512-bit key, from `tink-go` `daead/subtle`. Deterministic. |
| Epoch key | 32 random bytes per enclave per epoch. |
| Subkeys | HKDF-SHA256(epoch key, info = `yadm v1 <purpose> <enclave>`), 64 bytes. Purposes: `file`, `value`, `region`, `name`. |
| File container | `"yadm-sealed\0"`, version byte 1, enclave name (length-prefixed), epoch (uint32 BE), SIV ciphertext. AD = the header bytes. The path is not in the AD, so a rename keeps the blob. |
| Value token | `yadm:1:<enclave>:<epoch>:<base64url>`. AD = enclave, epoch and key path, so a token moved to another key fails. |
| Region token | `yadm:sealed 1 <epoch> <base64>`. AD = enclave, epoch and region label. |
| Wrapping | Every key-log entry carries all epoch keys so far, age-encrypted (X25519) to each member and to the recovery recipient. |
| Signing | Ed25519 per machine and for the recovery identity. |

Why deterministic: an unchanged file reseals to the same blob, so there is no churn. Two machines that capture the same edit produce the same blob and converge. Sealed values stay byte-stable, so line merges work.

What it leaks: equal plaintexts give equal ciphertexts, so a revert is visible. Sizes, file counts, paths (unless hidden paths are on), commit times and `Machine:` trailers are visible to every machine.

### 7.2 Key log

`keys/<enclave>/<seq>.toml`, one file per entry, append-only:

```toml
enclave  = "personal"
seq      = 2
prev     = "<hex sha-256 of entry 1's signed bytes>"
epoch    = 1
op       = "add"                 # create | add | remove | rotate | recover
subject  = "m-x9y8z7"
members  = [{ machine = "m-a1b2c3", recipient = "age1…", sign_key = "<base64>" },
            { machine = "m-x9y8z7", recipient = "age1…", sign_key = "<base64>" }]
recovery = { machine = "recovery", recipient = "age1…", sign_key = "<base64>" }
wrapped  = "<base64 age file holding epoch keys 1..epoch>"
signer   = "m-a1b2c3"
sig      = "<base64 Ed25519 over the canonical bytes with sig empty>"
```

Verification, on every load:

1. Entry `n+1` has `prev` = hash of entry `n`.
2. Its signer is a member of entry `n`, or the recovery identity of entry `n`. The signature verifies.
3. `remove` and `rotate` increase the epoch by one. `create` is epoch 1. `add` keeps the epoch.
4. The chain contains the machine's local pin (`pins/<enclave>`). A machine never accepts a chain that does not extend its pin.

An entry that fails any check is rejected; the enclave is reported as `refused` and its files are not applied until fixed. A machine that can push but holds no member key therefore cannot substitute a key: it cannot sign.

### 7.3 Lifecycle

| Step | Who | What happens |
|---|---|---|
| Create | Any machine of the type | `yadm enclave create <type>` writes entry 1, signed by the creator, wrapped to the creator and the recovery recipient. The recovery identity is generated offline and stored by the user outside the repository. |
| Join request | New machine | `yadm init` prints its recipient, signing key and machine id. |
| Add | A current member | `yadm enclave add <machine>` appends an `add` entry wrapped to the new member, and prints the entry fingerprint. |
| Pin | New machine | `yadm enclave join <enclave> --expect <fingerprint>` pins that entry. The fingerprint travels out of band. |
| Remove | A current member | `yadm enclave remove <machine> --confirm` appends a `remove` entry with a new epoch, wrapped to the rest, and reseals current sealed files in one commit. The removed machine keeps every key up to the old epoch and every commit it already fetched. The output lists what else the user must do: revoke the machine's repository access and rotate real secrets stored in the enclave. |
| Recover | Recovery identity | `recover` entry signed by the recovery key, used when no member remains. |

Key-log changes, `fleet.toml` and `manifest.toml` are protected: they never auto-commit.

### 7.4 Where plaintext may exist

- In a member's `$HOME` (the targets).
- In memory during render, capture, merge and diff. Three-way merges, diffs and template patching run in-process (`internal/textmerge`); plaintext is never handed to git.
- On stdout for `yadm diff`, `yadm log -p`, `yadm review` and `yadm hold show`.
- In a 0600 temp file in the state directory while a commit-gate check reads it, removed afterwards. Checks see only files this machine can already open.

The state database stores hashes, never rendered bytes. The last render of a template is recomputed from its source blob and the stored render Context when capture needs it.

Plaintext never enters the source tree, the object store, a ref, a note, a commit message, the status ref (except collectors published `plain`) or any non-member path. The tool runs git with `-c diff.cachetextconv=false`, defines no textconv, and `yadm check` fails on any `refs/notes/textconv` ref or `cachetextconv = true` setting.

Every change to sealing or delivery needs a test with `internal/secrecytest` that plants a canary in enclave plaintext and asserts it reaches neither a non-member's `$HOME` nor any repository's object store.

### 7.5 Hidden paths (reserved)

A type with `hide_paths = true` would store files as `sealed/<enclave>/<base32(HMAC(name key, path))>` with the real path inside the sealed header. The interface exists (`crypt.NameScheme`, `crypt.HiddenNames`); the implementation is not built. It is off by default. Even when built, counts, sizes, timing and co-change stay visible.

## 8. Apply, scan, capture and drift

### 8.1 State

`state.json` records, per managed target: source path and blob, scope, the SHA-256 of the bytes last written, size, mtime and mode, the seal set at last apply, the SHA-256 of the last render for templates, and when the current drift was first seen. It also records the applied commit, whether the first apply ran, holds, observed facts, last task results and the render Context of the last apply. It holds no file content and never leaves the machine.

### 8.2 Scan

Every command starts with a scan. It is a stat pass over managed targets and owned roots that hashes a file only when its stat tuple changed. A full hash pass runs at most once a day. Scans are bounded by the managed set and owned roots; they never walk all of `$HOME`.

Drift kinds: `modified`, `deleted`, `new` (in an owned root), `mode`.

### 8.3 Apply

1. Resolve the manifest for this machine; render each target in memory.
2. Skip a target whose bytes already match.
3. Hold a target whose current hash differs from the last written hash (`drifted`). Apply never overwrites it. The usual path captures it first.
4. Write changed targets atomically (temp file and rename), with the entry's mode. Copy the replaced bytes into `backup/` for 30 days.
5. Delete a target that left the plan, only if it is unchanged since written; otherwise hold it.
6. On a non-member, skip sealed files (`sealed` action) and leave sealed values and regions out.
7. Run triggered tasks (section 12): path tasks, remove tasks, unit reloads and, once per machine, first-apply tasks.

### 8.4 Capture

- **Verbatim file:** the target bytes become the source bytes.
- **Sealed file:** the target is sealed under the current epoch. Deterministic sealing makes an unchanged file a no-op.
- **Template:** capture recomputes the last render (source blob plus stored render Context, checked against the stored hash), diffs it against the target, applies the hunks to the template where their context matches verbatim, re-renders and accepts only if the result equals the target byte for byte. Otherwise the target is held (`rendered_edit`) and status reports it. Apply never re-renders over it.
- **Intra-file rules:** package rules (section 6), with the seal guard.
- **Every capture** passes the round-trip check: render(new source) = target. A failure is held as `uncapturable`, never committed.

### 8.5 Retag

`yadm retag <path> <type>[,<type>...] [--enclave <name>]` changes which machines get a target in one commit: the manifest entry's `when` and `enclave`, and the move between `files/` and `sealed/<enclave>/` with the content opened and resealed. Only a member of every enclave involved can retag. Machines that lose the target remove it on their next apply if it is unchanged there, and hold it otherwise. Retag is protected: it is a manual commit only.

## 9. Commits

### 9.1 Private index

Every commit operation builds its own fresh index file in the state directory, seeded from the parent commit and holding only that operation's paths. The source clone's own index and worktree are never used to stage. Parallel agents and the timer never sweep each other's changes.

### 9.2 Commit gate

Before any commit, manual or automatic, the gate runs every `[checks.<name>]` whose `paths` match a staged target, through the exec contract (section 12.4). The request lists the staged targets and the paths of 0600 temp files holding their plaintext. The gate fails closed: a non-zero exit, a timeout, `ok: false` or a check this machine has not allowed holds the matching files with `check_failed`. Other files still commit.

### 9.3 Auto-commit

The timer runs `yadm sync --auto`. A captured path auto-commits when all hold:

- its quiet period has passed since its last change (entry `quiet`, default 2 h; `0s` commits at once);
- no lease names it (`yadm lease take`, used by agent hooks; leases expire);
- the busy probe, if configured, does not name it;
- it is not protected: `manifest.toml`, `fleet.toml`, `keys/**`, manifest `protected` globs, entries with `review = true`, new files outside owned roots, deletions, retags, and more than 50 changed files in one scope;
- the gate passes.

Commits group by scope (`shared` or an enclave name), one commit per scope per run:

```
auto(host-a): 3 files [shared]

.config/shell/aliases.sh
.config/editor/settings.json
.gitconfig

Machine: m-a1b2c3
Yadm-Auto: 1
Yadm-Scope: shared
```

`yadm commit [-m <subject>] [path...]` makes a manual commit. It bypasses the quiet period and leases, never the gate or the seal guard. Protected paths commit only when named.

### 9.4 Review

Each scope has a fast-forward-only ref `refs/yadm/reviewed/<scope>`. `yadm review list [scope] --json` lists commits in `reviewed/<scope>..main` that touch the scope, with plaintext diffs for scopes this machine can open. Agents act with `yadm review ok <scope> <commit>`, `yadm review revert <commit>` (a new commit), a fix-forward commit, or `yadm bisect --as <machine> -- <cmd>`, which renders each candidate commit into a sandbox and never touches `$HOME`.

## 10. Sync

`yadm sync` runs under the lock in the state directory. A command waits at most 30 s for the lock, then exits with code 4. No command waits without a bound; every git and external call has a timeout.

1. Scan and capture.
2. With `--auto`, auto-commit by policy (section 9.3).
3. Run allowed collectors.
4. Fetch `main` and `refs/yadm/*`.
5. If local `main` is not an ancestor of `origin/main`, replay each local commit onto `origin/main` with `git merge-tree --write-tree`, in memory:
   - clean: `commit-tree` with the original message and trailers;
   - conflict on a sealed file this machine can open: open the three stages, merge them in memory (`textmerge.Merge3`), reseal, write the tree; a remaining conflict is held like any other;
   - other conflicts: the clean paths of the commit land; conflicted paths move to the local-only ref `refs/yadm/held/<machine>` and become `conflict` holds with all three stage blobs.
   History stays linear. There is no autostash and no merge commit.
6. Compare-and-swap local `main`. Move the source worktree; if it has local edits, stop with a `source_dirty` hold (the tool never stashes).
7. Apply.
8. Publish this machine's status record (section 11).
9. Push `main` and the status ref atomically. On rejection, go back to step 4, up to 5 retries with backoff. Never force.

A fetched commit that touches `sealed/<enclave>/` or `keys/<enclave>/` from a machine (by `Machine:` trailer) that is not a member of that enclave is applied and reported through the notify hook. The trailer is not authenticated; key-log changes are, by signature.

## 11. Status refs and observed facts

Each machine fast-forwards only its own `refs/yadm/status/<machine-id>`: a chain of commits whose tree holds one `status.json`. It publishes after a sync that changed something and at least hourly.

```json
{
  "schema": 1,
  "machine": "m-a1b2c3",
  "version": "1.0.0",
  "applied": "<commit>",
  "last_sync": "2030-01-01T12:00:00Z",
  "pending": 2,
  "held": 1,
  "conflicts": 0,
  "oldest_held": "2030-01-01T09:00:00Z",
  "epochs": { "personal": 1 },
  "observed": { "packages": { "collector": "packages", "items": ["tool-one", "tool-two"], "collected_at": "…" } },
  "sealed": { "client": "<sealed observed facts>" },
  "tasks": [ { "task": "package-bundle", "trigger": "paths", "commit": "…", "exit_code": 0, "duration_ns": 1200000000 } ]
}
```

`yadm fleet list --json` reads every status ref and flags machines whose last sync is older than a day. `yadm fleet diff <collector> --json` compares a published collector across machines: the union of items, what each machine lacks, and machines with no value.

Observed facts:

- A collector is a name, a command, a timeout and a `when` condition in `fleet.toml`.
- It runs on sync through the exec contract. Line output is normalized: trimmed, empty lines dropped, sorted, de-duplicated. A JSON response may carry `items` or `data`.
- `publish = "local"` (default) keeps the result in local state. `plain` also puts it in the status ref, readable by every machine. `sealed:<enclave>` puts it there sealed for that enclave.
- Templates and conditions read only this machine's own observed facts, from local state.
- A failed collector records its error and never fails the sync.

## 12. Tasks, checks, collectors and extensions

### 12.1 On-change tasks

```toml
[tasks.package-bundle]
on         = [".config/packages/list"]   # a matching target was written
on_remove  = []                          # a matching target was removed
first_apply = false                      # run on this machine's first apply
when       = "os:darwin"
command    = ["pkg-tool", "bundle", "--file", ".config/packages/list"]
timeout    = "10m"
```

- Triggers: `on` (target written), `on_remove` (target removed), `first_apply` (the first apply after `init` or `adopt`).
- A task runs once per apply, after all writes, with the matched targets in its request.
- A failed task is recorded in state and the status ref, reported through notify, and never stops other tasks or the sync.
- **Units** are a built-in task: apply reloads a launchd agent (`launchctl bootout` and `bootstrap`) or a systemd user unit (`daemon-reload`, then restart) only when its bytes changed.

### 12.2 No package manager in core

The core knows no package manager and does no machine provisioning. Bootstrap is a task with `first_apply = true`. Package-manager integration, if ever needed, ships as a separate `yadm-<name>` executable that a task or collector calls.

### 12.3 Trust

Tasks, checks and collectors run commands, and any machine that can push can change their definitions. A machine runs a definition only after it is allowed locally: `yadm task allow [name...]`, or `--allow-tasks` on `init` and `adopt`. `allowed.json` stores a SHA-256 of each allowed definition. A changed definition is not run; it becomes a `task_untrusted` hold until allowed again. Definitions live in protected files and never auto-commit.

### 12.4 Exec contract

One contract covers external subcommands, collectors, tasks, checks, the notify hook and the busy probe. There is no in-process plugin API.

- The tool runs argv directly (no shell) in `$HOME`, with a timeout.
- Stdin carries one JSON request:

  ```json
  { "schema": 1, "kind": "task", "name": "package-bundle",
    "machine": { "id": "m-a1b2c3", "name": "host-a", "types": ["personal"], "os": "darwin", "arch": "arm64", "facts": { "editor": "editor-one" } },
    "home": "/home/user", "source": "/home/user/.local/share/yadm/source",
    "commit": "<commit>", "changed": [".config/packages/list"], "trigger": "paths", "json": true }
  ```

- The environment carries the same context for plain scripts: `YADM_KIND`, `YADM_NAME`, `YADM_MACHINE`, `YADM_MACHINE_NAME`, `YADM_TYPES` (comma-separated), `YADM_OS`, `YADM_ARCH`, `YADM_HOME`, `YADM_SOURCE`, `YADM_COMMIT`, `YADM_JSON=1`, and `YADM_FACT_<KEY>` per declared fact.
- On exit 0, stdout is one JSON response when its first non-space byte is `{`:

  ```json
  { "schema": 1, "ok": true, "items": ["…"], "data": {}, "message": "…", "next": ["…"] }
  ```

  Otherwise each non-empty stdout line is an item.
- A non-zero exit, a timeout or invalid JSON is a failure. Stderr is kept (bounded) for the record and never parsed.

External subcommands: `yadm foo args…` runs `yadm-foo` from `PATH` when `foo` is not built in, with `kind = "subcommand"` and `args`. Under `--json`, its response is wrapped in the normal envelope.

## 13. Schedule

`yadm init` and `yadm adopt` install the sync schedule unless given `--no-schedule`: a launchd user agent on macOS, a systemd user timer on Linux. It runs `yadm sync --auto` every 5 minutes and once at login or wake. A run missed during sleep is not queued; the next run catches up once and tolerates a network that returns late (fetch failures retry on the next tick). `yadm schedule install|uninstall|status` manage it directly.

## 14. Commands

### 14.1 Output contract

- Every command accepts `--json`. With it, stdout carries exactly one envelope and nothing else.
- No command prompts unless given `--interactive`. Destructive steps need an explicit flag (`--confirm`, `--take`).

```json
{
  "schema": 1,
  "command": "status",
  "ok": true,
  "data": { },
  "next": ["yadm hold list"],
  "error": null
}
```

On failure, `ok` is false and `error` is `{ "code": "…", "message": "…", "details": … }`.

| Exit | Code | Meaning |
|---|---|---|
| 0 | | Success, nothing needs attention |
| 1 | `error` | The command failed |
| 2 | `usage` | Bad flags or arguments, or an unknown command with no `yadm-<name>` |
| 3 | `attention` | The command succeeded, but holds or conflicts exist; `data` lists them |
| 4 | `locked` | Another yadm process holds the lock; retry later |
| 5 | `not_implemented` | |
| 6 | `refused` | Refused for secrecy or trust: not a member, a key log that fails verification, an untrusted definition |

Hold objects have a stable shape for external resolvers. Fields are only added within a schema version:

```json
{ "id": "<stable hash>", "target": ".gitconfig", "scope": "shared", "reason": "conflict",
  "since": "…", "detail": "…", "base": "<blob>", "ours": "<blob>", "theirs": "<blob>",
  "next": ["yadm hold show <id>", "yadm hold resolve <id> --take source"] }
```

Reasons: `drifted`, `uncapturable`, `conflict`, `protected`, `secret_scan`, `seal_guard`, `source_dirty`, `task_untrusted`, `check_failed`, `rendered_edit`.

### 14.2 Command list

| Command | Does | `data` |
|---|---|---|
| `version` | Version and build | `{version, go, os, arch}` |
| `where` | Directories | `{source, state, config}` |
| `machine` | This machine | the fleet `Machine` plus `observed` and `enclaves` (opened, refused) |
| `why <path>` | Manifest explanation | `{target, managed, resolved, rejected[], protected, in_root}` |
| `managed <path>` | Is it managed here | `{target, managed, scope, source}` |
| `explain <command>` | Steps the command would take here | `{steps[]}` |
| `init <remote> --machine <m>` | Clone, write `machine.toml`, create identity, install schedule | `{machine, recipient, sign_key, source}` |
| `status` | Drift, holds, ahead/behind, last sync | `{machine, applied, ahead, behind, drift[], holds[], last_sync}` |
| `apply [--dry-run] [path…]` | Write changed targets | `{commit, actions[], holds[], tasks[]}` |
| `capture [path…]` | Capture without committing | `{paths[], holds[]}` |
| `diff [path…]` | Plaintext diff target vs source | `{files[{target, diff}]}` |
| `commit [-m] [path…]` | Gate and commit now | `{commits[], holds[]}` |
| `sync [--auto] [--no-push]` | Section 10 | `{captured[], committed[], fetched, replayed, applied, pushed, retries, holds[], alerts[], tasks[]}` |
| `log [path]` | History, plaintext where openable | `{commits[]}` |
| `retag <path> <types> [--enclave]` | Section 8.5 | `{commit, removed_on[]}` |
| `bisect --as <m> -- <cmd>` | Sandbox bisect | `{first_bad}` |
| `collect` | Run collectors now | `{observed{}, skipped[]}` |
| `check` | Self-check | `{checks[{name, ok, detail}]}`: identity keys and modes, key logs vs pins, fleet vs key-log membership, manifest collisions, schedule loaded, last sync age, holds, secrecy config |
| `fleet list` / `show <m>` / `diff <collector>` | Section 11 | statuses / one machine / `ObservedDiff` |
| `enclave list` / `create` / `add` / `remove --confirm` / `join --expect` / `verify` | Section 7.3 | key-log heads and members |
| `review list` / `ok` / `revert` | Section 9.4 | `{items[{commit, scope, diff}]}` |
| `hold list` / `show <id>` / `resolve <id> --take source\|target\|<file>` | Holds | hold objects |
| `lease take` / `release` / `list` | Leases | leases |
| `task list` / `allow` / `run <name>` | Section 12 | definitions with allowed state, results |
| `schedule install` / `uninstall` / `status` | Section 13 | `{installed, loaded, last_run, unit_path}` |
| `import <legacy-repo>` | Section 15 | `{commit, mappings[], machines, problems[]}` |
| `adopt` | Section 15 | `{commit, actions[], holds[], tasks[]}` |
| `git <args…>` | Plain git on the source clone, with the secrecy overrides | passthrough; `--json` is not interpreted |

## 15. Import and adopt

### 15.1 Import

`yadm import <legacy-repo> --output <dir> [--machines <tsv>] [--password-env <VAR>] [--class-enclave <class>=<enclave>…]` converts a repository managed by upstream yadm once. It reads the repository; it never runs upstream yadm.

| Input | Output |
|---|---|
| `path##cond,cond` alternates | A manifest entry per variant with an equivalent `when`; source under `files/` or `sealed/<enclave>/`. Conditions, long and short form: `default`, `class`/`c`, `os`/`o`, `arch`/`a`, `hostname`/`h`, `user`/`u`, `distro`/`d`, `distro_family`/`f`, `template`/`t`, `extension`/`e` (ignored). Values compare case-insensitively upstream, so the importer lowercases `os` and `arch` values. Hostname, user, distro and distro family become declared facts. Anything else fails the import. |
| Templates (`##template` or `##template.default`) | The built-in processor's variables (`yadm.arch`, `yadm.class`, `yadm.classes`, `yadm.os`, `yadm.hostname`, `yadm.user`, `yadm.distro`, `yadm.distro_family`) become section 5.2 references or facts; `if` with `==`/`!=`, `else` and `endif` become conditions; `include` is inlined when its file exists in the repository. `env.VAR`, other processors (`esh`, `j2`, `j2cli`, `envtpl`) and anything unconvertible fail the import with path and line. |
| Paths with `filter=crypt` in `.gitattributes` | Decrypted with the password from `--password-env`, sealed into the enclave mapped from the file's class, or `--default-enclave`. The password is never written anywhere. |
| Machines table (TSV with header) | `name`, `hostname`, `classes` become fleet machines; hostname becomes a fact; classes become types. Other columns become declared facts. |

The output is one commit whose parent is the legacy head, with a `Legacy-Head:` trailer, so history stays reachable through `git log`. That also keeps the legacy ciphertext and old path names reachable. Any problem means no commit. The importer never pushes.

### 15.2 Adopt

`yadm adopt [--dry-run] [--allow-tasks] [--no-schedule]` switches one machine to this tool:

1. Verify the identity and that the source clone resolves for this machine.
2. For each target: identical bytes are recorded in state without writing (`adopt`); a missing target is written; a differing target is held (`drifted`) for the user to resolve. Nothing is overwritten.
3. Run first-apply tasks (if allowed).
4. Install the schedule.

Adopt leaves any other dotfiles tool installed and untouched, so the user can roll back.

## 16. Threat model

- Every machine can push. A non-member is a writer, not only a reader.
- An enclave protects against reading. A non-member can still delete or roll back sealed files, edit shared scripts members run, or forge a `Machine:` trailer. The notify hook reports non-member commits that touch an enclave; members see them in review.
- Key-log changes are signed and chained, so a writer cannot add itself or substitute a key.
- Task, check and collector definitions run only after a local allow.
- A 0600 key file is readable by every process of the user. An enclave separates machines, not processes on one machine.
- A removed machine keeps everything up to its removal.

## 17. Dependencies

Pinned in `go.mod`; `go 1.25` minimum. Each was fetched and exercised (`internal/crypt/deps_test.go`, `internal/rules/deps_test.go`), and the module cross-builds with `CGO_ENABLED=0` for linux/arm64.

| Module | Version | Use | Why |
|---|---|---|---|
| `filippo.io/age` | v1.3.2 | Wrap epoch keys to member recipients | Reference implementation of age; X25519 recipients; stable. |
| `github.com/tink-crypto/tink-go/v2` | v2.9.0 | AES-SIV (`daead/subtle`) | Maintained, audited deterministic AEAD; we do not implement SIV. Pulls `google.golang.org/protobuf` transitively. |
| Go standard library | | HKDF (`crypto/hkdf`), Ed25519, SHA-256 | No extra dependency. |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | Parse fleet and manifest; `unstable` parser with comments for the TOML span editor | Only Go TOML parser that exposes a comment-preserving AST. Expression ranges are empty for key-values, so spans come from child nodes. |
| `github.com/tidwall/sjson` (+ `gjson`) | v1.2.10 | Byte-preserving JSON and JSONC value edits | Keeps comments and spacing on set; delete takes the comment above the key, handled in rules. |
| `github.com/spf13/cobra` | v1.10.2 | Command tree and flags | Nested commands, persistent `--json`, flag errors mapped to exit 2. |

Three-way merge, unified diff and template patching (`internal/textmerge`) are this project's code, so plaintext stays in process.

Git is the `git` binary (merge-tree `--write-tree` needs a current git), not a library.

## 18. Out of scope

Hooks run by the tool, encrypted archives, alternate template processors, a permissions command (`mode` per entry covers it), self-upgrade and an "enter the repo" shell. `yadm git` covers raw git access.
