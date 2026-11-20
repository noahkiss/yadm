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
| `$XDG_STATE_HOME/yadm/` | State: `state.json`, private indexes, `lock` (the sync lock), `netlock` (the network lock), `quick.json`, `backup/`, `pins/<enclave>`, `allowed.json`, `leases/`, identity keys. Default `~/.local/state/yadm/`. |
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
quiet = "2m"                      # auto-commit quiet period

[conditions]                      # named conditions (section 5.1)
include = ["conditions.toml"]     # more [conditions] tables from the source tree
desk = "type:work & !os:linux"
editor.gui = "cond:desk | fact:editor=editor-one"

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
merge = "structural"              # how a sync conflict resolves (section 10)
volatile = ["window.zoom"]        # machine-local keys: a merge keeps this machine's value

[[file]]
target = ".ssh/config"
regions = true
mode = 0o600

[[unit]]
target = "Library/LaunchAgents/example.helper.plist"
kind = "launchd"
reload = "auto"                   # or "never"; auto skips KeepAlive jobs

[[root]]
path = ".config/shell"            # new files here are reported
ignore = ["cache/**", "*.log"]    # globs under path that are never reported

[tasks.package-bundle]
on = [".config/packages/list"]
command = ["pkg-tool", "bundle", "--file", ".config/packages/list"]
timeout = "10m"

[tasks.tool-config]
on_render = true                  # run when types, facts or the fleet change
outputs = [".config/tool/generated/**"]   # files it writes: generated, never captured
command = ["yadm-tool-config"]

[checks.secret-scan]
paths = ["**"]
command = ["secret-check"]
```

Resolution for one machine:

- An entry applies when its `when` condition is true. An empty `when` applies everywhere.
- Two applying entries for one target are a **collision**. Every command that resolves the manifest fails on it, and `yadm check` lists it.
- Without `source`, the source is `files/<target>`, or `sealed/<enclave>/<target>` when `enclave` is set.
- A target glob (`.config/tool/**`) expands against the source tree.
- `mode` defaults to 0644, or 0755 for an executable source. Sealed files follow the same rule: sealing changes what the repository stores, not the mode on disk.
- Without `mode`, a target under `.ssh/` or `.gnupg/` loses group and other access (0600, or 0700 when executable), and apply creates those directories with mode 0700. An explicit `mode` always wins.
- `review = true` excludes an entry from auto-commit. Its changes wait for `yadm commit`.
- `merge` picks the sync conflict policy (section 10), and `union` also lets apply merge a target changed on both sides (section 8.3): `text` (default), `union`, `add-only`, `ours`, `theirs`, `generated`, `json-keys`, `toml-keys` or `structural`. `volatile` lists key paths (keep and drop syntax) that stay machine-local: capture never commits a change to one (section 6), and a key-level merge always resolves one to this machine's value.
- An owned root shares the files under its source directory: a file at `files/<root>/<rest>` (plain root) or `sealed/<enclave>/<root>/<rest>` (enclave root) that no entry names, by target, source or glob, is a target with the root's enclave on every machine the root applies to. Capture writes a new file of a root there, so committing it shares it. To narrow who gets it, `yadm retag` gives it its own entry.
- A root's `ignore` globs, relative to its path, name files that are never reported as new. `yadm hold ignore <id>` does the same for one file on this machine only.

`yadm why <path> --json` returns the winning entry, every entry that named the path but did not apply (with the reason), whether the path is protected and which owned root contains it. When a `when` names a condition, `when_expanded` (winning entry) and `expanded` (each rejection) give it with every named condition inlined.

`yadm manifest --json [--as <machine> | --fleet]` resolves the manifest for this machine, another fleet machine or every one. Per machine it returns each entry's target, source, `when` (raw and expanded), mode, enclave, scope, merge policy, a rules summary (format, keep, drop, volatile, seal key paths with their enclave, regions), and the owned roots and applying tasks. A machine whose resolve fails carries `error`. The query reads no file content, so it prints no plaintext. Another machine's observed facts come from collectors it published `plain`, and from collectors it published `sealed:<enclave>` when this machine is a member of that enclave (section 11); `observed` says which source applied (`local`, `published`, `none`).

## 5. Conditions and templates

### 5.1 Conditions

One condition language serves `when`, tasks, checks, collectors and template `{% if %}`.

```
type:work   os:darwin   arch:arm64   machine:host-a
fact:editor             fact:editor=editor-one
observed:packages=tool-one
!   &   |   ( )   true   false
```

- `cond:NAME` stands for a named condition. The manifest's `[conditions]` table maps names to conditions; a name is dot-separated segments of letters, digits, `_` and `-`, so `editor.gui = "…"` and `"editor.gui" = "…"` name the same condition. `include` lists source files (no glob, not under `sealed/` or `keys/`) whose own `[conditions]` tables load too; other tables in them are ignored, and they cannot include further. A definition may use `cond:` itself. A cycle, an unknown name or a name defined twice (across files too) fails the load with the file and the name. Templates may use `cond:` in `{% if %}`; collector `when`s, which the fleet file holds, may not.
- `yadm eval '<cond>' --json [--as <machine>]` evaluates a condition with the named conditions and returns the result, the expansion and the names used. With `--as` another machine, observed facts are those it published `plain`, plus those it published `sealed:<enclave>` when this machine is a member of that enclave; `unavailable` lists the collectors the condition reads that it cannot see, and those terms are false.
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
| `volatile` | JSON, JSONC, TOML | The value it held before; a local change is never captured, and a key the source lacks stays out | Live value untouched; a missing key is seeded from the source | Same |
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

- **Predicate drops.** A `drop` entry `ARRAY[?FIELD~=VALUE]` (contains) or `ARRAY[?FIELD==VALUE]` (equals) selects the elements of each array `ARRAY` matches whose `FIELD` (a key path inside the element, `*` allowed; empty means the element itself) holds VALUE: `drop = ["hooks.*[?hooks.*.command~=tool run]"]`. Selected elements are machine-local: capture removes them, and apply removes the source's and puts the live file's back, each after the owned element that preceded it in the live file (found by value; failing that, by position). Unselected elements stay owned. A capture of an unchanged file round-trips byte for byte, comments included. A `drop` string that holds `[?` is always a predicate.
- A keep or drop path may name a TOML table under a parent it does not own (`keep = ["hooks.pre"]`): a sibling table the app writes (`[hooks.state]`) stays local. This holds for `[t]` and `[[t]]` tables.
- Key paths name nested keys separated by dots, with `*` for any one segment: `mcp.servers.*.env.TOKEN`. A literal dot or star inside a key is escaped with a backslash: the JSON key `"files.exclude"` is the path `files\.exclude`. Arrays are indexed by number. A path that names an object or table covers everything below it.
- Edits are byte-level. A no-op round trip returns identical bytes. A change touches only the bytes of the values it changes.
- The JSON and JSONC editor is this project's own scanner and span editor; `sjson` is not used, because its delete takes the comment above a key and it cannot expand `*`. The TOML span editor is this project's code too, on go-toml's `unstable` parser. Every edit re-parses its output and fails closed.
- The rules package decides comment ownership: a delete keeps the comment lines above a key, except when keep-mode pruning removes an app-owned key, which takes its comments with it.
- **Seal guard.** Capture refuses, and holds the file with `seal_guard`, when the target lost a sealed key or its parent, when a sealed plaintext appears outside its seal path, or when region markers are gone or unbalanced. A capture never commits a sealed part as plaintext.
- The leak check looks for a sealed value of 8 bytes or more anywhere in the file, and for a shorter one only as a whole quoted string. It skips region lines shorter than 8 bytes, and checks region lines only against an earlier source, so a first capture is not held for a line that also stands outside its region.
- After a remove or rotate, `rules.Reseal` moves every value and region token of the enclave to the current epoch without touching other bytes.
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
| File container | `"yadm-sealed\0"`, version byte 2, enclave name (length-prefixed), epoch (uint32 BE), SIV ciphertext. AD = the header bytes, then the source path (length-prefixed), which the container does not store. A blob moved to another path fails to open, so a rename needs a member to reseal it; `yadm retag` does. Version 1, which had no path in the AD, is refused. |
| Value token | `yadm:1:<enclave>:<epoch>:<base64url>`. AD = enclave, epoch, and the source path of the file and the concrete key path (escaped, never the manifest pattern). A token moved to another key or another file fails. |
| Region token | `yadm:sealed 1 <epoch> <base64>`. AD = enclave, epoch, and the source path of the file and the region label. A token moved to another file fails. |
| Wrapping | Every key-log entry carries all epoch keys so far, age-encrypted (X25519) to each member and to the recovery recipient. |
| Key commitments | Every key-log entry carries a SHA-256 commitment to each epoch key (`key_commits`). The list only grows. A machine checks the unwrapped keys against it, so no signer can swap an earlier epoch's key. |
| Signing | Ed25519 per machine and for the recovery identity. |
| Encodings | Base64 is decoded strictly. A key-log file must be exactly the canonical encoding; any other spelling of the same entry is refused. |

Why deterministic: an unchanged file reseals to the same blob, so there is no churn. Two machines that capture the same edit produce the same blob and converge. Sealed values stay byte-stable, so line merges work.

What it leaks: equal plaintexts at one path give equal ciphertexts, so a revert is visible. Sizes, file counts, paths (unless hidden paths are on), commit times and `Machine:` trailers are visible to every machine.

What the binding does not cover: a plaintext sibling of a sealed key (a server URL next to its token) stays editable by any writer. The seal list must cover what gives a secret its meaning.

### 7.2 Key log

`keys/<enclave>/<seq>.toml`, one file per entry, append-only:

```toml
enclave  = "personal"
seq      = 2
prev     = "<hex sha-256 of entry 1's signed bytes>"
epoch    = 1
min_epoch = 1                    # lowest epoch members still open for delivery
op       = "add"                 # create | add | remove | rotate | retire | recover | set-recovery
subject  = "m-x9y8z7"
members  = [{ machine = "m-a1b2c3", recipient = "age1…", sign_key = "<base64>" },
            { machine = "m-x9y8z7", recipient = "age1…", sign_key = "<base64>" }]
recovery = { machine = "recovery", recipient = "age1…", sign_key = "<base64>" }
key_commits = ["<hex sha-256 commitment to the epoch 1 key>"]
wrapped  = "<base64 age file holding epoch keys 1..epoch>"
signer   = "m-a1b2c3"
sig      = "<base64 Ed25519 over the canonical bytes with sig empty>"
```

Verification, on every load:

1. Entry `n+1` has `prev` = hash of entry `n`.
2. Its signer is a member of entry `n`, or the recovery identity of entry `n` for `recover` and `set-recovery` only. The signature verifies.
3. `remove`, `rotate` and `recover` increase the epoch by one. `create` is epoch 1. `add`, `retire` and `set-recovery` keep the epoch.
4. `key_commits` holds one commitment per epoch and keeps entry `n`'s list as its prefix.
5. `min_epoch` stays the same, except that `retire` raises it, to at most the epoch.
6. Only `set-recovery` changes the recovery identity.
7. The chain contains the machine's local pin (`pins/<enclave>`). A machine never accepts a chain that does not extend its pin.

When a machine opens its keys, it checks each unwrapped key against `key_commits`.

Key-log files are append-only in history. Sync refuses a fetched commit that changes or deletes an existing `keys/<enclave>/<seq>.toml`. A signed competing entry at an existing seq is how a removed member would fork the log for a machine whose pin has not reached the removal yet. Each machine publishes its pinned head in its status ref, so a member that has not pinned a removal is visible.

A machine writes an entry only on a head that is exactly its pin. Loading the log verifies the chain from the old pin and advances the pin, so every write descends from everything the machine accepted. A machine with no pin writes only `create`, `recover` or `set-recovery`.

An entry that fails any check is rejected; the enclave is reported as `refused` and its files are not applied until fixed. A machine that can push but holds no member key therefore cannot substitute a key: it cannot sign.

Pinning is strict; there is no trust on first use:

- A machine opens an enclave's keys only when it holds a pin for that enclave.
- The machine that writes an entry (create, add, remove, rotate, recover) pins it in the same step.
- Every other machine gets its first pin only from `yadm enclave join <enclave> --expect <fingerprint>`, with the fingerprint received out of band.
- A machine listed as a member without a pin is refused. The message names the enclave and the join step. It shows no fingerprint from the local log, which a writer controls.
- Without this rule, a writer could replace an unpinned log with one that lists the machine. The machine would then seal new files under keys the writer holds.

### 7.3 Lifecycle

| Step | Who | What happens |
|---|---|---|
| Create | Any machine of the type | `yadm enclave create <type>` writes entry 1, signed by the creator, wrapped to the creator and the recovery recipient. The recovery identity is generated offline and stored by the user outside the repository. |
| Join request | New machine | `yadm init` prints its recipient, signing key and machine id. |
| Add | A current member | `yadm enclave add <machine>` appends an `add` entry wrapped to the new member, and prints the entry fingerprint. |
| Pin | New machine | `yadm enclave join <enclave> --expect <fingerprint>` pins that entry. The fingerprint travels out of band. |
| Remove | A current member | `yadm enclave remove <machine> --confirm` appends a `remove` entry with a new epoch, wrapped to the rest, and reseals every sealed file, value and region of the enclave in one commit, templates and glob entries included. The removed machine keeps every key up to the old epoch and every commit it already fetched. The output lists what else the user must do: revoke the machine's repository access, rotate real secrets stored in the enclave, and retire the old epoch once the reseal has landed. |
| Retire | A current member | `retire` entry that sets `min_epoch` to the current epoch, after the reseal commit has landed. From then on no member opens ciphertext of an older epoch for delivery. Until then, sealed content that is new to a machine (a source blob it has not applied before) opens only under the current epoch, and anything older is held with `seal_guard`. A removed member therefore cannot plant content under the keys it kept. |
| Recover | Recovery identity | `recover` entry signed by the recovery key, used when no member remains. |
| Set recovery | Recovery identity | `set-recovery` entry signed by the current recovery key that names a new recovery identity. It is how a leaked recovery key is replaced. |

Key-log changes, `fleet.toml` and `manifest.toml` are protected: they never auto-commit.

### 7.4 Where plaintext may exist

- In a member's `$HOME` (the targets).
- In memory during render, capture, merge and diff. Three-way merges, diffs and template patching run in-process (`internal/textmerge`); plaintext is never handed to git.
- On stdout for `yadm diff`, `yadm log -p`, `yadm review` and `yadm hold show`.
- In a 0600 temp file in the state directory while a commit-gate check reads it, removed afterwards. Checks see only files this machine can already open. A gate with no state directory runs no check and holds the files; it never uses the system temp directory.
- In `backup/enclave/<enclaves>/` in a member's state directory: the bytes apply replaced or deleted from a file with enclave plaintext (a whole sealed file, sealed values or regions), mode 0600, kept 30 days. When a verified key log no longer lists this machine, apply deletes that enclave's backups. A refused log deletes nothing. Other backups go to `backup/<time>/` and hold no enclave plaintext. A non-member never writes an enclave's plaintext, so its backups hold none.

The state database stores hashes, never rendered bytes. The one exception is the proposed patch of a `rendered_edit` hold on a shared template (section 8.4); an enclave template's hold carries none, so no enclave plaintext enters the state. The last render of a template is recomputed from its source blob and the stored render Context when capture needs it.

Plaintext never enters the source tree, the object store, a ref, a note (a review note on an enclave commit is sealed, section 9.6), a commit message, the status ref (except collectors published `plain`) or any non-member path. The tool runs git with `-c diff.cachetextconv=false`, defines no textconv, and `yadm check` fails on any `refs/notes/textconv` ref, any `cachetextconv = true` setting, and any filter or merge driver in the source clone's own config. The `git_drivers` check also fails on a filter or merge driver from any config scope (global, system) that an attribute source of the clone assigns: a `.gitattributes` in `main` or the worktree, `info/attributes`, the global attributes file (`core.attributesFile` or its XDG default) or, with git 2.42 or newer, the system one. A name counts when any line sets it, even if its pattern matches no path yet. A driver no attribute names, such as the `filter.lfs.*` keys `git lfs install` writes globally, never runs on the clone's paths, so the check leaves it alone: git hands a filter or merge driver a blob only for a path whose attributes name it.

Every change to sealing or delivery needs a test with `internal/secrecytest` that plants a canary in enclave plaintext and asserts it reaches neither a non-member's `$HOME` nor any repository's object store.

Any machine can push `manifest.toml`, so a manifest change that would make a member stage plaintext takes effect only after a local allow, as a task definition does (section 12.3):

- **Weaker protection.** The state records, per target, the protection of the last apply: the whole-file enclave, each sealed key with its enclave, regions, and the machine-local keys: `keep` (the keys the repo owns), `drop` and `volatile`. When the manifest drops or moves any of them, removes `keep` or adds a key to it, or removes a `drop` or `volatile` key, apply and capture hold the target with `seal_guard` until the user allows the new protection on this machine (`yadm protection allow`). Apply never records a weaker protection on its own. A new entry with `keep`, `drop` or `volatile` over a file yadm never wrote is held with `needs_decision`, even when its render equals the file; `adopt` takes it over. Apply takes it over without a hold only on evidence the merge cannot fake: the file, or the regular file inside `$HOME` that a symlink there points to, is byte-identical to the source's own bytes (opened, for a sealed source). `yadm hold resolve <id> --take target` on such a file, or on one `adopt` held `drifted`, is the decision: the target is recorded as managed with the entry's protection, and the live file is captured through the entry's rules (a `volatile` or dropped key keeps the source's value) and committed. When the capture changes nothing, nothing is committed and the target is still recorded.
- **Owned roots.** A new `[[root]]`, or one whose enclave changed, does nothing until allowed: it neither captures new files nor delivers its entry-less files. Until then the old version of the root stays, and the root is held as `root_untrusted`. An enclave root that leaves the manifest stays until its removal is allowed, so a plain root around it never captures its files. Scan and capture read only allowed roots. When a root takes effect, the files already in it form a baseline that is never captured automatically. The baseline walk follows a root that is itself a symlink, and the files `adopt` copies in when it replaces a directory symlink join the baseline too. A file that leaves management but stays on disk joins the baseline, and so does a protected target that leaves the plan.
- **Modes.** An explicit `mode` may not grant a file with enclave plaintext (a whole sealed file, sealed values or regions) a permission bit its source mode lacks. Apply holds such a target with `seal_guard`. Without `mode`, these files follow section 4. The state records the explicit `mode` of the last apply; a manifest that drops it or widens it holds the target with `seal_guard` until allowed on this machine.
- **Paths.** Apply, scan and capture never read or write a target whose parent directory resolves, through a symlink, outside `$HOME`; it is held. A target whose name holds a control character is held, never written or captured. Every suggested command (a hold's `next`, a packet's `command`) shell-quotes the paths it names.
- **Merges.** An in-memory merge of a sealed file opens both sides under the current epoch only, so it never reseals old-epoch content under the current one.

### 7.5 Hidden paths (reserved)

A type with `hide_paths = true` would store files as `sealed/<enclave>/<base32(HMAC(name key, path))>` with the real path inside the sealed header. The interface exists (`crypt.NameScheme`, `crypt.HiddenNames`); the implementation is not built. It is off by default. Even when built, counts, sizes, timing and co-change stay visible.

## 8. Apply, scan, capture and drift

### 8.1 State

`state.json` records, per managed target: source path and blob, scope, the SHA-256 of the bytes last written, size, mtime and mode, the mode the entry wanted, the seal set at last apply, the SHA-256 of the last render for templates, and when the current drift was first seen. It also records the applied commit, whether the first apply ran, holds, observed facts, last task results and the render Context of the last apply. It holds no file content, except the proposed patch of a `rendered_edit` hold on a shared template, and never leaves the machine.

### 8.2 Scan

Every command starts with a scan. It is a stat pass over managed targets and owned roots that hashes a file only when its stat tuple changed. A full hash pass runs at most once a day. Scans are bounded by the managed set and owned roots; they never walk all of `$HOME`.

Drift kinds: `modified`, `deleted`, `new` (in an owned root), `mode`.

A mode is drift only when it is wider than the entry wants or breaks a script. A live mode that grants a subset of the wanted bits (`live &^ want == 0`, such as 0640 from a tool writing under umask 027 where 0644 is wanted) is not drift and makes no hold. Apply and adopt take over a file yadm never wrote, whose bytes match, at such a stricter mode too, except a read-only one, which takes the entry's mode (section 15.2). A mode with any bit outside the wanted one drifts. One exception: a wanted mode with the owner's execute bit drifts when the live mode lacks it (0644 where 0755 is wanted), since the file stops running; 0750 there is not drift.

A file that matches a task's `outputs` glob (section 12.1) is generated: scan never reports it, capture and retag never take it, so it is never committed or gated. `yadm status` lists such files under `generated`.

### 8.3 Apply

1. Resolve the manifest for this machine; render each target in memory.
2. Skip a target whose bytes already match.
3. Hold a target whose current hash differs from the last written hash (`drifted`). Apply never overwrites it. The usual path captures it first. One exception: a `merge = "union"` target whose source changed too is merged, not held (see below).
4. Write changed targets atomically (temp file and rename), with the entry's mode. Copy the replaced bytes into `backup/` for 30 days. Apply never changes only the mode of a target whose stricter mode is not drift (section 8.2): it widens that mode only when it writes new bytes. When the entry's mode changes, apply sets the new mode on a target whose mode is still the one it last recorded.
5. Delete a target that left the plan, only if it is unchanged since written; otherwise hold it.
6. On a non-member, skip sealed files (`sealed` action) and leave sealed values and regions out.
7. Run triggered tasks (section 12): path tasks, remove tasks, unit reloads and, once per machine, first-apply tasks.

A `merge = "union"` target can change here while a sync brings a new source, for example an append-only list appended on two machines before either committed. Apply then writes the line union instead of holding the target. The base is the source as last written (opened, for a sealed file on a member), ours is the new source and theirs is the target. The union keeps every line either side added, the source's lines first, then the lines only the target has; a line either side removed stays removed, and a line that appears twice is written once. The state still records the source as written, so the next scan finds the union as drift and capture commits it. The write follows the mode rules of section 8.2 and backs up the replaced bytes. The target is held as `drifted` when the union cannot be computed: binary content, a template or intra-file rules on the entry, or a last-written source that is gone or does not open. Without a source change, a local edit of a union target is ordinary drift for capture.

### 8.4 Capture

- **Verbatim file:** the target bytes become the source bytes.
- **Sealed file:** the target is sealed under the current epoch. Deterministic sealing makes an unchanged file a no-op.
- **Template:** capture recomputes the last render (source blob plus stored render Context, checked against the stored hash), diffs it against the target, applies the hunks to the template where their context matches verbatim, re-renders and accepts only if the result equals the target byte for byte. Otherwise the target is held (`rendered_edit`) and status reports it. Apply never re-renders over it. The hold names the template (`source`) and carries a proposed unified diff (`patch`). With `patch_of = "template"` it patches the template: a three-way merge of template and target over the last render, each conflict resolved to the target's lines, accepted only when it renders back to the target on this machine. An edit on an expression or a conditional block thus becomes literal text, so the agent reviews it before committing. When no such candidate exists, `patch_of = "render"` and the diff is the hand edit against the last render. An agent edits the template and commits in one step. An enclave template's hold carries no patch, because holds live in `state.json`, which never holds plaintext.
- **Intra-file rules:** package rules (section 6), with the seal guard.
- **Every capture** passes the round-trip check: render(new source) = target. A failure is held as `uncapturable`, never committed.

### 8.5 Retag

`yadm retag <path> <type>[,<type>...] [--enclave <name>]` changes which machines get a target in one commit: the manifest entry's `when` and `enclave`, and the move between `files/` and `sealed/<enclave>/` with the content opened and resealed. Only a member of every enclave involved can retag. Machines that lose the target remove it on their next apply if it is unchanged there, and hold it otherwise. Retag is protected: it is a manual commit only. Its changes land together or not at all: when the gate holds the target, the manifest edit and the move are not committed either. On an unmanaged file in `$HOME` that no manifest entry names, retag tracks it: it appends an entry with the types' `when` (and the enclave) and commits the file's bytes as its source. A file a glob entry covers is refused.

### 8.6 Track

`yadm track <path> [--when <condition>] [--enclave <name>] [--no-push]` starts syncing a file that nothing covers yet. It appends a `[[file]]` entry for the path to `manifest.toml`, with `when` and `enclave` when given, and adds the file's bytes as its source: `files/<target>`, or `sealed/<enclave>/<target>` sealed under the enclave's current epoch, so a non-member only ever receives ciphertext. Both changes land in one commit (subject `track <path>`) through the commit gate, or neither does: when the gate holds the file, nothing is committed. The commit is pushed in the same call; with `--no-push`, the next sync publishes it. The new `when` is checked against the fleet before anything is committed.

Track refuses, with exit 2 and nothing committed, a path that a manifest entry names, a glob entry matches or an owned root contains (the error names which; `yadm retag` and `yadm commit` handle those), a path outside `$HOME`, a directory (share one with a `[[root]]`), and a path that is not a regular file. An `--enclave` that is not an enclave type fails; one this machine is not a member of is refused with exit 6.

## 9. Commits

### 9.1 Private index

Every commit operation builds its own fresh index file in the state directory, seeded from the parent commit and holding only that operation's paths. The source clone's own index and worktree are never used to stage. Parallel agents and the timer never sweep each other's changes.

### 9.2 Commit gate

Before any commit, manual or automatic, the gate runs every `[checks.<name>]` whose `paths` match a staged target, through the exec contract (section 12.4). The request lists the staged targets and the paths of 0600 temp files holding their plaintext. The gate fails closed: a non-zero exit, a timeout, `ok: false` or a check this machine has not allowed holds the matching files with `check_failed`. Other files still commit. Verdicts are per file: when a check fails on several files at once, the gate runs it again on each of them alone (up to 50), and only the files that fail alone stay held.

Source changes that are not targets skip the gate: a key-log entry (signed tool output) and the manifest edit of a retag or a track. They hold no plaintext, and check `paths` name targets. They still commit under the sync lock, through a private index.

### 9.3 Auto-commit

The timer runs `yadm sync --auto`. A captured path auto-commits when all hold:

- its quiet period has passed since its last change, by mtime (entry `quiet`, default 2 min; `0s` commits at once);
- no lease names it (`yadm lease take`; leases expire);
- the busy probe, if configured, does not name it;
- it is not protected: `manifest.toml`, `fleet.toml`, `keys/**`, `conditions.include` files, manifest `protected` globs, entries with `review = true`, new files outside owned roots, files that were in an owned root when it was accepted here (held `protected` until committed by name), deletions, retags, and more than 50 changed files in one scope;
- the gate passes.

Commits group by scope (`shared` or an enclave name), one commit per scope per run. Every commit the tool makes reaches the remote in the same call, through the phases of a sync (section 10): fetch, then the commit, replay, apply and publish under the sync lock, then push. The exception is a harness hook's commit: hooks commit locally and never touch the network, and the next timer tick pushes (the quick check runs in full when local `main` is ahead of the remote). The network lock lets one process per machine reach the remote at a time, whatever the number of agent sessions.

### 9.4 Commit messages

A tool commit reads like a human one. The subject is `<verb> <path>` for one file, `<verb> N files in <dir>` when they share a directory, and `<verb> N files` otherwise. The verb is `add`, `update` or `remove`. A commit whose only change was merged up the ladder is `merge <path> (<rung>)`. A caller's subject wins: `-m`, or the intent given with `--why` or by a harness hook. The body lists every path. Trailers:

| Trailer | Value |
|---|---|
| `Machine` | the machine id |
| `Yadm-Auto` | the trigger: `hook`, `stop`, `scan`, `manual` or `merge` |
| `Yadm-Scope` | `shared` or the enclave |
| `Yadm-Session` | the harness session id, when known |
| `Yadm-Tool` | the tool that made the edit (an editor tool, a shell, an app), when known |
| `Yadm-Resolved` | the ladder rung and path of each merged change |

```
update 3 files in .config/shell

.config/shell/aliases.sh
.config/shell/env.sh
.config/shell/prompt.sh

Machine: m-a1b2c3
Yadm-Auto: scan
Yadm-Scope: shared
```

A message names paths only. No subject, body or trailer ever carries file content, so enclave plaintext never reaches a message. (Hidden paths, section 7.5, would also keep sealed paths out of the subject.)

### 9.5 Manual commits

`yadm commit [-m <subject> | --why <intent>] [--no-push] [path...]` makes a manual commit and pushes it. It bypasses the quiet period and leases, never the gate or the seal guard. A source clone with local edits stops it before anything is committed, with a `source_dirty` hold. Protected paths commit only when named. A named file that predates its owned root is captured too. A named path that no manifest entry or owned root covers on this machine (the path itself, or anything under it) fails the whole commit, `--dry-run` included, before anything is captured; the error names the path and suggests `yadm retag`. With `--no-push`, the next sync pushes. When the push does not happen in this call (another process holds the network lock, or the remote kept moving), the commit stands, `push_error` says why, and the next sync pushes.

### 9.6 Review

Each scope has a fast-forward-only ref `refs/yadm/reviewed/<scope>`. Each machine trusts its own copy. Sync pushes a local advance, and moves the local ref to a fetched one only when the move skips no commit of the scope; otherwise the fetched ref is refused with a `reviewed_ref_refused` alert, since any machine can push it. `init` seeds empty local refs from the fetched ones. `yadm review list [scope] --json` lists commits in `reviewed/<scope>..main` that touch the scope, with plaintext diffs for scopes this machine can open, and `deferred`: the decisions agents moved here with `yadm defer` (section 9.7) whose holds are still open. Agents act with `yadm review ok <scope> <commit>`, `yadm review revert <commit>` (a new commit), a fix-forward commit, or `yadm bisect --as <machine> -- <cmd>`, which renders each candidate commit into a sandbox and never touches `$HOME`.

`yadm review note <commit> --why "<text>"` attaches a why note to a commit on `refs/yadm/notes/review`: a chain of commits whose tree holds `<commit id>.json` per note. The ref is fetched with the other yadm refs, and sync pushes it with `main`. A diverged notes ref is rebuilt on the remote one with the local notes it lacks, the newer note winning on one commit. `review note` writes the note under the sync lock and pushes it afterwards, under the network lock. `yadm log` and `review list` show each commit's note.

- A note on a commit that touches no enclave is stored as written.
- A free-text note on a commit that touches an enclave (`sealed/<e>/`, `keys/<e>/`, or a file whose entry seals values for `e`) is sealed to that enclave before it is written, with the file container bound to `notes/review/<commit>`. Members read it; every other machine sees `sealed note`. The note is refused (exit 6) when the commit touches more than one enclave, when it changes a file with sealed regions and `--seal` names no enclave, or when this machine is not a member.
- `--paths-only` writes a note whose text the tool generates from the commit's paths, which every machine already sees. It is never refused.
- The workflow that writes notes belongs to content, not core.

### 9.7 Agent hooks

Agents edit dotfiles; they must not have to remember to commit. `yadm hook <event>` is the harness side of that. A harness runs it from its hook configuration (an example is in `docs/hooks.md`, with the input and output schema). The file scan stays the primary trigger: editor hooks see only part of the changes (shell commands and apps write files too), so the timer still captures everything else.

| Event | Harness moment | Does |
|---|---|---|
| `post-edit` | after a file write or edit tool | Records the path for the session. If the path is managed or inside an owned root, commits it now through the gate, with `Yadm-Auto: hook` and `Yadm-Session`, locally; the next timer tick pushes it. Silent when clean; otherwise a decision packet. |
| `stop` | the agent (or a subagent) ends its turn | Commits the session's recorded paths locally; the next timer tick pushes them. Blocks the stop while a decision this session caused is open, including a conflict the timer met while pushing them. |
| `session-start` | a session starts | A quick sync, then at most 10 lines: holds near the cwd, deferred decisions, unreviewed auto-commits, fleet drift. |

A hook commit is unattended: naming the path does not lift protection, and a new file in an owned root is held (`protected`) for a decision, since which machines get it is the user's choice. A hook waits at most a few seconds for the sync lock; if another process holds it, the path stays recorded and `stop` or the timer commits it.

A **decision packet** says what happened, the diff size (line counts, never content), which machines and types the file reaches, a proposed fix, and two to five options, each with its consequence and the exact command. Packets cover a new file in an owned root (with the types its neighbours go to, and the options to share it, track it for those types with `yadm retag`, ignore it with `yadm hold ignore`, or defer it), a `rendered_edit` hold (with its patch for a shared template), a gate failure, a `seal_guard` hold, a conflict with an incoming change, and any other hold through its suggested commands.

"Decisions this session caused" are the open holds on the session's recorded paths (or on the owned roots that contain them), except plain drift and deferred ones. A subagent's stop considers only its own paths. `yadm defer <hold-id> --reason <why>` moves one to the review queue: the hold stays and the file stays uncommitted, but the session may end. Session records live under `hooks/` in the state directory as append-only lines (path, agent, tool), so parallel hooks never lose an update.

## 10. Sync

Two locks in the state directory serialize the processes of one machine. No process holds the sync lock while it waits on the network.

| Lock | File | Serializes | When it is held |
|---|---|---|---|
| sync lock | `lock` | Local writes: scan and capture, commits, replay, apply, publish, collectors, hold resolve, retag, enclave writes, the local allows (`task allow`, `root allow`, `protection allow`) | A command waits at most 30 s, then exits with code 4; a harness hook waits at most 3 s and leaves the work to the timer |
| network lock | `netlock` | Fetch, push and `git ls-remote` | Never waited on: a process that finds it held skips its network step, says so, and the next sync does it |

Each lock file holds its holder's record while held: pid, command (the binary name and subcommand words, no paths) and start time. The exit-4 error names the holder and how long it has held the lock. `yadm status` lists a lock held for more than 10 s and an active network backoff. A record whose pid is dead is ignored. No command waits without a bound; every git and external call has a timeout (3 min for a network call). Git runs in its own process group, and the whole group is killed at the deadline, so a stalled ssh child cannot keep a lock. Every commit goes through `sync.Commit`. `apply` and the local allows read `main` again once they hold the sync lock, since the process they waited for may have moved it.

A **quick sync** (`--quick`, and `--auto` unless `--full`) first runs a cheap check: a stat scan and `git ls-remote` of `main` and `refs/yadm/*`, compared with what the last full sync saw. It stops there unless the remote `main` or a reviewed ref moved, a target drifted, the last full sync is 15 minutes old, or the last check is more than 3 minutes old (the machine slept or the timer stopped). The first run is always full. A tick where nothing moved costs one stat pass and one round trip. Peers' status refs move on every sync, so they do not trigger a full sync; the periodic one fetches them. When `git ls-remote` fails, the run stops and the quick check backs off: it does not reach the remote again for 1 minute, doubling per further failure up to 15 minutes. A remote that answers, or a full sync (wake, periodic, local drift), clears it. The quick check also runs in full when local `main` is ahead of the remote (a hook's commit, or a push that was skipped or rejected, waits for the timer to push it). The stat scan runs under the sync lock and `git ls-remote` under the network lock; when another process holds the network lock, the check stops there, since that process is syncing already.

A sync runs in three phases:

- **Fetch**, under the network lock and without the sync lock: step 4. It updates only remote-tracking refs, so local writers go on meanwhile. When the network lock is held, the fetch is skipped and the run replays onto the last fetched `origin/main`. When the fetch fails, the local steps still run (capture, auto-commit, collectors), and the run ends with the fetch error before step 5.
- **Local work**, under the sync lock: steps 1 to 3 and 5 to 8.
- **Push**, under the network lock, after the sync lock is released: step 9.

The steps:

1. Scan and capture.
2. With `--auto`, auto-commit by policy (section 9.3).
3. Run allowed collectors.
4. Fetch `main` and `refs/yadm/*` (the fetch phase, before step 1). On a first sync, the key-log and manifest guards compare the fetched source with the `origin/main` the clone had before this fetch.
5. If local `main` is not an ancestor of `origin/main`, replay each local commit onto `origin/main` with `git merge-tree --write-tree`, in memory:
   - clean: `commit-tree` with the original message and trailers;
   - conflict on a sealed file this machine can open: open the three stages, merge them in memory (`textmerge.Merge3`), reseal, write the tree; a remaining conflict is held like any other;
   - other conflicts: the clean paths of the commit land; conflicted paths move to the local-only ref `refs/yadm/held/<machine>` and become `conflict` holds with all three stage blobs.
   Before a conflict is held, a ladder tries to resolve it in memory: a key-level merge for JSON, JSONC and TOML (edits to different keys never conflict; `volatile` keys keep this machine's value; one key changed differently on both sides fails), then the entry's `merge` policy (section 4). A rung that resolves a file records it in a `Yadm-Resolved` trailer.
   History stays linear. There is no autostash and no merge commit.
6. Compare-and-swap local `main`. Move the source worktree; if it has local edits, stop with a `source_dirty` hold (the tool never stashes). `main` moves only over a clean clone, checked while `HEAD` still names the old `main`, so the clone's index never falls behind `HEAD`. A clean clone at a commit yadm reached (a `yadm git commit` on `main`, for example) counts as clean. The hold's advice returns the clone to `HEAD`.
7. Apply.
8. Publish this machine's status record (section 11).
9. Release the sync lock. Under the network lock, push `main`, the status ref, the advanced reviewed refs and the notes ref atomically. The refspecs are computed in step 8, under the sync lock. A local commit made between steps 8 and 9 goes out too, since it descends from the replayed `main`. Never force. A rejection means the remote moved after the fetch; it is not an error. The run fetches, replays and pushes again, up to 5 more rounds with backoff, taking the sync lock again for each replay (when another process holds it, the run stops there and notes it); after that the next sync does it. When the network lock is held, the push is skipped and the next sync does it. After a push that moved `main`, run the nudge (section 12.5).

`sync` reports a skipped or rejected network step in `network`. Only a sync that fetched and whose push went out, or had nothing to push, counts as a full sync for the quick check and clears its backoff, so local `main` stays ahead and the next tick runs in full.

A manual commit, a hold resolve that commits, `retag`, `track` and the enclave commands run the same phases around their commit, in the same call: fetch first, then the commit and steps 3 and 5 to 8 under the sync lock, then step 9. A hook commit leaves the network to the next tick.

A fetched source whose key log rewrites, deletes or forks an entry, or holds an entry that does not parse, is refused before anything is applied: a `key-log` task hold and one alert, local `main` stays, and `main` is not pushed. A malformed entry never fails the sync itself.

A fetched manifest that weakens protection is refused the same way, with a `manifest-guard` hold: a target both sources plan loses its enclave, a seal key or regions, or a new or changed owned root covers a path the accepted source protects. The guard compares the last accepted remote with the fetched one, and refuses only what local `main` does not already run. `yadm protection allow <target>` or `yadm root allow <path>` names the refused source while the hold is open; the next sync takes it.

A hold on a managed target settles by itself when a complete scan finds the target back at what this machine last wrote or captured: its drift, failed capture or failed check no longer applies. Conflict holds and weakened-protection holds stay until resolved or allowed.

A conflict hold is settled with `yadm hold resolve <id>`: `--take target` (or `--take <file>`, written to the target first) commits this machine's file over the current source and pushes it; `--take source` drops the hold and rewrites the target from the source, backing up the replaced bytes.

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

A member of an enclave reads the facts other machines sealed for it:

- `fleet list` and `fleet show` keep `status` as the published record. Each row adds `sealed_observed`, the opened facts per enclave, and `sealed_errors` for a member's enclave whose facts fail to open.
- `fleet diff`, `eval --as` and `manifest --as` or `--fleet` read the opened facts as that machine's observed facts.
- A reader opens only the enclaves it is a member of. It takes an opened fact only when `fleet.toml` declares its collector `sealed:<that enclave>`, and for such a collector it ignores a plain value, which any writer can publish.
- A non-member sees only the plain facts. Its output never holds another enclave's facts.
- The sealed facts are bound to their enclave and epoch, not to the machine whose status ref carries them. A writer can copy one machine's sealed facts into its own status ref, and members then read them as that machine's.

Observed facts:

- A collector is a name, a command, a timeout and a `when` condition in `fleet.toml`.
- It runs on sync through the exec contract. Line output is normalized: trimmed, empty lines dropped, sorted, de-duplicated. A JSON response may carry `items` or `data`.
- `publish = "local"` (default) keeps the result in local state. `plain` also puts it in the status ref, readable by every machine. `sealed:<enclave>` puts it there sealed for that enclave.
- Templates, and conditions evaluated for this machine, read only its own observed facts, from local state.
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

- Triggers: `on` (target written), `on_remove` (target removed), `first_apply` (the first apply after `init` or `adopt`), `on_fact` (a listed input changed on this machine: a collector name for its observed items, or `fact:KEY` for a declared fact) and `on_render = true` (the render context changed: this machine's types, declared and observed facts, or the fleet file).
- `on_fact` and `on_render` compare fingerprints (hashes, never values) of the inputs with what the task last ran against, kept per task in state. A task with no record runs once. A held task records nothing, so the change still runs it once it is allowed; a failed run records, as a failed path task does not retry. Only a full apply checks inputs, and adopt runs no task. The trigger is named `fact` or `render` in the result.
- `outputs` lists target globs the task writes. They are generated (section 8.2). A managed target that matches one fails the resolve. Adding these fields to a definition changes its hash, so it needs a new allow; a definition without them keeps the hash it had.
- A task runs once per apply, after all writes, with the matched targets in its request.
- A failed task is recorded in state and the status ref, reported through notify, and never stops other tasks or the sync.
- **Units** are a built-in task: apply reloads a launchd agent (`launchctl bootout` and `bootstrap`) or a systemd user unit (`daemon-reload`, then restart) only when its bytes changed. A reload needs no allow entry: the unit file is managed content, and the service manager runs it at the next login whether or not apply reloads it. With `reload = "never"` a unit is never reloaded. On `auto`, the launchd reloader also skips a job whose plist sets `KeepAlive`, the job that runs the reload (`$XPC_SERVICE_NAME`), and a plist it cannot read as XML. A skip is recorded in the task result detail, not as a failure.
- A held task keeps the first apply open only when it is a `first_apply` task. A first-apply task that already succeeded does not run again while another one waits to be allowed. Once a held definition is allowed, the next apply drops its hold.

### 12.2 No package manager in core

The core knows no package manager and does no machine provisioning. Bootstrap is a task with `first_apply = true`. Package-manager integration, if ever needed, ships as a separate `yadm-<name>` executable that a task or collector calls. `docs/extensions.md` lists what such an extension may rely on: the JSON contracts, the exec contract, the manifest and eval queries and named conditions. A first-party extension in `cmd/yadm-<name>` imports only `cond`, `rules`, `extexec`, `model` and `render`, and no package under `internal/` names a coding-agent harness; tests enforce both.

### 12.3 Trust

Tasks, checks and collectors run commands, and any machine that can push can change their definitions. A machine runs a definition only after it is allowed locally: `yadm task allow [name...]`, or `--allow-tasks` on `init` and `adopt`. `allowed.json` stores a SHA-256 of each allowed definition. A changed definition is not run; it becomes a `task_untrusted` hold until allowed again. Definitions live in protected files and never auto-commit. The same allow list holds two more kinds: `yadm protection allow <target>` accepts a manifest change that weakens a target's sealing or protection here, and `yadm root allow <path>` accepts a new, changed or removed owned root (until then it holds `root_untrusted`). Both apply right after recording the allow.

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

External subcommands: `yadm foo args…` runs `yadm-foo` from `PATH` when `foo` is not built in, with `kind = "subcommand"` and `args`. Under `--json`, its response is wrapped in the normal envelope. A non-zero exit is reported with its code and stderr tail in `error.details`.

### 12.5 Nudge

Peers learn of a push on their next timer tick at the latest. To make it immediate, a user may install an executable `yadm-nudge` on `PATH`. After a push that moved `main`, sync runs it under the exec contract with `kind = "nudge"` and `event = {kind: "pushed", commit, machine}`, with a 10 s timeout; its failure never fails the sync. What it does is the user's: ping a notification service, or reach peers over their own network. A peer that receives a nudge runs `yadm sync --quick`. The core names no service.

## 13. Schedule

`yadm init` and `yadm adopt` install the sync schedule unless given `--no-schedule`: a launchd user agent on macOS, a systemd user timer on Linux. It runs `yadm sync --auto` every minute and once at login or wake; each run starts with the quick check (section 10), so a full sync runs only when something moved, at least every 15 minutes, and after a wake. A run missed during sleep is not queued; the next run catches up once and tolerates a network that returns late (fetch failures retry on the next tick). `yadm schedule install|uninstall|status` manage it directly.

The unit names yadm by an absolute path; a path inside a Homebrew Cellar is mapped to the version-free link in `<prefix>/bin`, so an upgrade does not break it. The unit sets an explicit `PATH`: the binary's directory, the Homebrew prefixes (`/opt/homebrew`, `/usr/local`, `/home/linuxbrew/.linuxbrew`) and the system directories. The caller decides whether a command may change the real service manager; a test binary also needs `YADM_SCHEDULE_LIVE=1`.

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
| 4 | `locked` | Another yadm process has held the sync lock past the wait (section 10); the message names its pid, command and age. Retry later |
| 5 | `not_implemented` | |
| 6 | `refused` | Refused for secrecy or trust: not a member, a key log that fails verification, an untrusted definition |

`yadm hook <event>` has its own contract, for harnesses: it prints one verdict object (not an envelope) or nothing, and exits 0 (allow), 2 (a decision blocks) or 1 (the hook failed; harnesses go on). See `docs/hooks.md`.

Hold objects have a stable shape for external resolvers. Fields are only added within a schema version:

```json
{ "id": "<stable hash>", "target": ".gitconfig", "scope": "shared", "reason": "conflict",
  "since": "…", "detail": "…", "base": "<blob>", "ours": "<blob>", "theirs": "<blob>",
  "next": ["yadm hold show <id>", "yadm hold resolve <id> --take source"] }
```

A `rendered_edit` hold also carries `source`, `patch` and `patch_of` (section 8.4). A hold's `since` is its first sighting, so its `id` stays stable while the cause persists.

Reasons: `drifted`, `uncapturable`, `conflict`, `protected`, `secret_scan`, `seal_guard`, `source_dirty`, `task_untrusted`, `check_failed`, `rendered_edit`, `root_untrusted`, `needs_decision`.

### 14.2 Command list

| Command | Does | `data` |
|---|---|---|
| `version` | Version and build | `{version, go, os, arch}` |
| `where` | Directories | `{source, state, config}` |
| `machine` | This machine | the fleet `Machine` plus `observed` and `enclaves` (opened, refused) |
| `why <path>` | Manifest explanation | `{target, managed, resolved, rejected[], protected, in_root, when_expanded?}` |
| `manifest [--as <m> \| --fleet]` | Resolved manifest per machine (section 4) | `{schema, commit, outputs[], machines[{machine, name, types, observed, error?, entries[], roots[], tasks[]}]}` |
| `eval <cond> [--as <m>]` | Evaluate a condition (section 5.1) | `{schema, machine, name, condition, expanded, names[], result, observed, unavailable[], note?}` |
| `managed <path>` | Is it managed here | `{target, managed, scope, source}` |
| `explain <command>` | Steps the command would take here | `{steps[]}` |
| `init <remote> --machine <m>` | Clone, write `machine.toml`, create identity, install schedule | `{machine, recipient, sign_key, source}` |
| `status` | Drift, holds, ahead/behind, last sync, locks held over 10 s, network backoff | `{machine, applied, ahead, behind, drift[], holds[], last_sync, generated[]?, locks[{lock, holder{pid, command, since}}]?, net_backoff_until?}` |
| `apply [--dry-run] [path…]` | Write changed targets | `{commit, actions[], holds[], tasks[]}` |
| `capture [path…]` | Capture without committing | `{paths[], holds[]}` |
| `diff [path…]` | Plaintext diff target vs source | `{files[{target, diff}]}` |
| `commit [-m\|--why] [--no-push] [path…]` | Gate, commit and push now | `{commits[], holds[], pushed, push_error?}` |
| `sync [--auto] [--quick] [--full] [--no-push]` | Section 10 | `{captured[], committed[], fetched, replayed, applied, pushed, retries, holds[], alerts[], tasks[], skipped, reason, network?}` |
| `log [path]` | History, plaintext where openable; each commit's review note | `{commits[{…, note?}]}` |
| `retag <path> <types> [--enclave]` | Section 8.5; commits through the gate and pushes | `{commit, removed_on[], holds[]}` |
| `track <path> [--when <cond>] [--enclave <e>] [--no-push]` | Section 8.6; commits through the gate and pushes | `{target, source, scope, commit, pushed, holds[], push_error?}` |
| `bisect --as <m> -- <cmd>` | Sandbox bisect | `{first_bad}` |
| `collect` | Run collectors now | `{observed{}, skipped[]}` |
| `check` | Self-check | `{checks[{name, ok, detail}]}`: identity keys and modes, key logs vs pins, fleet vs key-log membership, manifest collisions, schedule loaded, last sync age, holds, secrecy config |
| `fleet list` / `show <m>` / `diff <collector>` | Section 11 | statuses / one machine / `ObservedDiff`; rows carry `sealed_observed` on a member |
| `enclave list` / `create` / `add` / `remove --confirm` / `join --expect` / `verify` / `retire` / `set-recovery` | Section 7.3; `remove` also retires old epochs once its reseal commit lands | key-log heads and members |
| `protection allow <target>` / `root allow <path>` | Local allows (section 12.3), then apply | `{allowed, apply}` |
| `review list` / `ok` / `revert` / `note <commit> --why <text> \| --paths-only [--seal <e>] [--no-push]` | Section 9.6 | `{items[{commit, scope, diff, note?}], deferred[]}`; note: `{note, pushed, push_error?}` |
| `hold list` / `show <id>` / `resolve <id> --take source\|target\|<file>` / `ignore <id>` | Holds; a take that captures commits and pushes; `ignore` leaves an unmanaged file in an owned root untracked on this machine | hold objects |
| `hook post-edit` / `stop` / `session-start` | Section 9.7; harness JSON on stdin | a verdict (`docs/hooks.md`) |
| `defer <hold-id> --reason <why>` | Move a decision to the review queue | the deferred record |
| `lease take` / `release` / `list` | Leases | leases |
| `task list` / `allow` / `run <name>` | Section 12 | definitions with allowed state, results |
| `schedule install` / `uninstall` / `status` | Section 13 | `{installed, loaded, last_run, unit_path}` |
| `import <legacy-repo>` | Section 15 | `{commit, mappings[], machines, problems[]}` |
| `adopt` | Section 15 | `{commit, actions[], holds[], tasks[]}` |
| `git <args…>` | Plain git on the source clone, with the secrecy overrides | passthrough; `--json` is not interpreted |

## 15. Import and adopt

### 15.1 Import

`yadm import <legacy-repo> --output <dir> [--machines <tsv>] [--password-env <VAR>] [--class-enclave <class>=<enclave>…] [--filters <toml>] [--crypt-filter <name>…] [--machine <name>]` converts a repository managed by upstream yadm once. It reads the repository; it never runs upstream yadm.

| Input | Output |
|---|---|
| `path##cond,cond` alternates | A manifest entry per variant with an equivalent `when`; source under `files/` or `sealed/<enclave>/`. Conditions, long and short form: `default`, `class`/`c`, `os`/`o`, `arch`/`a`, `hostname`/`h`, `user`/`u`, `distro`/`d`, `distro_family`/`f`, `template`/`t`, `extension`/`e` (ignored). Values compare case-insensitively upstream, so the importer lowercases `os` and `arch` values. Hostname, user, distro and distro family become declared facts. Anything else fails the import. |
| Templates (`##template` or `##template.default`) | The built-in processor's variables (`yadm.arch`, `yadm.class`, `yadm.classes`, `yadm.os`, `yadm.hostname`, `yadm.user`, `yadm.distro`, `yadm.distro_family`) become section 5.2 references or facts; `if` with `==`/`!=`, `else` and `endif` become conditions; `include` is inlined when its file exists in the repository. `env.HOME` becomes `{{ home }}`. Any other `env.VAR`, other processors (`esh`, `j2`, `j2cli`, `envtpl`) and anything unconvertible fail the import with path and line. |
| Paths with `filter=crypt` in `.gitattributes` | Decrypted with the password from `--password-env`, sealed into the enclave mapped from the file's class, or `--default-enclave`. The password is never written anywhere. A filter of another name counts as transcrypt when the legacy repository's own local config (a bare repository works; the config is read, never run or written) shows a smudge, clean or textconv command that runs transcrypt, or when `--crypt-filter <name>` names it, since a clone lacks that config. A file stored as ciphertext under any other filter fails the import. |
| Tracked symlinks | Entries that reuse the source of what the link points at, under both conditions. A link that names a path inside a directory alternate (`dir##class.x/file`) reuses the files converted from it, under that alternate's condition. |
| Paths with any other `filter=<name>` (a strip filter) | The `--filters` file maps each filter, per target or target glob, to the entry's `format`, `keep`, `drop`, `volatile` and `merge`. A strip filter that also ran transcrypt sets `crypt = true`; its files are decrypted and sealed too. A path whose filter has no mapping, or no rule for its target, fails the import, so a filter is never lost silently. |
| Machines table (TSV with header) | `name`, `hostname`, `classes` become fleet machines; hostname becomes a fact; classes become types. Other columns become declared facts. Each machine gets a random id, except the row `--machine` names, which gets the importing machine's own id; a `--machine` that names no row fails the import. |

The output is one commit whose parent is the legacy head, with a `Legacy-Head:` trailer, so history stays reachable through `git log`. That also keeps the legacy ciphertext and old path names reachable. Any problem means no commit. The importer never pushes.

Sealing creates each enclave's key log, signed by the importing machine, on top of that commit. Once it is committed, the importing machine pins it in its state directory, so it needs no `enclave join --expect`; the report still prints each fingerprint for the other machines. An existing different pin for that enclave is kept, and the report says to join after switching repositories. A failed import pins nothing.

### 15.2 Adopt

`yadm adopt [--dry-run] [--allow-tasks] [--no-schedule]` switches one machine to this tool:

1. Verify the identity and that the source clone resolves for this machine.
2. Materialize links another tool left: a directory symlink above a target that points into `$HOME` becomes a real directory holding a copy of what it pointed to.
3. For each target: identical bytes are recorded in state without writing (`adopt`); a missing target is written; a differing target is held (`drifted`) for the user to resolve. Nothing is overwritten. A target that is a symlink to a file with the rendered bytes becomes a regular file with those bytes, and a read-only file with the rendered bytes (a 0444 render) takes the entry's mode. A symlink with other content is held.
4. Install the schedule.

Adopt runs no task: no path task, unit reload or first-apply task. `--allow-tasks` only records the allows; first-apply tasks run on the first apply after adopt. Adopt never changes or removes what a link pointed to, and leaves any other dotfiles tool installed, so the user can roll back.

## 16. Threat model

- Every machine can push. A non-member is a writer, not only a reader.
- An enclave protects against reading. A non-member can still delete or roll back sealed files, edit shared scripts members run, or forge a `Machine:` trailer. The notify hook reports non-member commits that touch an enclave; members see them in review.
- Key-log changes are signed and chained, so a writer cannot add itself or substitute a key. Key commitments stop a signer from swapping an earlier epoch's key. Key-log files are append-only in history, so a removed member cannot replace an entry for a machine that has not pinned the removal.
- A writer can move or swap sealed blobs, values and regions; each is bound to its path and key, so a moved one fails to open and is held. Sealed observed facts are the exception: they are bound to their enclave and epoch, not to a machine, so a writer can copy them between status refs (section 11).
- Task, check and collector definitions run only after a local allow. So do a manifest change that weakens a target's protection (enclave, seals, regions, an explicit mode, or the machine-local keys of `keep`, `drop` and `volatile`) and a new or changed owned root.
- A writer can push `refs/yadm/reviewed/<scope>`. A machine never takes a fetched reviewed ref that skips commits it has not reviewed.
- A writer chooses target names. Suggested commands shell-quote them, and names with control characters are held.
- The recovery identity signs only `recover` and `set-recovery`. A leaked recovery key is replaced with `set-recovery`.
- A 0600 key file is readable by every process of the user. An enclave separates machines, not processes on one machine. The tool loads identity files only as regular files (no symlink) owned by the user, in a state directory with no group or other access.
- A removed machine keeps everything up to its removal. It cannot plant content under its old keys: new sealed content opens only under the current epoch, and `retire` refuses old epochs for delivery for good. Its local backups of the enclave are deleted on the first apply after the removal.

## 17. Dependencies

Pinned in `go.mod`; `go 1.25` minimum. Each was fetched and exercised (`internal/crypt/deps_test.go`, `internal/rules/deps_test.go`), and the module cross-builds with `CGO_ENABLED=0` for linux/arm64.

| Module | Version | Use | Why |
|---|---|---|---|
| `filippo.io/age` | v1.3.2 | Wrap epoch keys to member recipients | Reference implementation of age; X25519 recipients; stable. |
| `github.com/tink-crypto/tink-go/v2` | v2.9.0 | AES-SIV (`daead/subtle`) | Maintained, audited deterministic AEAD; we do not implement SIV. Pulls `google.golang.org/protobuf` transitively. |
| Go standard library | | HKDF (`crypto/hkdf`), Ed25519, SHA-256 | No extra dependency. |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | Parse fleet and manifest; `unstable` parser with comments for the TOML span editor | Only Go TOML parser that exposes a comment-preserving AST. Expression ranges are empty for key-values, so spans come from child nodes. |
| `github.com/tidwall/sjson` (+ `gjson`) | v1.2.10 | Test only: `internal/rules/deps_test.go` records why rules does not use it | Its delete takes the comment above a key and it cannot expand `*`, so rules has its own JSON and JSONC editor. |
| `github.com/spf13/cobra` | v1.10.2 | Command tree and flags | Nested commands, persistent `--json`, flag errors mapped to exit 2. |

Three-way merge, unified diff and template patching (`internal/textmerge`) and the JSON, JSONC and TOML span editors (`internal/rules`) are this project's code, so plaintext stays in process.

Git is the `git` binary (merge-tree `--write-tree` needs a current git), not a library.

## 18. Out of scope

Hooks run by the tool, encrypted archives, alternate template processors, a permissions command (`mode` per entry covers it), self-upgrade and an "enter the repo" shell. `yadm git` covers raw git access; it refuses verbs that move the source HEAD (pull, checkout, reset, switch, merge, rebase, cherry-pick, revert, am) and points to `yadm sync`.
