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
| `$XDG_STATE_HOME/yadm/` | State: `state.json`, private indexes, `lock` (the sync lock), `netlock` (the network lock), `remote-accepted` (the accepted remote `main`, section 10), `quick.json`, `backup/`, `pins/<enclave>`, `allowed.json`, `leases/`, `pause.json`, `reroot.json` (re-roots this machine switched to, section 10.2), identity keys. Default `~/.local/state/yadm/`. |
| `$XDG_DATA_HOME/yadm/backups` | Bundles of old histories that re-roots replaced (section 10.2), beside the source clone and outside it and the state directory. |
| `$XDG_STATE_HOME/yadm/identity.age.key` | This machine's age X25519 identity, mode 0600. |
| `$XDG_STATE_HOME/yadm/identity.sign.key` | This machine's Ed25519 signing key, mode 0600. |
| `$XDG_CONFIG_HOME/yadm/machine.toml` | Local identity: machine id, remote, notify and busy commands, on-demand enclaves. Untracked. |

`yadm where --json` prints the three directories.

`machine.toml`:

```toml
machine = "m-a1b2c3"
remote  = "git@git.example.invalid:user/dotfiles.git"
notify  = ["yadm-notify"]          # optional, extexec contract
busy    = ["yadm-busy-probe"]      # optional, extexec contract
on_demand = ["work"]               # optional, enclaves read on demand only (section 7.6)
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
# pause_requires = "member"   # a fleet pause counts only when a pinned key-log member signed it (section 10.1)

[types.personal]
enclave = true          # files of this type are sealed for members
reroot_keep = 3         # back up the old history on a re-root; keep 3 (section 10.2)

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
- The fleet file never grants enclave membership. The key log does (section 7). `yadm check` reports where `types` and key-log membership disagree. A member that reads the enclave on demand only (section 7.6) needs no type.
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
- A target glob (`.config/tool/**`) expands against the source tree. A file in `$HOME` that an applying glob matches but whose source does not exist yet is not a target. `yadm commit <path>` or `yadm track <path>` captures it under that entry: its source is the entry's source directory plus the rest of the path (`files/…`, `sealed/<enclave>/…` for an enclave), with the entry's rules, and no entry is added. The capture is refused when two applying globs match the path, or when another applying entry would also read that source. Scan never looks for such files outside owned roots, so sync and an unnamed commit leave them alone; a named path is captured. A file inside an owned root that an applying glob matches is the glob's, not the root's: any capture of it goes through the glob entry, and a file two applying globs match is never captured.
- `mode` defaults to 0644, or 0755 for an executable source. Sealed files follow the same rule: sealing changes what the repository stores, not the mode on disk.
- Without `mode`, a target under `.ssh/` or `.gnupg/` loses group and other access (0600, or 0700 when executable), and apply creates those directories with mode 0700. An explicit `mode` always wins.
- `review = true` excludes an entry from auto-commit. Its changes wait for `yadm commit`.
- `merge` picks the sync conflict policy (section 10), and `union` also lets apply merge a target changed on both sides (section 8.3): `text` (default), `union`, `add-only`, `ours`, `theirs`, `generated`, `json-keys`, `toml-keys` or `structural`. `volatile` lists key paths (keep and drop syntax) that stay machine-local: capture never commits a change to one (section 6), and a key-level merge always resolves one to this machine's value.
- An owned root shares the files under its source directory: a file at `files/<root>/<rest>` (plain root) or `sealed/<enclave>/<root>/<rest>` (enclave root) that no entry names, by target, source or glob, is a target with the root's enclave on every machine the root applies to. Capture writes a new file of a root there, so committing it shares it. To narrow who gets it, `yadm retag` gives it its own entry.
- A root's `ignore` globs, relative to its path, name files that are never reported as new and never captured, named or not. `yadm hold ignore <id>` stops reporting one file on this machine only; committing that file by name tracks it again.
- Only the deepest accepted root that contains a new file captures it, and it never hands the file to a shallower root. It does not capture a file its `ignore` globs match, a file under a deeper enclave root of another enclave (one this machine has not accepted, or whose `when` is false here), or a file a manifest entry names, applying or not. `yadm commit <path>` refuses such a file with exit 6 and names the glob, the enclave root (with `yadm root allow` when it applies here) or the entry. Scan does not report it, and hooks and the timer leave it alone. To share a file an ignore glob hides, give it its own entry with `yadm retag`.

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
- A render reads only this machine's own Context: the source commit, its fleet entry, `$HOME`, the user, and its own observed facts from local state. Apply and capture never read another machine's status ref, so renders are reproducible and the capture round-trip check is sound. Only `yadm show --as`, which prints to stdout, renders with another machine's published `home` and `user` (section 7.6).

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
| File container | `"yadm-sealed\0"`, version byte 2, enclave name (length-prefixed), epoch (uint32 BE), SIV ciphertext. AD = the header bytes, then the source path (length-prefixed), which the container does not store. A blob moved to another path fails to open, so a rename needs a member to reseal it: `yadm source mv` does within an enclave, `yadm retag` across scopes. Version 1, which had no path in the AD, is refused. |
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

Key-log files are append-only in history. Sync refuses a fetched commit that changes or deletes an existing `keys/<enclave>/<seq>.toml`. A re-root (section 10.2) may replace the commits but keeps every key-log file byte for byte. A signed competing entry at an existing seq is how a removed member would fork the log for a machine whose pin has not reached the removal yet. Each machine publishes its pinned head in its status ref, so a member that has not pinned a removal is visible.

A machine writes an entry only on a head that is exactly its pin. Loading the log verifies the chain from the old pin and advances the pin, so every write descends from everything the machine accepted. A machine with no pin writes only `create`, `recover` or `set-recovery`.

An entry that fails any check is rejected; the enclave is reported as `refused` and its files are not applied until fixed. A machine that can push but holds no member key therefore cannot substitute a key: it cannot sign.

Pinning is strict; there is no trust on first use:

- A machine opens an enclave's keys only when it holds a pin for that enclave.
- The machine that writes an entry (create, add, remove, rotate, recover) pins it in the same step.
- Every other machine gets its first pin only from `yadm enclave join <enclave> --code <code>` or `--expect <fingerprint>`, with the join code or fingerprint received out of band.
- A machine listed as a member without a pin is refused. The message names the enclave and the join step. It shows no code or fingerprint from the local log, which a writer controls.
- Without this rule, a writer could replace an unpinned log with one that lists the machine. The machine would then seal new files under keys the writer holds.

**Join code.** A human carries the out-of-band value from one screen to another, so `enclave add` prints a short join code beside the fingerprint:

| Item | Choice |
|---|---|
| Input | The 32-byte entry fingerprint (SHA-256 of the signed bytes, so it covers enclave, seq, subject, members and keys). |
| KDF | argon2id (`golang.org/x/crypto/argon2`), 3 passes, 256 MiB, 1 thread, salt `yadm v1 join code`. About 0.6 s on a current laptop. |
| Output | 5 bytes (40 bits) as 8 Crockford base32 characters (`0-9A-Z` without `I`, `L`, `O`, `U`), shown as `XXXX-XXXX`. |
| Parsing | Case, dashes and spaces are ignored; `O` reads as `0`, `I` and `L` as `1`. A malformed code is a usage error. |
| Candidate | The newest `add` entry whose subject is the joining machine. Join derives that entry's code and pins only on a match. A wrong code, or the code of any other entry, pins nothing. |

Why 40 bits is enough with the KDF:

- The attack is a second preimage, not a collision. The attacker is a writer without a member key. To pass a forged log, it must build one whose `add` entry for the joining machine derives the same code as the honest entry. It cannot choose the honest entry, so a birthday search does not apply.
- No window bounds the work. A forged log is the attacker's own `create` and an `add` of the joining machine, which needs only the machine id that `yadm init` prints. The attacker can grind a table of codes before the honest `add` exists, and a code does not expire. The cost per guess is what bounds the attack.
- Each guess costs one full argon2id run: 256 MiB of memory and about 0.6 s of laptop time. A 50% chance needs 2^39 runs, about 10^4 core-years at that rate. Memory hardness limits how much GPU or ASIC parallelism buys.
- Join checks one candidate entry, so a forged log gets one guess per join, not one per entry it holds. Each join also costs the joining machine only one KDF run.
- The attacker must already hold repository write access. Without it, the attacker cannot place a forged log at all.
- `--expect <fingerprint>` remains for a user who wants the full 256 bits, and for entries that are not an `add` of the joining machine (the import's `create` entries, section 15).

### 7.3 Lifecycle

| Step | Who | What happens |
|---|---|---|
| Recovery keys | Any machine, no membership needed | `yadm enclave new-recovery <dir>` generates a recovery identity into a new directory (mode 0700, files 0600) outside the source, state and config directories and `~/.local`, symlinks resolved, and outside every path the manifest manages, owned roots and globs included. It refuses an existing directory, so it never overwrites one. It prints the public half and the `enclave create <type> --recovery-recipient … --recovery-sign-key …` line for the creator. The user stores the files offline and deletes the directory. `create --new-recovery <dir>` does the same on the creator. |
| Create | Any machine of the type | `yadm enclave create <type>` writes entry 1, signed by the creator, wrapped to the creator and the recovery recipient. Only the recovery identity's public half reaches the creator. |
| Join request | New machine | `yadm init` and `yadm machine` print its recipient, signing key and machine id. |
| Add | A current member | `yadm enclave add <machine>` appends an `add` entry wrapped to the new member, and prints its join code and fingerprint. The new member's keys come from `--recipient` and `--sign-key`, or from a vouching key log (below). |
| Pin | New machine | `yadm enclave join <enclave> --code <code>` (or `--expect <fingerprint>`) pins that entry. The code travels out of band. A machine that reads the enclave on demand runs `yadm enclave on-demand <enclave>` first (section 7.6). |
| Remove | A current member | `yadm enclave remove <machine> --confirm` appends a `remove` entry with a new epoch, wrapped to the rest, and reseals every sealed file, value and region of the enclave in one commit, templates and glob entries included. The entry and the reseal land together or not at all: when the commit gate holds any resealed file, remove commits nothing, names the held targets, and leaves the key log, pins and epoch unchanged. Remove retires the old epochs only after it finds every resealed file in its commit as written. The removed machine keeps every key up to the old epoch and every commit it already fetched. The output lists what else the user must do: revoke the machine's repository access, rotate real secrets stored in the enclave, and retire the old epoch once the reseal has landed. |
| Retire | A current member | `retire` entry that sets `min_epoch` to the current epoch, after the reseal commit has landed. From then on no member opens ciphertext of an older epoch for delivery. Until then, sealed content that is new to a machine (a source blob it has not applied before) opens only under the current epoch, and anything older is held with `seal_guard`. A removed member therefore cannot plant content under the keys it kept. |
| Recover | Recovery identity | `recover` entry signed by the recovery key, used when no member remains. |
| Set recovery | Recovery identity | `set-recovery` entry signed by the current recovery key that names a new recovery identity. It is how a leaked recovery key is replaced. |

Key-log changes, `fleet.toml` and `manifest.toml` are protected: they never auto-commit.

**Keys for `enclave add`.** Wrapping the enclave keys to a false recipient hands the enclave to whoever holds its secret. So `add` takes the new member's keys from one of two sources:

- **The flags.** The user reads `--recipient` and `--sign-key` off the new machine's `yadm machine` (or `yadm init`) and compares them on both screens.
- **A vouching key log.** The flags may be left out when another enclave's key log vouches for the keys. All of these must hold:
  - This machine has pinned that log, and its verified head lists the machine.
  - The entry that introduced the machine's current key pair is signed by this machine, or by a current member of the enclave being added to. This is the last entry where the machine appears, or appears with other keys. The signer counts by its signing key: the key that verified the entry must be the one the target enclave's head lists for it. A machine id alone counts for nothing, since the other log's members could list that id under a key they hold.
  - Every pinned log whose verified head lists the machine lists the same keys, whoever signed it. On a disagreement, `add` asks for the flags.
  - The target enclave's own log never listed the machine. A removed machine comes back only through the flags.
  - The user names the machine by its id, never by a fleet name. The id alone selects the keys, and any writer can edit `fleet.toml`.

Why the signer rule: a signer that is already a member of the target enclave holds its keys. A false key from it gives it no access it lacks. A member of only the other enclave gets no such pass, or it could plant a key in its own enclave's log and so reach a second enclave.

What never vouches:

- `fleet.toml` and status records carry no keys, and any writer can edit them.
- An unpinned log may be a writer's forgery (section 7.2).
- A machine's own `create` and a `recover` entry name no trusted signer.

When the flags disagree with any pinned log, the flags win and the output says so. The output's `keys_from` names the source: `flags`, or the vouching enclave and its head's seq.

### 7.4 Where plaintext may exist

- In a member's `$HOME` (the targets), unless the member reads the enclave on demand (section 7.6).
- In memory during render, capture, merge and diff. Three-way merges, diffs and template patching run in-process (`internal/textmerge`); plaintext is never handed to git.
- On stdout for `yadm diff`, `yadm log -p`, `yadm review`, `yadm hold show` and `yadm show`.
- In a 0600 temp file in the state directory while a commit-gate check reads it, removed afterwards. Checks see only files this machine can already open. A gate with no state directory runs no check and holds the files; it never uses the system temp directory.
- In `backup/enclave/<enclaves>/` in a member's state directory: the bytes apply replaced or deleted from a file with enclave plaintext (a whole sealed file, sealed values or regions), mode 0600, kept 30 days. When a verified key log no longer lists this machine, apply deletes that enclave's backups. A refused log deletes nothing. Other backups go to `backup/<time>/` and hold no enclave plaintext. A non-member never writes an enclave's plaintext, so its backups hold none. Neither does a member that reads the enclave on demand (section 7.6).

The state database stores hashes, never rendered bytes. The one exception is the proposed patch of a `rendered_edit` hold on a shared template (section 8.4); an enclave template's hold carries none, so no enclave plaintext enters the state. The last render of a template is recomputed from its source blob and the stored render Context when capture needs it.

Plaintext never enters the source tree, the object store, a ref, a note (a review note on an enclave commit is sealed, section 9.6), a commit message, the status ref (except collectors published `plain`) or any non-member path. The tool runs git with `-c diff.cachetextconv=false`, defines no textconv, and `yadm check` fails on any `refs/notes/textconv` ref, any `cachetextconv = true` setting, and any filter or merge driver in the source clone's own config. The `git_drivers` check also fails on a filter or merge driver from any config scope (global, system) that an attribute source of the clone assigns: a `.gitattributes` in `main` or the worktree, `info/attributes`, the global attributes file (`core.attributesFile` or its XDG default) or, with git 2.42 or newer, the system one. A name counts when any line sets it, even if its pattern matches no path yet. A driver no attribute names, such as the `filter.lfs.*` keys `git lfs install` writes globally, never runs on the clone's paths, so the check leaves it alone: git hands a filter or merge driver a blob only for a path whose attributes name it.

Every change to sealing or delivery needs a test with `internal/secrecytest` that plants a canary in enclave plaintext and asserts it reaches neither a non-member's `$HOME` nor any repository's object store.

Any machine can push `manifest.toml`, so a manifest change that would make a member stage plaintext takes effect only after a local allow, as a task definition does (section 12.3):

- **Weaker protection.** The state records, per target, the protection of the last apply: the whole-file enclave, each sealed key with its enclave, regions, and the machine-local keys: `keep` (the keys the repo owns), `drop` and `volatile`. When the manifest drops or moves any of them, removes `keep` or adds a key to it, or removes a `drop` or `volatile` key, apply and capture hold the target with `seal_guard` until the user allows the new protection on this machine (`yadm protection allow`). Apply never records a weaker protection on its own. A new entry with `keep`, `drop` or `volatile` over a file yadm never wrote is held with `needs_decision`, even when its render equals the file; `adopt` takes it over. Apply takes it over without a hold only on evidence the merge cannot fake: the file, or the regular file inside `$HOME` that a symlink there points to, is byte-identical to the source's own bytes (opened, for a sealed source). `yadm hold resolve <id> --take target` on such a file, or on one `adopt` held `drifted`, is the decision: the target is recorded as managed with the entry's protection, and the live file is captured through the entry's rules (a `volatile` or dropped key keeps the source's value) and committed. When the capture changes nothing, nothing is committed and the target is still recorded.
- **Owned roots.** A new `[[root]]`, or one whose enclave changed, does nothing until allowed: it neither captures new files nor delivers its entry-less files. Until then the old version of the root stays, and the root is held as `root_untrusted`. An enclave root that leaves the manifest stays until its removal is allowed, so a plain root around it never captures its files. A plain root never captures a file under a deeper enclave root that is not accepted here either (section 4). Scan and capture read only allowed roots. When a root takes effect, the files already in it form a baseline that is never captured automatically. The baseline walk follows a root that is itself a symlink, and the files `adopt` copies in when it replaces a directory symlink join the baseline too. A file that leaves management but stays on disk joins the baseline, and so does a protected target that leaves the plan.
- **Modes.** An explicit `mode` may not grant a file with enclave plaintext (a whole sealed file, sealed values or regions) a permission bit its source mode lacks. Apply holds such a target with `seal_guard`. Without `mode`, these files follow section 4. The state records the explicit `mode` of the last apply; a manifest that drops it or widens it holds the target with `seal_guard` until allowed on this machine.
- **Paths.** Apply, scan and capture never read or write a target whose parent directory resolves, through a symlink, outside `$HOME`; it is held. A target whose name holds a control character is held, never written or captured. Every suggested command (a hold's `next`, a packet's `command`) shell-quotes the paths it names.
- **Merges.** An in-memory merge of a sealed file opens both sides under the current epoch only, so it never reseals old-epoch content under the current one.

### 7.5 Hidden paths (reserved)

A type with `hide_paths = true` would store files as `sealed/<enclave>/<base32(HMAC(name key, path))>` with the real path inside the sealed header. The interface exists (`crypt.NameScheme`, `crypt.HiddenNames`); the implementation is not built. It is off by default. Even when built, counts, sizes, timing and co-change stay visible.

### 7.6 On-demand enclaves

A machine can hold an enclave's keys without receiving its files. The fleet this serves has one enclave per work machine (`work`, `client`), and personal machines that must read those files without taking them home.

- The personal machine becomes a full key-log member through `enclave add` and `enclave join`. The key log has no read-only role: anyone who holds a symmetric epoch key can also seal with it.
- `on_demand` in `machine.toml` lists the enclaves this machine reads on demand only. It is a local setting, never in the fleet file or the manifest. `yadm enclave on-demand <enclave>` adds a name; `--off` removes it. Set it before `enclave join`, so no sync after the join delivers anything.
- For an on-demand enclave the machine verifies the key log and advances its pin as for any enclave. Apply then leaves its keys out, so the machine treats the enclave as a non-member does:
  - Apply never writes its whole files, sealed values or regions into `$HOME`. A shared file is delivered without them.
  - Capture, `track` and `retag` never seal for it. A sealed value or region in a shared file is restored from the source on capture.
  - Its plaintext never goes to a backup. A file whose protection names the enclave (its whole-file enclave, a seal key, or a region marker in its bytes) is replaced without a backup only when it holds the bytes apply last wrote, which the source reproduces. Any other such file is not replaced: apply and `hold resolve --take source` fail and ask the user to move it aside. Older backups of the enclave are deleted.
  - A target of it that an earlier apply delivered leaves `$HOME` as if it had left the plan: deleted when unchanged, held as `drifted` otherwise.
  - The commit gate and in-memory merges never open it.
- The machine opens it only to print to stdout:
  - `yadm show <path> [--as <machine>]` renders a target as a fleet machine receives it: that machine's plan and condition context, opened with the keys of every enclave it is a member of in the pinned key log. It refuses when that machine is a member of an enclave this machine cannot open. Without `--as` it renders for this machine as if every enclave it is a member of were delivered. With `--as`, `{{ home }}` and `{{ user }}` take the values that machine published in its status record (section 11); a machine that published none, or values that are not an absolute clean path and a plain name without control characters, renders them as the literal `$HOME` and `$USER`, never as this machine's own. `home_from` in the output says which (`local`, `published` or `placeholder`), and text output notes a placeholder on stderr. `--source` prints the entry's source unrendered instead: a whole sealed file opened, a template as written, sealed values and regions as their tokens. It takes the same refusals.
  - `yadm review`, `yadm hold show` and review notes open it as for any member.
  - Sealed observed facts of the enclave (section 11) open as for any member, in `fleet list`, `fleet show`, `fleet diff`, `eval --as` and `manifest --as`.
  - `yadm diff` compares delivered targets with the source; it skips an on-demand target and points to `yadm show`.
- `enclave add` and `retire` work as for any member. `enclave remove` is refused: its reseal commit passes the commit gate, whose checks would read the enclave's plaintext from a temp file in the state directory. A member that receives the enclave runs it.
- The machine publishes its `on_demand` list in its status record (section 11). `yadm check` on any machine lists each enclave's members from the pinned head with a role: `type`, `on demand` or `no type`. A member with neither the type nor an on-demand claim fails the `membership` check. An `on_demand` name that is not an enclave in `fleet.toml` fails the `on_demand` check, since a typo would leave the enclave delivered.

## 8. Apply, scan, capture and drift

### 8.1 State

`state.json` records, per managed target: source path and blob, scope, the SHA-256 of the bytes last written, size, mtime and mode, the mode the entry wanted, the seal set at last apply, the SHA-256 of the last render for templates, and when the current drift was first seen. It also records the applied commit, whether the first apply ran, holds, observed facts, last task results and the render Context of the last apply. It holds no file content, except the proposed patch of a `rendered_edit` hold on a shared template, and never leaves the machine.

### 8.2 Scan

Every command starts with a scan. It is a stat pass over managed targets and owned roots that hashes a file only when its stat tuple changed. A full hash pass runs at most once a day. Scans are bounded by the managed set and owned roots; they never walk all of `$HOME`.

Drift kinds: `modified`, `deleted`, `new` (in an owned root), `mode`.

A mode is drift only when it is wider than the entry wants or breaks a script. A live mode that grants a subset of the wanted bits (`live &^ want == 0`, such as 0640 from a tool writing under umask 027 where 0644 is wanted) is not drift and makes no hold. Apply and adopt take over a file yadm never wrote, whose bytes match, at such a stricter mode too, except a read-only one, which takes the entry's mode (section 15.2). Group write is noise, not drift, when the wanted mode lets the group read (0664 from a tool writing under umask 002 where 0644 is wanted, 0775 where 0755 is wanted): git does not record it, so no capture could settle it. Apply leaves it until it writes new bytes. Any other bit outside the wanted one drifts: other write, an execute bit, group write on an owner-only file (0620 where 0600 is wanted) or on a file the owner may not write (0464 where 0444 is wanted), and group write on any target under `.ssh/` or `.gnupg/`, whatever its `mode` (ssh refuses a group-writable file there). One exception: a wanted mode with the owner's execute bit drifts when the live mode lacks it (0644 where 0755 is wanted), since the file stops running; 0750 there is not drift.

A file that matches a task's `outputs` glob (section 12.1) is generated: scan never reports it, capture and retag never take it, so it is never committed or gated. `yadm status` lists such files under `generated`.

### 8.3 Apply

1. Resolve the manifest for this machine; render each target in memory.
2. Skip a target whose bytes already match.
3. Hold a target whose current hash differs from the last written hash (`drifted`). Apply never overwrites it. The usual path captures it first. One exception: a `merge = "union"` target whose source changed too is merged, not held (see below).
4. Write changed targets atomically (temp file and rename), with the entry's mode. Copy the replaced bytes into `backup/` for 30 days. Apply never changes only the mode of a target whose mode is not drift (section 8.2: stricter, or group write only): it widens that mode only when it writes new bytes. When the entry's mode changes, apply sets the new mode on a target whose mode is still the one it last recorded.
5. Delete a target that left the plan, only if it is unchanged since written; otherwise hold it.
   A full apply then drops each hold that nothing covers any more: its target is not in the plan or the state, and no applying glob entry or owned root contains it. A `conflict` hold, a commit-gate hold (`check_failed`, `task_untrusted`: a track or retag may be about to cover its file, so it goes only with the file, section 10), a hold for weakened protection and a hold without a target stay.
6. On a non-member, skip sealed files (`sealed` action) and leave sealed values and regions out.
7. Run triggered tasks (section 12): path tasks, remove tasks, unit reloads and, once per machine, first-apply tasks.

A `merge = "union"` target can change here while a sync brings a new source, for example an append-only list appended on two machines before either committed. Apply then writes the line union instead of holding the target. The base is the source as last written (opened, for a sealed file on a member), ours is the new source and theirs is the target. The union keeps every line either side added, the source's lines first, then the lines only the target has; a line either side removed stays removed, and a line that appears twice is written once. The state still records the source as written, so the next scan finds the union as drift and capture commits it. The write follows the mode rules of section 8.2 and backs up the replaced bytes. The target is held as `drifted` when the union cannot be computed: binary content, a template or intra-file rules on the entry, or a last-written source that is gone or does not open. Without a source change, a local edit of a union target is ordinary drift for capture.

### 8.4 Capture

- **Verbatim file:** the target bytes become the source bytes.
- **Sealed file:** the target is sealed under the current epoch. Deterministic sealing makes an unchanged file a no-op.
- **Template:** capture recomputes the last render (source blob plus stored render Context, checked against the stored hash), diffs it against the target, applies the hunks to the template where their context matches verbatim, re-renders and accepts only if the result equals the target byte for byte. Otherwise the target is held (`rendered_edit`) and status reports it. Apply never re-renders over it. The hold names the template (`source`) and carries a proposed unified diff (`patch`). With `patch_of = "template"` it patches the template: a three-way merge of template and target over the last render, each conflict resolved to the target's lines, accepted only when it renders back to the target on this machine. An edit on an expression or a conditional block thus becomes literal text, so the agent reviews it before committing. When no such candidate exists, `patch_of = "render"` and the diff is the hand edit against the last render. An agent edits the template and commits in one step. An enclave template's hold carries no patch, because holds live in `state.json`, which never holds plaintext.
- **Intra-file rules:** package rules (section 6), with the seal guard.
- **New file under a glob entry** (section 4), named by `yadm commit` or `yadm track`: captured as a managed file of that entry with no previous source, so the entry's enclave, sealed values and regions apply. A non-member is held (`seal_guard`). A template glob holds the file (`uncapturable`): its template source is written by hand.
- **Deletion** of a managed target, committed by name (`yadm commit <path>`, or `yadm hold resolve <id> --take target` on its hold): the source file goes. When the target's applying entry names it literally (not a glob), its `[[file]]` table goes in the same commit, with its `[file.*]` sub-tables and the comment lines directly above it, so the manifest never names a missing source. A glob entry or an owned root keeps its definition. The commit is refused, with nothing committed, when another entry (on any machine) still reads that source, or when the edited manifest does not parse to the old entries minus exactly those tables or does not validate. Machines that had the target remove it on their next apply if it is unchanged there, and hold it otherwise (section 8.3). A deletion writes no content, so a sealed file's deletion never writes plaintext.
- **Every capture** passes the round-trip check: render(new source) = target. A failure is held as `uncapturable`, never committed.

### 8.5 Retag

`yadm retag <path> <type>[,<type>...] [--enclave <name>] [--source <source>] [--dry-run]` changes which machines get a target in one commit: the manifest entry's `when` and `enclave`, and the move between `files/` and `sealed/<enclave>/` with the content opened and resealed. Only a member of every enclave involved can retag. Machines that lose the target remove it on their next apply if it is unchanged there, and hold it otherwise. Retag is protected: it is a manual commit only. Its changes land together or not at all: when the gate holds the target, the manifest edit and the move are not committed either. On an unmanaged file in `$HOME` that no manifest entry names, retag tracks it: it appends an entry with the types' `when` (and the enclave) and commits the file's bytes as its source. A file a glob entry covers is refused. A file under an enclave root (in the manifest, applying here or not, or accepted here) is that enclave's plaintext: retag refuses it with exit 6 unless `--enclave` names that enclave.

- **Variants.** A target with several entries needs `--source` naming the entry's source (`files/…` or `sealed/<enclave>/…`); without it, retag fails with exit 2 and lists the sources. Retag refuses an edit that makes two entries for the target apply on one fleet machine (observed facts count as absent). When the picked entry does not apply on this machine, the live file is not its content, so the gate does not read it and the commit holds only source changes; such an entry can move into an enclave but not out of one.
- **Conditions.** Retag replaces only the type terms of `when` and keeps every other term: `type:work & os:darwin` retagged to `home` becomes `type:home & os:darwin`, and a `when` with no type term gains one (`os:darwin` becomes `type:home & os:darwin`). It works when the type terms form one top-level factor: a type term or a disjunction of type terms, joined to the rest by `&`. Any other shape (a type term under `!`, inside a `|` with other terms, in two factors, or inside a `cond:` name) is refused with exit 2 and nothing committed: edit the manifest by hand.
- **Moves.** A move to a source path that already exists, or that another entry or glob would read, is refused. Sealed content opens under the enclave's current epoch only, so a move never reseals content planted under an older key.

### 8.6 Track

`yadm track <path> [--when <condition>] [--enclave <name>] [--no-push]` starts syncing a file that nothing covers yet. Without `--when` and `--enclave`, a new file that an applying glob entry matches (section 4) is captured under that entry instead, as `yadm commit <path>` would: no manifest edit, and the output names the glob. It appends a `[[file]]` entry for the path to `manifest.toml`, with `when` and `enclave` when given, and adds the file's bytes as its source: `files/<target>`, or `sealed/<enclave>/<target>` sealed under the enclave's current epoch, so a non-member only ever receives ciphertext. Both changes land in one commit (subject `track <path>`) through the commit gate, or neither does: when the gate holds the file, nothing is committed. The commit is pushed in the same call; with `--no-push`, the next sync publishes it. The new `when` is checked against the fleet before anything is committed.

Track refuses, with exit 2 and nothing committed, a path that a manifest entry names or an owned root contains (the error says when no root may capture it either, section 4), a path a glob entry matches when `--when` or `--enclave` is given or the glob does not apply here (a second entry would collide), and a path two applying globs match (the error names which; `yadm retag` and `yadm commit` handle those), a path outside `$HOME`, a directory (share one with a `[[root]]`), and a path that is not a regular file. An `--enclave` that is not an enclave type fails; one this machine is not a member of is refused with exit 6.

### 8.7 Source move

`yadm source mv <old-source> <new-source> [--dry-run] [--no-push]` renames a source within its scope: `files/…` to `files/…`, or `sealed/<e>/…` to `sealed/<e>/…`. Paths are relative to the source root. Every literal entry that reads the old source gets its `source` line pointed at the new path; a new path that is the entry's default (`files/<target>` or `sealed/<e>/<target>`) drops the line instead. No other manifest line changes, comments included. The content moves with the path binding renewed: a sealed blob is opened under the old path and sealed under the new one with the enclave's current epoch, and sealed values and regions are rebound the same way, all in memory. The manifest edit, the old source's deletion and the new blob land in one protected commit (subject `move <old> to <new>`) through the normal commit path, and the commit is pushed; `--no-push` leaves it to the next sync. The content every target gets stays the same, so no machine rewrites a target.

It refuses, with exit 2 and nothing committed, a move between `files/` and `sealed/<e>/` (`yadm retag` changes who can read a file), an old source that no literal entry reads (an owned root's entry-less file) or that a glob entry reads, and a new source that exists, is a directory or sits under a file in the source tree, or that another entry or glob would read. A non-member of the enclave, or of an enclave whose sealed values or regions the file holds, is refused with exit 6.

### 8.8 Untrack

`yadm untrack <path> [--source <source>] [--dry-run] [--no-push]` stops syncing one entry. It removes the entry's `[[file]]` table, with its `[file.*]` sub-tables and the comment lines directly above it, and deletes its source, in one protected commit (subject `untrack <path>`) that is pushed; `--no-push` leaves it to the next sync. A source that another entry (on any machine) still reads stays, and the output says so (`source_kept`). The path is a target; a target with several entries needs `--source`, and a path under `files/` or `sealed/<e>/` that no entry names as its target picks the entry that reads that source.

The file stays on disk on this machine. When the entry applies here, this machine stops managing the target in the same step as the commit lands: its state record and holds go, and a file inside an owned root is recorded as ignored here (as `yadm hold ignore` does), so scan never reports it as new. Other machines remove an unchanged copy on their next apply and hold a changed one, as for any target that leaves the plan (section 8.3).

It refuses, with exit 2 and nothing committed, a path no literal entry names: a glob entry's or an owned root's file (commit its deletion with `yadm commit <path>`, or ignore it with `yadm hold ignore`). A non-member of the entry's enclave, or of an enclave whose sealed values or regions the file holds, is refused with exit 6. The commit carries no plaintext.

## 9. Commits

### 9.1 Private index

Every commit operation builds its own fresh index file in the state directory, seeded from the parent commit and holding only that operation's paths. The source clone's own index and worktree are never used to stage. Parallel agents and the timer never sweep each other's changes.

Every git call the tool runs against the source clone, `yadm git` included, sets `core.excludesFile` to an empty file. The manifest defines what the source holds, so the user's global ignore rules (`core.excludesFile` or `$XDG_CONFIG_HOME/git/ignore`) never hide a file there. A `.gitignore` in the source and `info/exclude` still apply.

### 9.2 Commit gate

Before any commit, manual or automatic, the gate runs every `[checks.<name>]` whose `paths` match a staged target, through the exec contract (section 12.4). The request lists the staged targets, the paths of 0600 temp files holding their plaintext, and the entry each target has once the commit lands (`entries`, section 12.4). The gate fails closed: a non-zero exit, a timeout, `ok: false`, a planned manifest that does not parse or a check this machine has not allowed holds the matching files with `check_failed`. Other files still commit. Verdicts are per file: when a check fails on several files at once, the gate runs it again on each of them alone (up to 50), and only the files that fail alone stay held.

Source changes that are not targets skip the gate: a key-log entry (signed tool output), the manifest edit of a retag, a track or a committed deletion, and every change of a source move, an untrack, or a retag of an entry that does not apply on this machine. They change no target's plaintext, and check `paths` name targets. They still commit under the sync lock, through a private index.

### 9.3 Auto-commit

The timer runs `yadm sync --auto`. A captured path auto-commits when all hold:

- its quiet period has passed since its last change, by mtime (entry `quiet`, default 2 min; `0s` commits at once);
- no live lease names it (`yadm lease take`, section 9.7; an expired lease protects nothing);
- the busy probe, if configured, does not name it;
- no open decision on it is deferred (`yadm defer`, section 9.7);
- it is not protected: `manifest.toml`, `fleet.toml`, `keys/**`, `conditions.include` files, manifest `protected` globs, entries with `review = true`, new files outside owned roots, files that were in an owned root when it was accepted here (held `protected` until committed by name), deletions, retags, and more than 50 changed files in one scope;
- the gate passes.

A new file inside an owned root accepted here is not protected: accepting the root accepts the new files in it, so the timer shares one after its quiet period. A hook's decision packet (section 9.7) is the chance to retag, ignore or defer it first; a deferred one stays held until it is settled.

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

`yadm commit [-m <subject> | --why <intent>] [--no-push] [--dry-run] [path...]` makes a manual commit and pushes it. It bypasses the quiet period and leases, never the gate or the seal guard. A source clone with local edits stops it before anything is committed, with a `source_dirty` hold. Protected paths commit only when named. A named managed file deleted in `$HOME` commits its deletion (section 8.4). A named file that predates its owned root is captured too. A named file with a deferred decision (section 9.7) is captured and committed, which settles the decision; a commit that does not name it leaves it held. A named new file that an applying glob entry matches is captured under that entry (section 4). A named path that no manifest entry, applying glob or owned root covers on this machine (the path itself, or anything under it) fails the whole commit, `--dry-run` included, before anything is captured; the error names the path and suggests `yadm retag`. With `--no-push`, the next sync pushes. When the push does not happen in this call (another process holds the network lock, or the remote kept moving), the commit stands, `push_error` says why, and the next sync pushes. With `--dry-run` it scans and captures but commits nothing; `planned` lists each commit it would make, with its scope, subject and paths, new files in owned roots included. The gate does not run in a dry run.

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
| `post-edit` | after a file write or edit tool | Records the path for the session. If the path is managed or inside an owned root and no live lease names it, commits it now through the gate, with `Yadm-Auto: hook` and `Yadm-Session`, locally; the next timer tick pushes it. Silent when clean; otherwise a decision packet. |
| `stop` | the agent (or a subagent) ends its turn | Commits the session's recorded paths that no live lease names, locally; the next timer tick pushes them. Blocks the stop while a decision this session caused is open, including a conflict the timer met while pushing them. |
| `session-start` | a session starts | A quick sync and a repair of a broken schedule (section 13), then at most 10 lines: the repair first, holds near the cwd, deferred decisions (one line: how many still wait and how many expired), live leases (one line: each holder, its paths and expiry), fleet drift. Unreviewed auto-commits are not counted there; `yadm review list` shows them on request. |

A hook commit is unattended: naming the path does not lift protection. A hook does not commit a new file in an owned root: it holds it (`protected`) and returns a decision packet, since which machines get it is the user's choice. If nobody decides and nobody defers it, the timer shares it after its quiet period (section 9.3). A hook waits at most a few seconds for the sync lock; if another process holds it, the path stays recorded and `stop` or the timer commits it.

A **lease** (`yadm lease take <path...> --holder <name> --ttl <duration>`) says an agent is mid-edit on those paths and commits them itself. A lease path is a glob or a directory. A lease lasts `--ttl`, at most 24h (a longer `--ttl` is capped), so a crashed or forgetful holder holds a path back for a day at most. Each holder has one lease: a repeat `take` by a live holder adds its paths to the lease and moves the expiry of all of them to the new TTL. `yadm lease release <holder>` ends the lease; `yadm lease release <holder> <path...>` drops only those paths, spelled as they were taken, and keeps the rest. While a live lease names a path, no hook commits it, raises a decision on it or blocks a stop on it, whoever holds the lease; the path stays recorded. A conflict, `seal_guard`, `secret_scan` or `root_untrusted` hold on a leased path is the exception: hooks raise it as usual. A lease on a new file in an owned root holds back its decision the same way. `stop` names each lease that held back one of its paths in its quiet output: `leased by <holder> until HH:MM`. The holder commits with `yadm commit <path>`, which bypasses leases (section 9.5). When the lease is released or expires, a path still pending commits as usual: through the next `post-edit` or `stop` that covers it, or the timer after its quiet period. An expired lease protects nothing. The holder is a free-form label: no hook compares it with a session or agent id, so a lease holds back every session's hooks, the holder's own included.

A **decision packet** says what happened, the diff size (line counts, never content), which machines and types the file reaches, a proposed fix, and two to five options, each with its consequence and the exact command. Packets cover a new file in an owned root (with the types its neighbours go to, and the options to share it, track it for those types with `yadm retag`, ignore it with `yadm hold ignore`, or defer it), a `rendered_edit` hold (with its patch for a shared template), a gate failure, a `seal_guard` hold, a conflict with an incoming change, and any other hold through its suggested commands.

"Decisions this session caused" are the open holds on the session's recorded paths (or on the owned roots that contain them), except plain drift, deferred ones and those on leased paths (a lease never holds back a conflict or secrecy hold). A subagent's stop considers only its own paths. `yadm defer <hold-id> --reason <why> [--for <duration>]` moves one to the review queue for a short wait: the hold stays and the file stays uncommitted, but the session may end. A defer lasts `--for`, 6h by default and at most 48h (a longer `--for` is capped). The agent stays responsible for settling the decision; the command's output says so and names the expiry. An expired defer that is not settled is an open decision again: the stop hook and `session-start` raise it, and `yadm check` warns on it. The timer still never commits it. While the hold is open, neither the timer's scan nor a hook or unnamed commit captures or commits the file; `yadm commit <path>` does. A new file's defer covers its path, so an edit does not raise the decision again; it ends when the file is committed by name, retagged with `yadm retag`, ignored with `yadm hold ignore`, or removed. Other defers cover their hold. Session records live under `hooks/` in the state directory as append-only lines (path, agent, tool), so parallel hooks never lose an update.

## 10. Sync

Two locks in the state directory serialize the processes of one machine. No process holds the sync lock while it waits on the network.

| Lock | File | Serializes | When it is held |
|---|---|---|---|
| sync lock | `lock` | Local writes: scan and capture, commits, replay, apply, publish, collectors, hold resolve, retag, enclave writes, the local allows (`task allow`, `root allow`, `protection allow`) | A command waits at most 30 s, then exits with code 4; a harness hook waits at most 3 s and leaves the work to the timer |
| network lock | `netlock` | Fetch, push and `git ls-remote` | Never waited on: a process that finds it held skips its network step, says so, and the next sync does it |

Each lock file holds its holder's record while held: pid, command (the binary name and subcommand words, no paths) and start time. The exit-4 error names the holder and how long it has held the lock. `yadm status` lists a lock held for more than 10 s and an active network backoff. A record whose pid is dead is ignored. No command waits without a bound; every git and external call has a timeout (3 min for a network call). Git runs in its own process group, and the whole group is killed at the deadline, so a stalled ssh child cannot keep a lock. Every commit goes through `sync.Commit`. `apply` and the local allows read `main` again once they hold the sync lock, since the process they waited for may have moved it.

A **quick sync** (`--quick`, and `--auto` unless `--full`) first runs a cheap check: a stat scan and `git ls-remote` of `main` and `refs/yadm/*`, compared with what the last full sync saw. It stops there unless the remote `main`, a reviewed ref or the pause ref moved, a target drifted, the last full sync is 15 minutes old, the last check is more than 3 minutes old (the machine slept or the timer stopped), or a fleet pause that held this machine has passed its deadline (section 10.1). The first run is always full. A tick where nothing moved costs one stat pass and one round trip. Peers' status refs move on every sync, so they do not trigger a full sync; the periodic one fetches them. When `git ls-remote` fails, the run stops and the quick check backs off: it does not reach the remote again for 1 minute, doubling per further failure up to 15 minutes. A remote that answers, or a full sync (wake, periodic, local drift), clears it. The quick check also runs in full when local `main` is ahead of the remote (a hook's commit, or a push that was skipped or rejected, waits for the timer to push it). The stat scan runs under the sync lock and `git ls-remote` under the network lock; when another process holds the network lock, the check stops there, since that process is syncing already.

A sync runs in three phases:

- **Fetch**, under the network lock and without the sync lock: step 4. It updates only remote-tracking refs, so local writers go on meanwhile. When the network lock is held, the fetch is skipped and the run replays onto the last fetched `origin/main`. When the fetch fails, the local steps still run (capture, auto-commit, collectors), and the run ends with the fetch error before step 5.
- **Local work**, under the sync lock: steps 1 to 3 and 5 to 8.
- **Push**, under the network lock, after the sync lock is released: step 9.

The steps:

1. Scan and capture.
2. With `--auto`, auto-commit by policy (section 9.3).
3. Run allowed collectors.
4. Fetch `main` and `refs/yadm/*` (the fetch phase, before step 1). The key-log and manifest guards compare the fetched source with the accepted remote `main` (below).
5. If local `main` is not an ancestor of `origin/main`, replay each local commit onto `origin/main` with `git merge-tree --write-tree`, in memory:
   - clean: `commit-tree` with the original message and trailers;
   - conflict on a sealed file this machine can open: open the three stages, merge them in memory (`textmerge.Merge3`), reseal, write the tree; a remaining conflict is held like any other;
   - other conflicts: the clean paths of the commit land, unless the commit changes `manifest.toml` (a track, a retag, a committed deletion): then none of its paths land, so a manifest edit never lands without the source changes it describes. Conflicted paths move to the local-only ref `refs/yadm/held/<machine>` and become `conflict` holds with all three stage blobs.
   Before a conflict is held, a ladder tries to resolve it in memory: a key-level merge for JSON, JSONC and TOML (edits to different keys never conflict; `volatile` keys keep this machine's value; one key changed differently on both sides fails), then the entry's `merge` policy (section 4). A rung that resolves a file records it in a `Yadm-Resolved` trailer.
   History stays linear. There is no autostash and no merge commit.
6. Compare-and-swap local `main`. Move the source worktree; if it has local edits, stop with a `source_dirty` hold (the tool never stashes). `main` moves only over a clean clone, checked while `HEAD` still names the old `main`, so the clone's index never falls behind `HEAD`. A clean clone at a commit yadm reached (a `yadm git commit` on `main`, for example) counts as clean. The hold's advice returns the clone to `HEAD`.
7. Apply.
8. Publish this machine's status record (section 11).
9. Release the sync lock. Under the network lock, push `main`, the status ref, the advanced reviewed refs, the notes ref and a pause or resume record written here that has not gone out, atomically. The refspecs are computed in step 8, under the sync lock. A local commit made between steps 8 and 9 goes out too, since it descends from the replayed `main`. Never force; the one forced push is `yadm reroot` (section 10.2). A rejection means the remote moved after the fetch; it is not an error. The run fetches, replays and pushes again, up to 5 more rounds with backoff, taking the sync lock again for each replay (when another process holds it, the run stops there and notes it); after that the next sync does it. When the network lock is held, the push is skipped and the next sync does it. After a push that moved `main`, run the nudge (section 12.5).

`sync` reports a skipped or rejected network step in `network`. Only a sync that fetched and whose push went out, or had nothing to push, counts as a full sync for the quick check and clears its backoff, so local `main` stays ahead and the next tick runs in full.

A manual commit, a hold resolve that commits, `retag`, `track` and the enclave commands run the same phases around their commit, in the same call: fetch first, then the commit and steps 3 and 5 to 8 under the sync lock, then step 9. A hook commit leaves the network to the next tick.

A fetched source whose key log rewrites, deletes or forks an entry, or holds an entry that does not parse, is refused before anything is applied: a `key-log` task hold and one alert, local `main` stays, and `main` is not pushed. A malformed entry never fails the sync itself.

A fetched `main` that does not descend from the accepted remote `main` is a history rewrite. Unless a verified re-root record announces it (section 10.2), it is refused the same way, with a `history-rewrite` hold and a `history_rewrite` alert; `yadm check` fails its `reroot` item. Nothing from the remote is applied and `main` is not pushed. The hold clears when the remote returns to a descendant of the accepted `main`.

A fetched manifest that weakens protection is refused the same way, with a `manifest-guard` hold: a target both sources plan loses its enclave, a seal key or regions, or a new or changed owned root covers a path the accepted source protects. The guard compares the last accepted remote with the fetched one, and refuses only what local `main` does not already run. `yadm protection allow <target>` or `yadm root allow <path>` names the refused source while the hold is open; the next sync takes it.

The accepted remote `main` lives in `remote-accepted` in the state directory. Only a fetched source that passes both guards moves it; a fetch never does. `init` records the `origin/main` of its clone, an empty remote included: the clone's own fetch is the trusted start. A machine with no record writes one before any fetch (a sync, a commit that pushes, a notes push): the `origin/main` it holds then, or local `main` when a `key-log` or `manifest-guard` hold is already open. A fetch that cannot record its start fails. A refusal therefore holds on every later sync, not only the first. There is no local override: `yadm hold resolve` does not settle these holds. A `key-log` hold clears when the remote drops the offending commits (history, not a revert, since entries never change in history). A `manifest-guard` hold clears through the allow above. A machine whose recorded start is itself bad has no other way out than a new `init`.

A hold on a managed target settles by itself when a complete scan finds the target back at what this machine last wrote or captured: its drift, failed capture or failed check no longer applies. A protected or commit-gate hold (`check_failed`, `task_untrusted`) on a file nothing manages, such as a new file in an owned root or a file a refused `track` named, settles when a complete scan finds the file gone: nothing is left to commit or check. While the file exists, the hold stays. Conflict holds and weakened-protection holds stay until resolved or allowed.

A conflict hold is settled with `yadm hold resolve <id>`: `--take target` (or `--take <file>`, written to the target first) commits this machine's file over the current source and pushes it; `--take source` drops the hold and rewrites the target from the source, backing up the replaced bytes.

A fetched commit that touches `sealed/<enclave>/` or `keys/<enclave>/` from a machine (by `Machine:` trailer) that is not a member of that enclave is applied and reported through the notify hook. The trailer is not authenticated; key-log changes are, by signature.

### 10.1 Fleet pause

`yadm pause` holds sync on every other machine for a bounded time, so one machine can make a change that touches the whole fleet while no peer commits, applies or pushes half of it.

**Flow.**

1. The initiator writes a signed pause record and pushes it: `yadm pause [--for 30m] [--reason R] [--wait 2m | --no-wait]`. It prints progress while peers confirm (`waiting… 1/2 confirmed (host-c not yet)`), then `paused fleet-wide until 22:41 (30m); resumes automatically`. A peer that has not confirmed when the wait ends does not block the initiator; it pauses on its next sync if the pause is still on.
2. Every other machine's sync still fetches, so it sees a resume or an extension. It skips scan and capture, auto-commit, collectors, replay and apply, and pushes only its status ref. The status record carries `paused_until` and `pause_id`: that is the confirmation.
3. On a held machine, `commit`, `apply`, `capture`, `hold resolve`, `protection allow`, `root allow` and every other command that commits through `sync.Commit` (track, retag, source mv, untrack, the enclave writes) refuse with exit 4 (`locked`), like a held sync lock: retry later. The message names the initiator, the reason and the deadline. A dry run still works. A harness hook leaves its paths recorded and returns a quiet verdict, and the timer commits them after the pause.
4. The initiator is not held. Its commits proceed and push as usual; peers apply them when they resume.
5. Every machine resumes by itself at the deadline, by its own clock, offline included. The quick check runs a full sync once a pause that held this machine has passed its deadline. A lost initiator can therefore hold the fleet at most 4 hours.

`yadm resume [pause-id]` lifts a pause early. `yadm pause --for X` on the initiator while its pause holds extends it: the new deadline is the later of the current one and now + X. `yadm status`, `yadm check` and `yadm fleet list` show the pause.

**Record.** The pause ref `refs/yadm/pause` is a chain of commits whose tree holds one `<id>.json` per pause, the latest record of that pause:

```json
{ "schema": 1, "op": "pause", "id": "p-1a2b3c4d5e6f", "initiator": "m-a1b2c3",
  "reason": "rename shell config", "created": "2030-01-01T12:00:00Z",
  "deadline": "2030-01-01T12:30:00Z", "signer": "m-a1b2c3", "sig": "<base64>" }
```

A resume is the same record with `op = "resume"` and its own signer. Why a dedicated ref, not a protected file in `main`:

- Sync already fetches `refs/yadm/*`, so every machine sees it without a new fetch path.
- It is not in `main`, so it never auto-commits, never passes the commit gate and is never applied. A held machine does not move `main`, yet it still reads the latest record.
- A protected file in `main` would reach a held machine only through the replay and apply the pause stops.
- One file per pause means a resume of one pause never hides another.

The writer builds on the fetched ref and pushes fast-forward, never forced; a rejected push is redone on the new remote head. A write drops records that can hold no one for a day. A record that could not go out (the network lock stayed busy, or the remote was offline) stays on the local ref and the next sync pushes it; when the remote ref moved meanwhile, the sync carries the record onto it. `yadm pause` without `--for` on a running pause changes nothing on a remote that holds it, pushes it again when it never went out, and waits for confirmations again.

**Trust.** A pause must reach every machine in the fleet, including machines in no enclave; a machine that ignores it keeps writing while the rest waits, which defeats the pause.

| Item | Choice |
|---|---|
| Key | The machine's Ed25519 signing key, the one its key-log entries carry as `sign_key`. Every machine signs its pause and resume records. |
| Domain | The signed message is `"yadm v1 statement pause\n"` followed by the canonical JSON of the record with `sig` empty. A key-log entry is signed over its bare TOML, so no signature is valid as both. |
| Accepted | A well-formed record whose signer is a machine in `fleet.toml` at this machine's local `main`. A record from any other id is ignored. |
| Verified | The signer is a member of the head of a key log this machine has pinned and verified, and the signature verifies under that member's key. `status`, `check` and `fleet list` show whether a pause is verified. |
| Unverified | A signer that no pinned log lists, or a record without a signature. It counts like a verified one. |
| Forged | A signature that fails under every pinned key of the signer it names. The record is ignored and `check` fails. |
| Pause | Signed by its initiator (`signer = initiator`). Only the initiator extends it; an unverified record never extends a verified pause. |
| Resume | Any machine in `fleet.toml` may resume, so a pause whose initiator is lost can end early. A deadline needs no record: each machine applies it by its own clock. |
| Switch | `pause_requires = "member"` in `fleet.toml` makes an unverified record count for nothing, and `yadm pause` and `yadm resume` refuse on a machine that no pinned log lists. The default is off. |

Why accepting unverified pauses is acceptable for now:

- A repository writer can already run code on every machine: the source ships scripts and tasks that machines apply and run. A pinned-member signature on a pause would not stop that writer.
- The cap bounds a hostile pause: it holds a machine at most 4 hours in a row, chained pauses included, and every machine resumes by its own clock.
- `check`, `status` and `fleet list` show an unverified pause, so it does not pass unnoticed.

Once a fleet-wide enclave is the norm, `pause_requires = "member"` turns the signature into the requirement.

A record that does not count is ignored. It appears in `pause_ignored` in the status record, in `yadm status`, and as a failing `pause` item in `yadm check`, until its claimed deadline passes. A machine reads at most 64 records of at most 4 KiB from the ref, reports at most 16 ignored records, and never fails a sync over the pause ref: a ref it cannot read is reported the same way.

**Bounds.** Local state in the state directory (`pause.json`) is the authority. Each accepted record merges into it: the first time this machine saw the pause, the latest signed deadline, and whether a signed resume lifted it. A machine resumes at

```
min(signed deadline, created + 4h, first seen here + min(deadline - created, 4h), end of the hold run)
```

- The 4-hour cap holds whatever the record asks; `yadm pause` itself clamps a longer request and says so. An extension keeps `created`, so it never passes the cap.
- `first seen + span` bounds a record whose `created` lies in the future (the initiator's clock runs ahead): a 30-minute pause holds 30 minutes here, whatever the skew.
- A hold run starts when a pause first holds this machine and ends at the first evaluation that finds none holding. A pause first seen during a run ends with it, at most 4 hours after the run began. Chained pauses therefore hold a machine at most 4 hours in a row; then one sync runs unheld, replays `main` and takes any change to `fleet.toml` and the key logs before a newer pause can hold it.
- A pause whose window ended before this machine saw it is a no-op: a machine that slept through it never holds.
- A lifted pause stays lifted, so a replayed pause record does not hold the machine again. A shorter deadline for a known pause is ignored. A ref that a writer rewinds, deletes or fills with garbage changes nothing already accepted.
- A writer can replay a signed record a machine has not seen yet. It holds that machine at most until the cap from the record's creation.
- When two machines pause at the same time, each holds the rest of the fleet, but only the earlier pause (by `created`, then id) holds the other initiator. The later initiator is held like any peer.
- A pause record never replaces a resume of the same pause on the ref. A write that the remote moved past is carried onto the new remote head by the next sync, unless the remote already holds a resume or a later record of that pause.

### 10.2 Re-root

`yadm reroot` replaces the shared history on purpose: a `git filter-repo` purge of old plaintext, or one squashed commit after the fleet moved its secrets into enclaves. Every machine switches on its next sync; none needs a new clone.

**Flow on the initiator.**

1. Decide which machines back up the old history: set `reroot_keep` on their types in `fleet.toml` and let every machine sync. Without it no machine backs up.
2. Review the queue (`yadm review list`). The re-root marks the new head reviewed for every scope, so it refuses while commits are unreviewed, unless `--fold-unreviewed` is given.
3. Pause the fleet (section 10.1). `yadm reroot` starts a pause when this machine runs none.
4. Sync, so local `main` is the remote `main` and this machine accepted it.
5. Prepare the rewritten history in the source clone and leave `keys/` untouched: a squash (`yadm git commit-tree -m "new root" "main^{tree}"`) or a `git filter-repo` run on a copy, fetched back as a branch.
6. `yadm reroot --new-head <commit-or-ref> [--reason R]`. It checks, before any pause starts, that the new head is a rewritten commit (neither in the remote `main`'s history nor descended from it), that every key-log file is byte-identical between the old and the new head, that the new manifest passes the guard of section 10 against the old one, and that this machine is a member of a key log it pinned. It signs a re-root record and pushes, in one atomic push, `main` to the new head with a lease on the old one, every reviewed ref to the new head with a lease on its remote value (also one whose scope `fleet.toml` no longer names, so no ref keeps the old history reachable), and the record. Then it switches this machine through a normal sync and waits for peers (`--wait`, `--no-wait`).
7. Wait until `yadm fleet list` shows every machine `rerooted <id>`. A held peer switches during the pause; an offline one on its next sync.
8. `yadm resume`.

**Record.** The re-root ref `refs/yadm/reroot` is a chain of commits whose tree holds one `<id>.json` per re-root, the newest 16 kept:

```json
{ "schema": 1, "id": "r-1a2b3c4d5e6f", "initiator": "m-a1b2c3", "reason": "purge old history",
  "created": "2030-01-01T12:00:00Z", "old_head": "<commit>", "new_head": "<commit>",
  "pause_id": "p-…", "signer": "m-a1b2c3", "sig": "<base64>" }
```

The signed message is `"yadm v1 statement reroot\n"` and the canonical JSON with `sig` empty. A machine reads at most 64 records of at most 4 KiB, as for the pause ref. Records do not expire: a machine offline for days still finds the one that leads to the remote it fetches.

**Trust.** It mirrors the pause (section 10.1): the signer is the initiator, a machine in `fleet.toml` at this machine's local `main`, signing with the key its key-log entries carry. Unlike a pause, only a verified record counts: the signer must be a member of the head of a key log this machine pinned, and the signature must verify under that member's key. An unsigned record, a signer no pinned log lists, and a forged signature are refused and named in the `history-rewrite` hold.

Why a re-root requires what a pause does not:

- A pause is bounded and undone by the clock. A re-root replaces the history every machine builds on and cannot be undone by waiting.
- An unverified re-root would let any writer, with no member key, rewind or replace the shared history on every machine. The append-only key-log rule and the accepted-remote base exist to stop exactly that.
- A machine whose pins list no member cannot verify any record, so it never switches; it keeps refusing the rewritten remote and needs a new `init`. A fleet-wide enclave gives every machine a log to pin.

**Switch on a peer.** When the fetched `main` does not descend from the accepted one, sync takes the newest record that verifies, whose new head the fetched `main` contains, whose new head is not already in the accepted history (a replay changes nothing), whose signed creation time is after the floor (the time this machine joined, recorded by `init`, and the newest re-root it already runs: one it switched to, or a verified record whose new head the accepted history holds), and whose old head, when this machine has that commit, descends from the accepted `main`. The floor refuses an older record a writer replays to a machine that lacks its old head, even when the writer strips newer records from the fetched ref. The initiator refuses to sign while its clock is not after its own floor, since every machine would refuse the record. A machine held by a pause takes only a record its initiator signed. Then:

1. Local commits that are not in the old head (or, without that commit, not in the accepted `main`) block the switch with a `reroot` hold. Nothing is dropped. `yadm reroot carry` keeps them on the local-only ref `refs/yadm/carry/<id>`, replays them onto the new head as step 5 of section 10 replays any local commit (a conflict becomes a hold), switches and pushes.
2. Every key-log file of the old head must be byte-identical at the new head, with none added, and every entry the accepted `main` had must be there unchanged. Otherwise the switch is held. After the switch, the key logs load against the pins as on every sync.
3. The manifest guard of section 10 judges the new head against local `main`.
4. A machine whose types set `reroot_keep` (the largest value among its types, read from the `fleet.toml` it ran before the switch; absent or 0 means none) writes `git bundle create --all` of its source clone to `$XDG_DATA_HOME/yadm/backups/<UTC time>-<old head>.bundle`, mode 0600 in a 0700 directory, and keeps the newest `reroot_keep`. A failed backup holds the switch; a run that stopped after its backup reuses it. The initiator writes its backup before it pushes, so a failed backup there pushes nothing. Pruning never deletes the bundle just written. `yadm backups list` and `yadm backups prune [--keep N]` manage them.
5. Local `main` moves to the new head over a clean clone (step 6 of section 10). A local reviewed ref that points into the old history takes the fetched one when it is in the new history, and is dropped otherwise. A fetched ref past the new head that skips commits of the scope is not taken: the local ref moves to the new head, so no writer's commit leaves this machine's queue.
6. `reroot.json` records the switch, and then the new head becomes the accepted remote `main`, last, so a run that stops halfway finds the same record and goes on. The status record carries the switch's id as `reroot`.
7. The normal guards run on the commits after the new head, and apply follows. While a rewrite is pending, auto-commit waits, so a machine that wakes with local edits does not commit them onto the old history; it captures them again after the switch and commits them on the new one. When the new tree equals the old one (a squash), no target changes; otherwise apply writes the difference as for any fetch.

**What a backup holds.** A bundle is the old history as this machine's clone held it, refs and objects. It holds no enclave plaintext beyond what that history held: sealed files there are ciphertext. If the rewrite purged plaintext that the old history stored, the bundle still holds it; keep `reroot_keep` at 0 on machines that must not keep it, and prune or delete bundles once they are not needed. The old objects also stay in each clone's object store until git's reflog expiry and garbage collection remove them.

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
  "tasks": [ { "task": "package-bundle", "trigger": "paths", "commit": "…", "exit_code": 0, "duration_ns": 1200000000 } ],
  "on_demand": ["work"],
  "home": "/home/user",
  "user": "user",
  "paused_until": "2030-01-01T12:30:00Z",
  "pause_id": "p-1a2b3c4d5e6f",
  "pause_verified": true,
  "pause_ignored": [ { "id": "p-…", "why": "signer is not trusted: m-… is not a machine in fleet.toml" } ],
  "reroot": "r-1a2b3c4d5e6f",
  "reroot_held": "reroot"
}
```

`paused_until` and `pause_id` confirm a fleet pause the machine honours, `pause_verified` says a pinned key-log member signed it, and `pause_ignored` lists pause records it did not accept (section 10.1). A change to either publishes a record at once. Both are self-reported, so a confirmation is advisory: the initiator learns who says it paused, not who did.

`reroot` is the last re-root the machine switched to, the confirmation `yadm reroot` waits for; `reroot_held` names the hold (`history-rewrite` or `reroot`) that keeps it from taking a rewritten remote (section 10.2). A change to either publishes a record at once.

`home` and `user` are the machine's `$HOME` and user name, the values its templates render `{{ home }}` and `{{ user }}` with. Only `yadm show --as` reads them (section 7.6). A change to either publishes a record on the next sync. They are plain: every machine that fetches the remote sees each machine's account name.

`on_demand` lists the enclaves the machine reads on demand only (section 7.6). It is self-reported: `yadm check` uses it to explain a key-log member without the enclave's type, and a change to it publishes a record on the next sync.

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
on         = [".config/packages/list"]   # a matching target was written or taken over
on_remove  = []                          # a matching target was removed
first_apply = false                      # run on this machine's first apply
when       = "os:darwin"
command    = ["pkg-tool", "bundle", "--file", ".config/packages/list"]
timeout    = "10m"
```

- Triggers: `on` (target written, or taken over by adopt or the first apply), `on_remove` (target removed), `first_apply` (the first apply after `init` or `adopt`), `on_fact` (a listed input changed on this machine: a collector name for its observed items, or `fact:KEY` for a declared fact) and `on_render = true` (the render context changed: this machine's types, declared and observed facts, or the fleet file).
- `on_fact` and `on_render` compare fingerprints (hashes, never values) of the inputs with what the task last ran against, kept per task in state. A task with no record runs once. A held task records nothing, so the change still runs it once it is allowed; a failed run records, as a failed path task does not retry. Only a full apply checks inputs; adopt runs path tasks only, and records the inputs of each task it ran. The trigger is named `fact` or `render` in the result.
- `outputs` lists target globs the task writes. They are generated (section 8.2). A managed target that matches one fails the resolve. Adding these fields to a definition changes its hash, so it needs a new allow; a definition without them keeps the hash it had.
- A task runs once per apply, after all writes, with the matched targets in its request.
- A failed task is recorded in state and the status ref, reported through notify, and never stops other tasks or the sync.
- **Units** are a built-in task: apply reloads a launchd agent (`launchctl bootout` and `bootstrap`) or a systemd user unit (`daemon-reload`, then restart) only when its bytes changed. A reload needs no allow entry: the unit file is managed content, and the service manager runs it at the next login whether or not apply reloads it. With `reload = "never"` a unit is never reloaded. On `auto`, the launchd reloader also skips a job whose plist sets `KeepAlive`, the job that runs the reload (`$XPC_SERVICE_NAME`), and a plist it cannot read as XML. A skip is recorded in the task result detail, not as a failure.
- **Takeover.** Adopt, and apply while the first apply is open, take over a target with no state record whose bytes already match. Nothing is written, but an `on` task that matches it runs once, as if the target had changed. The target is then in state, so a later identical apply fires nothing. A task not allowed is held as usual, and a later allow does not replay the takeover. A first-apply task that already ran at this commit for another trigger does not run again for `first_apply`.
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

- A check's request adds `staged` and `entries`, keyed by target. `staged` maps a target to a 0600 temp file holding its plaintext; the file is removed when the check returns. `entries` gives the manifest entry the target has once the commit lands, read from the planned manifest, so the entry a `track` or `retag` adds in the same commit counts:

  ```json
  { "kind": "check", "changed": [".config/app/token"],
    "staged": { ".config/app/token": "<state>/yadm-check-1/0" },
    "entries": { ".config/app/token": { "target": ".config/app/token", "source": "sealed/personal/.config/app/token", "when": "type:personal", "enclave": "personal" } } }
  ```

  `target` is the entry's target: the path, or the glob that covers it. `when` is the condition as written, true here or not; `""` means every machine, and `enclave` `""` means plaintext. A file in an owned root gets `"root": true` and the root's path, `when` and `enclave`. A target that no entry or owned root covers has no key. `entries` holds manifest fields only, never file content. A check judges the commit from it, not from `yadm why`, which reads the committed source.

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

On macOS the job's stdout and stderr go to `schedule.log` in the state directory, created with mode 0600. Each `sync --auto` writes one timestamped line there. A run that finds the log larger than 512 KiB first moves it to `schedule.log.1`, replacing the older copy, and creates a new 0600 log. An installed job keeps the output path its plist names until `yadm schedule install` rewrites it. On Linux the journal keeps the output.

**Health.** A managed Mac can attach a launch constraint to the job that pins the binary. After an upgrade replaces the binary, launchd refuses every run with exit 78 (`EX_CONFIG`) and marks the job `needs LWCR update`, while the job still shows as loaded. The binary never starts, so the log stays empty; the status fields are the evidence. `schedule status` reads `launchctl print` for the job's run count, last exit code and that flag, and on Linux the service's last result and exit status. Each `sync --auto` records its start time in `schedule-run` in the state directory; on macOS that is the schedule's last run.

- `yadm check` fails the `schedule` check when the job is not loaded, when its last exit is 78, or when launchd flags the constraint. Its message names the fix, `yadm schedule install`, which is also in `next`. It warns when the last scheduled run started more than 5 intervals ago.
- A `yadm sync` run by hand (not `--auto`, not `--dry-run`) and the `session-start` hook reinstall a schedule in that state themselves, after their own sync, and say so in one line. They try at most once an hour, recorded in `schedule-heal` in the state directory, whether or not the install succeeds. A scheduled run never reinstalls its own job, and a schedule that is not installed is left alone.

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
| 4 | `locked` | Another yadm process has held the sync lock past the wait (section 10); the message names its pid, command and age. Or another machine's fleet pause holds this one (section 10.1); the message names the initiator, the reason and the deadline. Retry later |
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
| `machine` | This machine; the text lists each enclave as `member`, `member (on demand)`, `not a member` or `refused` | the fleet `Machine` plus `observed`, `enclaves` (opened, refused, other, on_demand), and `recipient` and `sign_key` when the machine has identity keys |
| `why <path>` | Manifest explanation | `{target, managed, resolved, rejected[], protected, in_root, when_expanded?}` |
| `manifest [--as <m> \| --fleet]` | Resolved manifest per machine (section 4) | `{schema, commit, outputs[], machines[{machine, name, types, observed, error?, entries[], roots[], tasks[]}]}` |
| `eval <cond> [--as <m>]` | Evaluate a condition (section 5.1) | `{schema, machine, name, condition, expanded, names[], result, observed, unavailable[], note?}` |
| `managed <path>` | Is it managed here | `{target, managed, scope, source}` |
| `explain <command>` | Steps the command would take here | `{steps[]}` |
| `init <remote> --machine <m>` | Clone, write `machine.toml`, create identity, install schedule | `{machine, recipient, sign_key, source}` |
| `status` | Drift, holds, ahead/behind, last sync, locks held over 10 s, network backoff, fleet pause, re-root | `{machine, applied, ahead, behind, drift[], holds[], last_sync, generated[]?, locks[{lock, holder{pid, command, since}}]?, net_backoff_until?, pause?{held?, own?, ignored[]?, confirmations?}, reroot?{last?, held?}}` |
| `apply [--dry-run] [path…]` | Write changed targets | `{commit, actions[], holds[], tasks[]}` |
| `capture [path…]` | Capture without committing | `{paths[], holds[]}` |
| `diff [path…]` | Plaintext diff target vs source | `{files[{target, diff, skipped?}]}` |
| `show <path> [--as <m>] [--source]` | Print a target as machine `m` (default this one) receives it, or with `--source` its source unrendered, to stdout only; opens on-demand enclaves (section 7.6) | `{machine, name, target, source, enclave?, content, encoding, home_from, view?}`; without `--json`, the bytes alone |
| `commit [-m\|--why] [--no-push] [--dry-run] [path…]` | Gate, commit and push now | `{commits[], holds[], pushed, push_error?, planned[{scope, subject, paths[]}]?}`; `planned` only with `--dry-run` |
| `sync [--auto] [--quick] [--full] [--no-push]` | Section 10; without `--auto`, also repairs a broken schedule (section 13) | `{captured[], committed[], fetched, replayed, applied, pushed, retries, holds[], alerts[], tasks[], skipped, reason, network?, schedule_healed?, paused?, pause?}` |
| `pause [--for <d>] [--reason <r>] [--wait <d> \| --no-wait]` | Section 10.1: sign and push a fleet pause, or extend this machine's own, then wait for peers to confirm | `{id, initiator, reason?, created, until, requested, clamped?, extended?, pushed, push_error?, confirmed[], waiting[], ignored[]?}` |
| `resume [pause-id]` | Section 10.1: sign and push a resume | the same, with `resumed`; `{resumed: false}` when no pause holds |
| `reroot --new-head <commit-or-ref> [--reason <r>] [--fold-unreviewed] [--for <d>] [--wait <d> \| --no-wait]` | Section 10.2: check, start a pause when none runs, sign and push the rewrite, switch here, wait for peers | `{id, old_head, new_head, reason?, pause_id, pause_started?, pushed, backup?, unreviewed?, switched[], waiting[], held[]?}` |
| `reroot carry` | Section 10.2: replay unpushed commits onto a re-rooted history, switch and push | `{reroot, sync}` |
| `backups list` / `prune [--keep N]` | Section 10.2: re-root bundles, newest first; prune keeps `reroot_keep` of this machine's types, or 3 | `{dir, keep, bundles[]}` / `{dir, keep, deleted[]}` |
| `log [path]` | History, plaintext where openable; each commit's review note | `{commits[{…, note?}]}` |
| `retag <path> <types> [--enclave <e>] [--source <s>] [--dry-run]` | Section 8.5; commits through the gate and pushes | `{commit, source, when, removed_on[], holds[]}` |
| `track <path> [--when <cond>] [--enclave <e>] [--no-push]` | Section 8.6; commits through the gate and pushes | `{target, source, scope, commit, pushed, holds[], push_error?, glob?}`; `glob` names the entry a new file was captured under |
| `source mv <old> <new> [--dry-run] [--no-push]` | Section 8.7; commits and pushes | `{from, to, targets[], scope, commit, pushed, push_error?}` |
| `untrack <path> [--source <s>] [--dry-run] [--no-push]` | Section 8.8; commits and pushes; the file stays here | `{target, source, scope, source_kept, commit, pushed, push_error?}` |
| `bisect --as <m> -- <cmd>` | Sandbox bisect | `{first_bad}` |
| `collect` | Run collectors now | `{observed{}, skipped[]}` |
| `check` | Self-check | `{checks[{name, ok, warn?, detail}]}`: identity keys and modes, key logs vs pins, fleet vs key-log membership with each member's role (section 7.6), on-demand names, manifest collisions, schedule loaded and runnable (section 13), last sync age, the fleet pause (failed for an ignored pause record, warned while held, naming whether the pause is verified), the re-root (failed while a `history-rewrite` or `reroot` hold is open), holds, one `deferred` warning per expired defer that is not settled (section 9.7), one passing `lease` item per live lease with its holder, paths and expiry (warned when it expires more than 24h from now), secrecy config. `warn` marks a check that passes but needs a look. |
| `fleet list` / `show <m>` / `diff <collector>` | Section 11 | statuses / one machine / `ObservedDiff`; rows carry `sealed_observed` on a member |
| `enclave list` / `create` / `add` / `remove --confirm` / `join --code` (or `--expect`) / `verify` / `retire` / `set-recovery` | Section 7.3; `remove` also retires old epochs once its reseal commit lands | key-log heads and members; `list` rows carry `on_demand`; `add` carries `keys_from`; `remove` is refused for an on-demand enclave (section 7.6) |
| `enclave new-recovery <dir> [--enclave <type>]` | Section 7.3: a recovery identity for a creator elsewhere; needs no init | `{dir, recipient, sign_key, create}` |
| `enclave on-demand <enclave> [--off]` | Section 7.6: edits `on_demand` in `machine.toml`; the next apply takes effect | `{enclave, on_demand, machine_toml}` |
| `protection allow <target>` / `root allow <path>` | Local allows (section 12.3), then apply | `{allowed, apply}` |
| `review list` / `ok` / `revert` / `note <commit> --why <text> \| --paths-only [--seal <e>] [--no-push]` | Section 9.6 | `{items[{commit, scope, diff, note?}], deferred[]}`; note: `{note, pushed, push_error?}` |
| `hold list` / `show <id>` / `resolve <id> --take source\|target\|<file>` / `ignore <id>` | Holds; a take that captures commits and pushes; `ignore` leaves an unmanaged file in an owned root untracked on this machine | hold objects |
| `hook post-edit` / `stop` / `session-start` | Section 9.7; harness JSON on stdin | a verdict (`docs/hooks.md`) |
| `defer <hold-id> --reason <why> [--for <duration>]` | Move a decision to the review queue for a short wait (section 9.7) | the deferred record with `until`, and `note` |
| `lease take` / `release` / `list` | Leases | leases |
| `task list` / `allow` / `run <name>` | Section 12 | definitions with allowed state, results |
| `schedule install` / `uninstall` / `status` | Section 13 | `{installed, loaded, last_run, unit_path, last_exit?, runs?, needs_constraint_update?, last_result?, log?}`: `last_exit` is the job's last exit status (absent before its first exit), `runs` launchd's start count, `needs_constraint_update` launchd's `needs LWCR update` flag, `last_result` systemd's service result, `log` the launchd job's output file |
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

Sealing creates each enclave's key log, signed by the importing machine, on top of that commit. Once it is committed, the importing machine pins it in its state directory, so it needs no `enclave join`; the report still prints each fingerprint for the other machines, which join with `--expect`. An existing different pin for that enclave is kept, and the report says to join after switching repositories. A failed import pins nothing.

### 15.2 Adopt

`yadm adopt [--dry-run] [--allow-tasks] [--no-schedule]` switches one machine to this tool:

1. Verify the identity and that the source clone resolves for this machine.
2. Materialize links another tool left: a directory symlink above a target that points into `$HOME` becomes a real directory holding a copy of what it pointed to.
3. For each target: identical bytes are recorded in state without writing (`adopt`); a missing target is written; a differing target is held (`drifted`) for the user to resolve. Nothing is overwritten. A target that is a symlink to a file with the rendered bytes becomes a regular file with those bytes, and a read-only file with the rendered bytes (a 0444 render) takes the entry's mode. A symlink with other content is held.
4. Install the schedule.

Adopt runs path tasks only: each allowed `on` task that matches a target adopt took over (adopted, written or materialized) runs once (section 12.1). It runs no unit reload, `on_remove`, input or first-apply task; first-apply tasks run on the first apply after adopt. `--allow-tasks` records the allows before adopt runs tasks. Adopt never changes or removes what a link pointed to, and leaves any other dotfiles tool installed, so the user can roll back.

## 16. Threat model

- Every machine can push. A non-member is a writer, not only a reader.
- An enclave protects against reading. A non-member can still delete or roll back sealed files, edit shared scripts members run, or forge a `Machine:` trailer. The notify hook reports non-member commits that touch an enclave; members see them in review.
- A machine's first pin comes from a value a human carries out of band. The short join code is 40 bits behind a memory-hard KDF; a writer that grinds a forged log against it pays one argon2id run per guess (section 7.2).
- Key-log changes are signed and chained, so a writer cannot add itself or substitute a key. Key commitments stop a signer from swapping an earlier epoch's key. Key-log files are append-only in history, so a removed member cannot replace an entry for a machine that has not pinned the removal.
- A writer can move or swap sealed blobs, values and regions; each is bound to its path and key, so a moved one fails to open and is held. Sealed observed facts are the exception: they are bound to their enclave and epoch, not to a machine, so a writer can copy them between status refs (section 11).
- Task, check and collector definitions run only after a local allow. So do a manifest change that weakens a target's protection (enclave, seals, regions, an explicit mode, or the machine-local keys of `keep`, `drop` and `volatile`) and a new or changed owned root.
- A writer can push `refs/yadm/reviewed/<scope>`. A machine never takes a fetched reviewed ref that skips commits it has not reviewed.
- A writer chooses target names. Suggested commands shell-quote them, and names with control characters are held.
- The recovery identity signs only `recover` and `set-recovery`. A leaked recovery key is replaced with `set-recovery`.
- A 0600 key file is readable by every process of the user. An enclave separates machines, not processes on one machine. The tool loads identity files only as regular files (no symlink) owned by the user, in a state directory with no group or other access.
- An on-demand member (section 7.6) holds the enclave's keys like any member. The setting keeps plaintext off its disk; it does not limit what the machine can read or seal. A compromised on-demand member exposes the enclave as any member would, and its removal follows the same steps. Its `on_demand` claim in the status record is self-reported, and a writer can forge it, as it can the published `home` and `user` that `show --as` renders with; `yadm check` treats it as an explanation for a missing type, never as proof. The pinned key log is what proves which machines hold an enclave's keys.
- A writer can start or lift a fleet pause by writing an unverified record under the id of any machine in `fleet.toml`, unless `fleet.toml` sets `pause_requires = "member"` (section 10.1). It cannot forge a verified one, and an unverified record never extends a verified pause. A pause holds a machine at most 4 hours in a row, chained pauses included, and every machine resumes by its own clock. `check`, `status` and `fleet list` show an unverified pause. The pause reason is plain text every machine reads. A writer can also hide a pause: it can overwrite or delete a record on the ref before a machine fetches it, and that machine then never holds.
- A writer can force-push a rewritten `main`. Every machine refuses it unless a re-root record verified by a pinned key-log member announces it (section 10.2), and even then a rewrite that changes a key-log file is held. A member key can therefore replace the history, but not the key logs, and a machine with unpushed commits never loses them. Re-root backups hold the old history, ciphertext included, outside the state directory.
- A removed machine keeps everything up to its removal. It cannot plant content under its old keys: new sealed content opens only under the current epoch, and `retire` refuses old epochs for delivery for good. Its local backups of the enclave are deleted on the first apply after the removal.

## 17. Dependencies

Pinned in `go.mod`; `go 1.25` minimum. Each was fetched and exercised (`internal/crypt/deps_test.go`, `internal/rules/deps_test.go`), and the module cross-builds with `CGO_ENABLED=0` for linux/arm64.

| Module | Version | Use | Why |
|---|---|---|---|
| `filippo.io/age` | v1.3.2 | Wrap epoch keys to member recipients | Reference implementation of age; X25519 recipients; stable. |
| `github.com/tink-crypto/tink-go/v2` | v2.9.0 | AES-SIV (`daead/subtle`) | Maintained, audited deterministic AEAD; we do not implement SIV. Pulls `google.golang.org/protobuf` transitively. |
| `golang.org/x/crypto` | v0.55.0 | argon2id for the join code (section 7.2); `internal/crypt/joincode_test.go` pins its output | Go-team maintained; already required by `age`. |
| Go standard library | | HKDF (`crypto/hkdf`), Ed25519, SHA-256 | No extra dependency. |
| `github.com/pelletier/go-toml/v2` | v2.4.3 | Parse fleet and manifest; `unstable` parser with comments for the TOML span editor | Only Go TOML parser that exposes a comment-preserving AST. Expression ranges are empty for key-values, so spans come from child nodes. |
| `github.com/tidwall/sjson` (+ `gjson`) | v1.2.10 | Test only: `internal/rules/deps_test.go` records why rules does not use it | Its delete takes the comment above a key and it cannot expand `*`, so rules has its own JSON and JSONC editor. |
| `github.com/spf13/cobra` | v1.10.2 | Command tree and flags | Nested commands, persistent `--json`, flag errors mapped to exit 2. |

Three-way merge, unified diff and template patching (`internal/textmerge`) and the JSON, JSONC and TOML span editors (`internal/rules`) are this project's code, so plaintext stays in process.

Git is the `git` binary (merge-tree `--write-tree` needs a current git), not a library.

## 18. Out of scope

Hooks run by the tool, encrypted archives, alternate template processors, a permissions command (`mode` per entry covers it), self-upgrade and an "enter the repo" shell. `yadm git` covers raw git access; it refuses verbs that move the source HEAD (pull, checkout, reset, switch, merge, rebase, cherry-pick, revert, am) and points to `yadm sync`.
