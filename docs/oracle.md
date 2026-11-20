# Oracle harness

`yadm-oracle` records what stock yadm 3.5.0 writes into `$HOME` for each machine profile. The new tool is checked against these records byte for byte.

The records hold the plaintext of encrypted files. Write them to a private directory outside this repository.

## Run

```sh
go run ./cmd/yadm-oracle \
  -repo "$DOTFILES_GIT_DIR" \
  -profiles "$PROFILES_TSV" \
  -out "$ORACLE_DIR"
```

`go run ./cmd/yadm-oracle -h` lists every flag.

The harness reads the source repo and never writes to it. For each profile it:

1. Creates a sandbox under `<out>/.work/<name>/` with its own home, yadm directory and data directory. The yadm directory has no `hooks/`, so no yadm hook runs. Its config sets `yadm.auto-alt = false`.
2. Runs `yadm clone --no-bootstrap -n --no-hardlinks` against the source repo, with `-Y` and `--yadm-data` pointing into the sandbox.
3. Sets `local.class` (one `--add` per class, in profile order), `local.os`, `local.hostname`, `local.user` and, if given, `local.arch`.
4. For a profile with `decrypt=yes`: copies the source repo's `transcrypt.*` keys, every filter whose smudge runs transcrypt, and the `crypt/` directory. `transcrypt.openssl-path` is set to `openssl` from `PATH`.
5. Runs `yadm checkout -- :/`, then `yadm alt`, then `yadm perms`.
6. Walks the sandbox home and writes the record. The sandbox is deleted unless `-keep` is given.

yadm runs with a scrubbed environment: `HOME` is the sandbox home, `USER` and `LOGNAME` come from the profile, and git reads no global or system config. The process umask is `022`.

The run fails for a profile when an encrypted path is in the wrong form: ciphertext on a `decrypt=yes` profile, or plaintext on any other profile.

## Profiles file

A tab-separated file with a header line. Columns are matched by name; others are ignored.

| Column | Required | Meaning |
|---|---|---|
| `hostname` | yes | Value for `local.hostname`. |
| `classes` | yes | Comma-separated classes, added in this order. yadm's `{{yadm.class}}` is the last one. |
| `name` | no | Output directory name. Defaults to `hostname`. |
| `os` | no | Value for `local.os`, such as `Darwin` or `Linux`. Falls back to `-default-os`. |
| `arch` | no | Value for `local.arch`. Unset means yadm uses `uname -m` of the machine running the harness. |
| `user` | no | Value for `local.user`, `USER` and `LOGNAME`. Defaults to the token `@@USER@@`. |
| `decrypt` | no | `yes` gives the profile the transcrypt key. Defaults to `no`. |

## Output

```
<out>/<name>/manifest.json   the record
<out>/<name>/content/<path>  normalized content of each target
<out>/<name>/alt.log         yadm alt stdout and stderr, normalized
```

### Normalization

The sandbox home path is replaced by `@@HOME@@` in content and logs. Any other sandbox path is replaced by `@@SANDBOX@@`, and the manifest warns when one survives. A profile with no `user` renders the login name as `@@USER@@`. Hostnames are not replaced: alternates match on them.

### manifest.json

| Field | Meaning |
|---|---|
| `format` | Format version, currently `1`. |
| `profile` | The profile as applied. |
| `source_commit` | The commit the sandbox checked out. |
| `tools` | yadm, git and awk versions. yadm renders templates with `gawk` when present, else `awk`. |
| `placeholders` | Each token and what it stands for. |
| `counts` | Totals by kind, plus tracked, encrypted, unresolved and self-link counts. |
| `targets` | Every file the profile sees at a path with no `##` component. Sorted by path. |
| `unresolved` | Every path on disk with a `##` component, as stored. Symlinks inside are recorded, not followed. Content is not stored. |
| `self_links` | Symlinks inside a `##` directory named like that directory. |
| `encrypted` | Tracked paths whose `filter` attribute names a transcrypt filter. |
| `case_collisions` | Tracked paths that differ only in letter case. |
| `warnings` | yadm alt stderr, skipped alternates, failed templates, symlink cycles, ciphertext targets. |

Each entry in `targets` and `unresolved`:

| Field | Meaning |
|---|---|
| `path` | Path relative to `$HOME`, slash-separated. |
| `kind` | `plain`: a tracked file at its own path. `link`: content reached through a symlink, either a yadm alternate link or a tracked symlink. `template`: a real file rendered from a template. `dangling`: a symlink with no target. `unknown`: a file nothing tracked accounts for. In `unresolved`, `symlink` marks a link. |
| `source` | The tracked path that holds the content. For a template, the template source. |
| `template` | True for rendered output. |
| `mode` | Permission bits of the dereferenced file, as octal text. |
| `size` | Size of the normalized content. |
| `sha256` | SHA-256 of the normalized content. |
| `normalized` | True when normalization changed the content. |
| `ciphertext` | True when the raw content starts with transcrypt's `U2FsdGVk` header. |
| `link_at`, `link_text` | The first symlink on the way to the content, and its link text. |
| `tracked_symlink` | True when git tracks that symlink itself (mode `120000`). |

Symlinks are dereferenced: the new tool writes real files, so a target records the content and mode a reader sees.

## Test

`go test ./...` builds a synthetic repo and runs the harness on two profiles. It skips the end-to-end test when stock `yadm` is not installed, and skips the encryption checks when `transcrypt` is not installed.
