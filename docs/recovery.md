# Enclave recovery

This guide takes you from "every machine is gone" or "one machine is gone" back to readable
sealed files. It uses only yadm commands, `age-keygen`, and the secrets you stored in your
password manager. [design.md](design.md), section 7, is the specification behind it.

## The model in one paragraph

An enclave is a set of files only its member machines can read. yadm seals those files in the
source repository with a symmetric key per epoch. The key log under `keys/<enclave>/` lists the
members and wraps every epoch key to each member's age recipient and to the enclave's
**recovery identity**. The recovery identity is an age X25519 key plus an Ed25519 signing key that
you generate once (`yadm enclave new-recovery`) and keep offline. It is the enclave's break-glass
key: it can unwrap every epoch key, so it can open every sealed file of that enclave even when no
member machine is left. It opens no other enclave. The recovery identity signs only two key-log
entries: `recover` and `set-recovery`.

## What to keep offline, per enclave

| Item | Where it comes from | Where to keep it |
|---|---|---|
| `identity.age.key` | `yadm enclave new-recovery <dir>` | password manager **and** paper |
| `identity.sign.key` | the same directory | password manager **and** paper |
| the recipient (`age1…`) and signing key | printed by `new-recovery`; also in every key-log entry's `recovery` line | not secret |

Each file has two lines: `# machine: recovery`, then the key. Store both lines. Keep one item per
enclave, and name it so you can tell the enclaves apart without opening it.

Before you use a stored identity, write each file back to a new directory:

```sh
umask 077
mkdir ~/recovery-personal          # outside the source, state and config directories
# paste each stored value into its file, both lines, ending in a newline
$EDITOR ~/recovery-personal/identity.age.key
$EDITOR ~/recovery-personal/identity.sign.key
chmod 600 ~/recovery-personal/*
```

yadm refuses a key file that is a symlink, is readable by group or others, or sits in a directory
with group or other access. Delete the directory when you are done.

## Check that a recovery identity is the right one

Run this once a year, and before any recovery. It changes nothing.

```sh
age-keygen -y ~/recovery-personal/identity.age.key
grep '^recovery' "$(ls <source>/keys/personal/*.toml | sort | tail -1)"
```

The `age1…` that `age-keygen` prints must equal `recipient` in the newest key-log entry. If it
differs, this identity cannot open the enclave: find the right one before going further.
`<source>` is the source clone (default `~/.local/share/yadm/source`), or any fresh clone of the
remote.

## Case 1: at least one member machine survives

This is the normal "add a machine" flow. `yadm enclave --help` has the full text.

1. Install yadm on the new machine and run `yadm init <remote>`. It prints the machine id, its
   recipient and its signing key.
2. On the surviving member:

   ```sh
   yadm enclave add host-b --enclave personal --recipient <age1…> --sign-key <key>
   yadm sync
   ```

   Compare the recipient and signing key on both screens. `add` prints a join code.
3. On the new machine, type the code you read off the member's screen:

   ```sh
   yadm sync
   yadm enclave join personal --code XXXX-XXXX
   yadm apply
   ```

4. Retire each lost machine (below).

## Case 2: no member machine survives

You need the remote, read access to it, and the enclave's recovery identity. Two steps exist:
**read** the enclave, which works today, and **re-admit** a machine, which has no command yet.

### Read the enclave

1. Install yadm and clone the remote with git: `git clone <remote> ~/dotfiles-src`. Reading
   needs no `yadm init`. Read before you run `init`, or see the note on `--out` below.
2. Restore the recovery identity (above) and check it (above). Reading needs only
   `identity.age.key`.
3. Open the enclave's sealed files into a new directory:

   ```sh
   yadm enclave recover personal --read-only \
     --identity ~/recovery-personal/identity.age.key \
     --expect <fingerprint> --repo ~/dotfiles-src --out ~/personal-plain
   ```

   - `--identity -` reads the key from stdin instead, so it never touches the disk.
   - Name paths after the enclave to open only those files or directories, for example
     `.config/notes`. `--out -` prints one file to stdout.
   - `--repo` defaults to the source clone.
   - `--out` must be a new directory outside the clone and yadm's own directories, and
     must hold no path the manifest manages. recover creates it with mode 0700 and writes
     each file with mode 0600. On a machine that ran `yadm init` but cannot load its
     manifest yet (for example, it is not in `fleet.toml`), `--out` must be outside `$HOME`.

   It verifies the key-log chain, opens the epoch keys with the recovery identity, and
   opens every selected file in memory. It writes them only when all open. It writes nothing
   to the clone or the key log and adds no member. It opens whole sealed files only, not
   sealed values or regions inside plain files.
4. Delete the output directory and the recovery directory when you are done.

**Why `--expect`.** Every file is authenticated under the keys the key log wraps, so a file
sealed under the enclave's real keys never opens to other content. But anyone who can push to
the remote can replace the key log and the sealed files together. Your recovery recipient is
public, so a forged log can wrap the forger's keys to it. Without `--expect`, recover reports
`not anchored`: the files match the log, but the log may not be yours. With `--expect` the log
must contain the entry with that fingerprint, which no forger can produce.

Use the fingerprint of the newest entry. Entries after the one you pin are trusted only by
their signatures. A machine you removed after that entry still holds its signing key. It can
cut the log back to an entry where it was a member, sign a new entry with keys it chose, and
reseal files under them. So recover reports `anchored` only when `--expect` names the head
entry. Then every file was sealed by a holder of the enclave's current keys. A writer can
still put back an older sealed version of a file.

So keep the newest fingerprint with each recovery identity, and replace it after every
key-log change:

- After `yadm enclave create`, `add`, `remove`, `retire` or `set-recovery`, run
  `yadm enclave list --json` on a member. Each row's `fingerprint` is the head that member
  verified against its pin. `remove` writes a second entry, the retire, so the fingerprint
  it prints is not the head.
- An older entry's fingerprint still refuses a log forged from scratch, but recover then
  reports `not anchored`.

### Re-admit a machine

Make the new machine a member with the recovery identity: a `recover` entry, signed by the
recovery key, that names the new machine as the only member and starts a new epoch.

**Status: no command writes it yet.** The key-log format and the library support `recover`
(design.md, section 7.3), but the CLI does not expose it. Until it does:

- read the enclave as above; no machine can become a member again;
- the recovery identity is still the only key to the enclave. Keep it, and keep checking it
  yearly;
- keep at least two member machines, ideally in two places, so Case 1 always applies.

When the command ships, this section will give the exact invocation. Like a read, it must
prove the log is yours before it seals anything new.

## Retire a lost machine

On any remaining member:

```sh
yadm enclave remove host-a --enclave personal --confirm
```

`remove` starts a new epoch, reseals every file of the enclave in one commit, and retires the old
epochs once the reseal lands. The lost machine keeps every key up to the old epoch and every
commit it fetched. So, as `remove` reminds you:

- revoke the machine's access to the remote (its deploy key or token);
- rotate every real secret the enclave held (tokens, passwords).

## Rotate a recovery identity

Rotate when the identity may have leaked, or when its offline copy is lost while a member still
works.

- **Leaked, but you still have it:**

  ```sh
  yadm enclave set-recovery --enclave personal \
    --recovery-dir ~/recovery-personal --new-recovery ~/recovery-personal-2
  ```

  The current identity signs a `set-recovery` entry that names the new one. Store the new
  directory's two files offline, then delete both directories.
- **Lost:** no command can replace it. `set-recovery` must be signed by the current recovery
  identity. A lost identity means the enclave survives only while a member survives.

What you lose with a recovery identity:

| Lost | Effect |
|---|---|
| the recovery identity, members alive | nothing yet. The next total loss is unrecoverable |
| every member, identity kept | nothing is lost: `enclave recover --read-only` reads it (Case 2); a new member needs the `recover` command |
| every member and the identity | every sealed file of that enclave, for good |

## Yearly test

1. Restore each enclave's recovery identity into a scratch directory.
2. Run the check above: the `age1…` matches the newest key-log entry.
3. Run the read (Case 2) with `--expect` into a scratch directory. It must report
   `anchored`. If it does not, the kept fingerprint is not the head: replace it with the one
   `yadm enclave list --json` shows on a member. Delete the directory.
4. Confirm the paper copy matches the password manager copy, line by line.
5. Confirm at least two members are alive: `yadm enclave list`.
6. Delete the scratch directories.

A full no-member drill, one that re-admits a machine, belongs in a throwaway copy of the remote,
never the real one: re-admitting writes to an append-only key log. The read in step 3 writes
nothing to the remote.
