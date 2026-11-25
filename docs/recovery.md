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

You need the remote, read access to it, and the enclave's recovery identity.

1. Install yadm and `age`, then run `yadm init <remote>` on the new machine.
2. Restore the recovery identity into a directory (above) and check it (above).
3. Make the new machine a member with the recovery identity: a `recover` entry, signed by the
   recovery key, that names the new machine as the only member and starts a new epoch.

**Status: step 3 has no command yet.** The key-log format and the library support `recover`
(design.md, section 7.3), but the CLI does not expose it. Until it does:

- the recovery identity is still the only key to the enclave. Keep it, and keep checking it
  yearly;
- keep at least two member machines, ideally in two places, so Case 1 always applies.

When the command ships, this section will give the exact invocation. It will also say how the
new machine trusts the key log it has no pin for: a forged log can name your public recovery
key, so the command must prove the log is yours before it seals anything new.

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
  identity. A lost identity means the enclave survives only while a member survives. To get a
  recovery key back, create a new enclave with a new identity and move the files into it.

What you lose with a recovery identity:

| Lost | Effect |
|---|---|
| the recovery identity, members alive | nothing yet. The next total loss is unrecoverable |
| every member, identity kept | nothing, once Case 2 has its command |
| every member and the identity | every sealed file of that enclave, for good |

## Yearly test

1. Restore each enclave's recovery identity into a scratch directory.
2. Run the check above: the `age1…` matches the newest key-log entry.
3. Confirm the paper copy matches the password manager copy, line by line.
4. Confirm at least two members are alive: `yadm enclave list`.
5. Delete the scratch directory.

A full no-member drill belongs in a throwaway copy of the remote, never the real one: `recover`
writes to an append-only key log.
