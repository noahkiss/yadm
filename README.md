# yadm

Your dotfiles, on every machine you use, kept in sync without thinking about it.

This `yadm` is a ground-up rewrite. It shares a name with [the original yadm](https://github.com/yadm-dev/yadm), because that name is muscle memory. It shares no code, and it is not compatible with it.

## The problem

Most people who live in a terminal work on more than one machine. Some machines are personal, some belong to an employer, and some belong to a client. They share most of their setup: the shell, the editor, the git config, the scripts and the agent instructions. Some files must never leave the personal machines. Some files exist only on work machines. Some files differ by a path or a single line.

Existing dotfiles managers handle part of this. In daily use, the gaps add up:

- **Every command pays for every file.** A tool that re-links hundreds of alternates after each `status` turns a 0.1-second command into a 20-second one.
- **Personal and work content share one repo, with secrecy bolted on.** Encryption sits in a git filter that local config can switch off. Diffs show ciphertext, renames look like rewrites, and one wrong suffix commits a private file in plaintext.
- **Generated files look like real files.** Symlinks and rendered outputs end up in the index, go stale, or break apps that refuse symlinks.
- **Sync needs a human.** Pulls autostash and conflict. Machines drift for weeks before anyone notices. Apps rewrite their own config files and leave phantom diffs.
- **Agents have to remember the rituals.** Run this after that, never use that flag, retag with these three commands in this order. An agent that forgets one step leaks a file or breaks a machine.

## What yadm is designed for

- **One repo for every machine.** Personal and work machines share what they share and keep apart what they must. There is no fork per machine and no branch per employer.
- **Machine types as enclaves.** A machine belongs to one or more types, such as `home`, `work` or `client`. Each type can be a sealed enclave: its files are encrypted for the members of that type, and other machines hold only ciphertext.
- **A fleet the tool understands.** The tool keeps a registry of your machines: names, nicknames, types, operating systems and any facts you add. Any machine can answer "what does that machine get?" and "when did it last sync?".
- **Fast by default.** Commands touch only what changed. Status is instant on a repo with thousands of files.
- **Sync without babysitting.** Changes are committed and pushed on a schedule, conflicts are held per file instead of blocking everything, and a sleeping laptop catches up once when it wakes.
- **Files that apps rewrite.** Rules per file keep the parts you own, drop the parts an app regenerates, and encrypt the parts that are secret, all inside the same file.
- **Real files on disk.** What lands in `$HOME` is a plain file that every app can read, rewritten only when its content changes.
- **Built for agents and humans alike.** Every command has machine-readable output and clear exit codes. Every command explains itself and suggests the next step. Nothing depends on remembering a follow-up step. Auto-commits can run unattended or go to an agent for review.
- **Plain git underneath.** The history is an ordinary git repository. If the tool ever breaks, your files are still on disk and your history is still in git.

## Who it is for

People who keep their setup on several machines across personal and work boundaries, and who increasingly share those machines with coding agents.
