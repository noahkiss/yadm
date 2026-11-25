<p align="center"><img src="docs/assets/banner.jpg" alt="A hedgehog with headphones and a laptop sits in a meadow beside three round burrow doors, one of them padlocked" width="100%"></p>

<h1 align="center"><img src="docs/assets/mark.png" alt="" width="48" height="48" align="absmiddle"> yadm</h1>

<p align="center">Yet another dotfiles manager (again!): one setup across personal, work and client machines, built for agents and humans.</p>

<p align="center">
  <a href="#install"><b>Install</b></a> ·
  <a href="docs/design.md">Docs</a> ·
  <a href="docs/hooks.md">Agent hooks</a> ·
  <a href="https://github.com/noahkiss/yadm/releases">Releases</a>
</p>

```sh
# On a new machine: clone your dotfiles and install the sync schedule.
yadm init <remote> --machine host-b

# On a member machine: let host-b into the "personal" enclave. It prints a join code.
yadm enclave add host-b --enclave personal --recipient <age1...> --sign-key <key>
yadm sync

# Back on host-b: type the code you read off the other screen, then apply.
yadm sync
yadm enclave join personal --code 7K3M-Q9TD
yadm apply

# From then on, the schedule keeps every machine in sync. Check on it any time.
yadm status
```

yadm keeps one dotfiles repository in sync across every machine you use. Personal, work and client machines share the setup they have in common. Files that must stay on some machines stay there, encrypted for everyone else. A schedule syncs each machine, so machines do not drift and nobody has to remember a ritual.

It works with plain git, macOS (launchd) and Linux (systemd). It hooks into coding-agent harnesses such as Claude Code, so an agent's dotfile edits commit as they happen. This yadm shares only its name with [the original yadm](https://github.com/yadm-dev/yadm). It shares no code and is not compatible with it. `yadm import` converts a repository from it once.

## What you get

- **One repository for every machine.** Each machine belongs to types such as `home`, `work` or `client`. Conditions decide which files it gets, so there is no fork per machine and no branch per employer.
- **Secrets stay on the machines that own them.** Any type can be an enclave whose files only its member machines can decrypt. A personal machine can read a work machine's enclave on demand, and yadm never writes that plaintext to its disk. See `yadm enclave --help`.
- **Machines join with a short code.** A new enclave member types a join code you read off a member's screen. `yadm enclave new-recovery` makes an offline recovery identity for each enclave.
- **Sync without babysitting.** The schedule commits and pushes changes once they settle, and a conflict holds only its own file. A sleeping laptop catches up once when it wakes.
- **Checks before every commit.** Checks you define run on every commit, manual or automatic, once you allow them on a machine. A failing check holds only the files it fails on.
- **Built for coding agents.** Harness hooks commit an agent's edits and stop a session from ending with an open decision. Leases and defers let an agent keep a path to itself or park a decision; see [docs/hooks.md](docs/hooks.md).
- **Fleet-wide changes with guard rails.** `yadm pause` holds sync on every other machine for a bounded time. `yadm reroot` replaces the shared history with one you rewrote, announced by a signed record, so no machine needs a new clone.
- **Real files and plain git.** Every file yadm writes to `$HOME` is a plain file, never a symlink, and per-key rules leave alone the parts an app rewrites. The history is an ordinary git repository.

## Install

### Command line

```sh
brew install noahkiss/tap/yadm-nkmk
```

The formula runs on macOS and Linux. It installs a `yadm` binary, so it conflicts with Homebrew's core `yadm`. The [releases page](https://github.com/noahkiss/yadm/releases) has signed and notarized macOS binaries and Linux binaries for amd64 and arm64.

Then set up each machine:

```sh
yadm init <remote> --machine host-a
yadm apply
```

On a machine that another dotfiles tool managed, run `yadm adopt` in place of `yadm apply`. It takes over identical files and holds differing ones for you to decide.

### You also need

- A current `git` on `PATH`.
- A git remote that every machine can push to.

## Documentation

- [Design](docs/design.md): the specification, including the threat model.
- [Agent hooks](docs/hooks.md): the hook contract for coding-agent harnesses.
- [Extensions](docs/extensions.md): what a `yadm-<name>` extension may rely on.
- `yadm <command> --help` describes each command. `yadm explain <command>` lists the steps it would take on this machine.

## Contributing

[AGENTS.md](AGENTS.md) lists the build and test commands and the constraints every change must meet. [docs/design.md](docs/design.md) is the specification.

## License

[MIT](LICENSE)
