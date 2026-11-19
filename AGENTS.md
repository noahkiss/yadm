# AGENTS.md

`yadm` is a dotfiles manager for people who share one setup across personal, work and client machines. The README states what it is for. This file states the constraints a contributor's agent needs.

## Constraints

- **This repository is public.** Code, docs, tests, fixtures, examples, commit messages and CI logs must not contain real hostnames, usernames, home paths, employer or client names, network addresses or account names. Use placeholders such as `host-a`, `work`, `client` and `$HOME`.
- **Test fixtures are synthetic.** Fixtures in this repository are generated with fake names and fake content. Tests that read a real dotfiles repository run only when a contributor opts in through an environment variable or build tag, and they write their output outside this repository.
- **Secrecy is the core guarantee.** A change that touches encryption, key handling or what a machine is allowed to receive needs a test that proves an enclave's plaintext never reaches a machine outside that enclave or the git object store.
- **Unrelated to upstream yadm.** This project shares only the name with yadm-dev/yadm. Do not copy its code or assume its behavior.

## Conventions

- Conventional commits with short unscoped subjects: `feat: …`, `fix: …`, `docs: …`, `chore: …`.
