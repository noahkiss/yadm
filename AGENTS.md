# AGENTS.md

`yadm` is a dotfiles manager for people who share one setup across personal, work and client machines. The README states what it is for. This file states the constraints a contributor's agent needs.

## Constraints

- **This repository is public.** Code, docs, tests, fixtures, examples, commit messages and CI logs must not contain real hostnames, usernames, home paths, employer or client names, network addresses or account names. Use placeholders such as `host-a`, `work`, `client` and `$HOME`.
- **Test fixtures are synthetic.** Fixtures in this repository are generated with fake names and fake content. Tests that read a real dotfiles repository run only when a contributor opts in through an environment variable or build tag, and they write their output outside this repository.
- **Secrecy is the core guarantee.** A change that touches encryption, key handling or what a machine is allowed to receive needs a test that proves an enclave's plaintext never reaches a machine outside that enclave or the git object store.
- **Unrelated to upstream yadm.** This project shares only the name with yadm-dev/yadm. Do not copy its code or assume its behavior.

## Build and test

- Build: `go build ./...`; the binary is `go build -o yadm ./cmd/yadm`.
- Check before every commit: `gofmt -l .` prints nothing, and `go vet ./...` and `go test ./...` pass.
- Tests need the `git` binary on `PATH`.
- `docs/design.md` is the specification. Each package's `doc.go` states its contract.
- Secrecy tests use `internal/secrecytest` to plant a canary in enclave plaintext and assert it reaches neither a non-member's `$HOME` nor any repository's object store. `internal/fixture` builds the synthetic source tree from `testdata/fixture`.

## Conventions

- Conventional commits with short unscoped subjects: `feat: …`, `fix: …`, `docs: …`, `chore: …`.
