Synthetic repository in the upstream-yadm shape, input for the importer tests.

- `name##cond` files are alternates.
- `dot-gitattributes` becomes `.gitattributes` when a test builds the legacy
  repository. It is renamed here so this repository's git never applies its
  filter lines. It marks files for transcrypt; the files here are plaintext,
  and importer tests encrypt them at test time with a test password.
- `.config/yadm/machines.tsv` is the machines table.
- `@@CANARY@@` is replaced with a secrecytest canary at build time.
