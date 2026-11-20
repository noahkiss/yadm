// Package importer converts a repository managed by upstream yadm into this
// tool's layout, once, in one commit whose parent is the legacy head. It does
// not run upstream yadm or copy its code; it reads the repository.
//
// What it converts:
//
//   - Alternate files named `path##cond[,cond...]`: each becomes a manifest
//     entry with an equivalent `when` condition and a source under
//     `files/` (or `sealed/<enclave>/`). Supported conditions, long and short:
//     default, class/c, os/o, arch/a, hostname/h, user/u, distro/d,
//     distro_family/f, template/t, extension/e (ignored). Upstream compares
//     values case-insensitively, so os and arch values are lowercased.
//     Anything else fails the import with the path.
//   - Templates for the built-in processor only: yadm.* variables, if with
//     == or !=, else, endif, and include (inlined) become package render
//     syntax. env.VAR, other processors and anything unconvertible fail the
//     import with path and line.
//   - Transcrypt: paths matched by a `filter=crypt` attribute are decrypted with
//     the password from the environment variable the caller names, and sealed
//     into the enclave the caller maps them to. The importer never writes the
//     password anywhere.
//   - A machines table (TSV with a header): `name`, `hostname`, `classes`
//     columns become fleet machines (hostname becomes a fact, classes become
//     types); every other column becomes a declared fact.
//
// Output: a branch whose first commit has the legacy head as parent and a
// `Legacy-Head:` trailer. The importer never pushes; the user reviews and
// pushes the branch.
//
// Exported API:
//
//	type Options struct{ Legacy, Machines, Branch, PasswordEnv string; ClassEnclaves map[string]model.EnclaveName; DefaultEnclave model.EnclaveName; DryRun bool }
//	type Mapping struct{ From string; Target model.Target; Source model.SourcePath; When string }
//	type Report struct{ Commit model.CommitID; Mappings []Mapping; Machines int; Problems []Problem }
//	func Import(ctx context.Context, opts Options) (Report, error)
//	type AltName struct{ Base string; Conds []AltCond }
//	func ParseAltName(path string) (AltName, bool, error)
package importer
