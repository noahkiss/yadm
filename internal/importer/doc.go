// Package importer converts a repository managed by upstream yadm into this
// tool's layout, once, in one commit whose parent is the legacy head. It does
// not run upstream yadm or copy its code; it reads the repository's head tree.
//
// What it converts:
//
//   - Alternate files named `path##cond[,cond...]`, at file or directory
//     level: each variant becomes manifest entries with a `when` condition and
//     a source under `files/` (or `sealed/<enclave>/`). Supported conditions,
//     long and short: default, class/c, os/o, arch/a, hostname/h, user/u,
//     distro/d, distro_family/f, template/t, extension/e (ignored). Upstream
//     compares values case-insensitively, so os and arch values are
//     lowercased. Hostname, user, distro and distro family become facts.
//     Anything else fails the import with the path.
//   - Precedence: upstream picks one matching variant by score (more
//     conditions win; a template beats any other file). Each entry's `when` is
//     its variant's conditions plus the negation of every higher-ranked
//     variant that could also match, so at most one entry applies per machine.
//   - Templates for the built-in processor only: yadm.* variables, if with
//     == or !=, else, endif, and include (inlined) become package render
//     syntax; env.HOME becomes {{ home }}. Literal text that would open a
//     tag ({{, {%, {#) is escaped with render.Escape. Any other env.VAR and
//     other processors fail the import with path and line.
//   - Modes: a target gets 0644, or 0755 when its source is executable,
//     sealed or not; the manifest default gives that, so no `mode` is
//     written. Under .ssh and .gnupg the entry sets 0600, or 0700 when
//     executable, as upstream's perms step leaves them.
//   - Checks: the manifest and fleet must pass strict manifest.Parse and
//     fleet.Parse, every condition must name a declared type or fact, and no
//     fleet machine may get two entries for one target.
//   - Transcrypt: paths whose `filter` attribute names a transcrypt filter are
//     decrypted with the password from the environment variable the caller
//     names, and sealed through the caller's Sealer into the enclave the
//     caller maps their class to. The importer never writes the password or
//     the plaintext anywhere.
//   - Strip filters: any other `filter` attribute (a clean filter that
//     dropped runtime keys or kept only owned tables) maps through
//     Options.Filters to the entry's format, keep, drop, volatile and merge
//     fields. A filter marked Crypt also runs transcrypt, so its files are
//     decrypted and sealed too. A path whose filter has no mapping, or whose
//     filter has no rule for its target, fails the import: a filter is never
//     lost silently.
//   - Tracked symlinks become entries that reuse the source of what they
//     point at, under both conditions.
//   - A machines table (TSV with a header): `name`, `hostname`, `classes`
//     columns become fleet machines (hostname becomes a fact, classes become
//     types); `os` and `arch` set the machine fields; every other column
//     becomes a declared fact.
//
// Output: a new repository whose branch holds one commit with the legacy
// head as parent and a `Legacy-Head:` trailer. Any problem means nothing is
// written: Import returns ErrProblems and every problem in the Report. The
// importer never pushes.
//
// Exported API:
//
//	type Sealer interface{ SealFile(enclave model.EnclaveName, path model.SourcePath, plaintext []byte) ([]byte, error) }
//	type Options struct{ Legacy, Machines, Branch, Output, PasswordEnv string; ClassEnclaves map[string]model.EnclaveName; DefaultEnclave model.EnclaveName; CryptFilters []string; Filters map[string]Filter; Sealer Sealer; DryRun bool }
//	type Filter struct{ Crypt bool; Paths map[string]StripRule }; type StripRule struct{ Format; Keep, Drop, Volatile []string; Merge }
//	func ReadFilters(file string) (map[string]Filter, error); func ParseFilters(b []byte) (map[string]Filter, error)
//	type Mapping struct{ From string; Target model.Target; Source model.SourcePath; When string; Sealed bool }
//	type Problem struct{ Path string; Line int; Reason string }
//	type Report struct{ Commit model.CommitID; Mappings []Mapping; Machines int; Problems []Problem }
//	var ErrProblems error
//	func Import(ctx context.Context, opts Options) (Report, error)
//	type AltName struct{ Base string; Conds []AltCond; Alt string; Dir bool }
//	func ParseAltName(path string) (AltName, bool, error)
package importer
