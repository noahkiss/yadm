// Package cli is the command tree, the JSON envelope, exit codes, the query
// commands (`machine`, `why`, `managed`, `where`, `explain`) and the
// dispatch to external `yadm-<name>` subcommands. It wires every other
// package together and holds no domain logic of its own.
//
// Every command accepts --json. With --json, stdout carries exactly one
// Envelope and nothing else; human text goes nowhere. No command prompts
// unless it is given --interactive.
//
// Exported API:
//
//	type Envelope struct{ Schema int; Command string; OK bool; Data any; Next []string; Error *ErrorBody }
//	type ErrorBody struct{ Code, Message string; Details any }
//	const ExitOK, ExitError, ExitUsage, ExitAttention, ExitLocked, ExitNotImplemented, ExitRefused
//	type Paths struct{ Source, State, Config string }
//	func DefaultPaths() (Paths, error)
//	func NewRoot(version string) *cobra.Command
//	func Main(args []string, stdout, stderr io.Writer, version string) int
package cli
