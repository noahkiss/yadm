// Package rules applies intra-file rules: keep, drop and seal by key path in
// JSON, JSONC and TOML (format-preserving), and sealed marked regions in any
// line-comment text file.
//
// Two directions:
//
//   - ToTarget (apply): take the source bytes, open sealed parts this machine
//     may read, leave out the ones it may not, and merge the result into the
//     live target so keys the app owns stay as the app wrote them.
//   - ToSource (capture): take the live target, discard dropped keys, keep only
//     owned keys, reseal sealed parts, and put back the stored tokens a
//     non-member cannot see. It returns Violations instead of writing when the
//     result would lose or unseal a sealed part (the seal guard).
//
// Key paths name nested keys, separated by dots, with `*` for any one
// segment: "mcp.servers.*.env.TOKEN" is mcp → servers → (any) → env → TOKEN.
// A literal dot or star inside a key is escaped with a backslash: the JSON
// key "files.exclude" is the path `files\.exclude`. JSON arrays are indexed
// by number ("list.0"). A path that names a table or object covers everything
// below it. Region markers, after any comment prefix:
//
//	# yadm:seal <enclave> [label]
//	...plaintext body on member machines...
//	# yadm:end
//
// In the source the body is one line `# yadm:sealed 1 <epoch> <base64>`. A
// non-member's target keeps the two marker lines with nothing between them.
//
// Edits are byte-level: a no-op round trip returns the input unchanged, and a
// change touches only the bytes of the values it changes. The JSON and JSONC
// editor is this package's own scanner (sjson deletes the comment above a key
// and cannot expand `*`); the TOML span editor sits on go-toml's unstable
// parser. Every edit re-parses its output and fails closed. A delete keeps
// the comment lines above a key, except when keep-mode pruning removes an
// app-owned key, which takes its comments with it. An insert lands after the
// previous sibling, below the comment lines that sat between them.
//
// Every sealed value is bound to the file's source path and its concrete key
// path, and every region to the source path and its label
// (crypt.PartName), so a token swapped between keys or copied into another
// file fails to open.
//
// The leak check (SealedValueLeaked) looks for each sealed plaintext outside
// its seal path. A value of 8 bytes or more is looked for anywhere; a shorter
// one only as a whole quoted string. Region lines shorter than 8 bytes are
// not looked for, and region lines are checked only against an earlier
// source, so a first capture is never held for a line that also stands
// outside its region.
//
// Only string values can be sealed, and a drop or seal path may not name an
// array element (ErrArrayElement). A sealed string whose spelling cannot be
// rebuilt from its value (JSON escapes, invalid UTF-8, TOML multi-line
// strings) fails the round trip. ToSource returns ErrRoundTrip when its
// result does not render back to the target, and model.ErrNotImplemented
// (wrapped) for an edit the span editors do not perform, such as adding an
// element to an array of tables.
//
// Exported API:
//
//	type Spec struct{ Format manifest.Format; Keep, Drop []string; Seal map[string]model.EnclaveName; Regions bool; Source model.SourcePath; Volatile []string }
//	func SpecOf(e manifest.Entry) Spec; func SpecFor(r manifest.Resolved) Spec // SpecFor sets Source
//	var ErrNoSource error // sealing or opening with an empty Spec.Source
//	type Sealer interface{ CanOpen; SealValue; OpenValue; SealRegion; OpenRegion }  // crypt.Set implements it
//	func ToTarget(source, live []byte, spec Spec, s Sealer) ([]byte, error)
//	func ToSource(target, prevSource []byte, spec Spec, s Sealer) ([]byte, []Violation, error)
//	func Reseal(source []byte, spec Spec, enclave model.EnclaveName, s Sealer) ([]byte, error) // after remove or rotate
//	func Merge3(format string, volatile []string, base, ours, theirs []byte) (merged []byte, ok bool, err error) // key-level 3-way merge from ours; volatile keys stay ours; ok=false holds
//	type Structural struct{} // its Merge3 method satisfies sync.Structural
//	type Violation struct{ Path string; Kind ViolationKind; Detail string }
//	const SealedKeyRemoved, SealedValueLeaked, RegionMarkerLost, ParseFailed, SealedNotString, SealNotMember, RegionNotMember ViolationKind
//	var ErrRoundTrip, ErrArrayElement error
package rules
