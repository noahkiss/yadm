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
// Key paths are dot-separated with `*` for one segment, for example
// "mcp.servers.*.env.TOKEN". Region markers, after any comment prefix:
//
//	# yadm:seal <enclave> [label]
//	...plaintext body on member machines...
//	# yadm:end
//
// In the source the body is one line `# yadm:sealed 1 <epoch> <base64>`. A
// non-member's target keeps the two marker lines with nothing between them.
//
// Edits are byte-level: a no-op round trip returns the input unchanged, and a
// change touches only the bytes of the values it changes. sjson does the JSON
// edits; the TOML span editor sits on go-toml's unstable parser. Comment
// ownership on delete is decided here (sjson removes a preceding comment).
//
// Exported API:
//
//	type Spec struct{ Format manifest.Format; Keep, Drop []string; Seal map[string]model.EnclaveName; Regions bool }
//	type Sealer interface{ CanOpen; SealValue; OpenValue; SealRegion; OpenRegion }  // crypt.Set implements it
//	func ToTarget(source, live []byte, spec Spec, s Sealer) ([]byte, error)
//	func ToSource(target, prevSource []byte, spec Spec, s Sealer) ([]byte, []Violation, error)
//	type Violation struct{ Path string; Kind ViolationKind; Detail string }
package rules
