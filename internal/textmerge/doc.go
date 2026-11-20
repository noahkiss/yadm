// Package textmerge holds the in-process line algorithms that must see
// plaintext: three-way merge of sealed files during replay, unified diffs for
// `diff`, `log -p`, `review` and `hold show`, and patching a template with a
// hand edit of its rendered output. Everything happens in memory; no plaintext
// is written to disk or passed to git.
//
// Exported API:
//
//	func Merge3(base, ours, theirs []byte) (merged []byte, conflicts []Region, err error)
//	func Diff(aLabel, bLabel string, a, b []byte) (string, error)
//	func PatchTemplate(tmpl, lastRender, target []byte) ([]byte, error)
//	type Region struct{ OursStart, OursEnd int; Base, Ours, Theirs []byte }
package textmerge
