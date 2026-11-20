package textmerge

import "github.com/noahkiss/yadm/internal/model"

// Region is one conflicted region of a three-way merge, by line numbers in ours.
type Region struct {
	OursStart, OursEnd int
	Base, Ours, Theirs []byte
}

// Merge3 merges ours and theirs over base line by line. With no conflicts it
// returns the merged bytes. With conflicts it returns the merged bytes with
// conflict markers and the regions; callers that store the result must not
// commit marker text and hold the file instead.
func Merge3(base, ours, theirs []byte) (merged []byte, conflicts []Region, err error) {
	return nil, nil, model.ErrNotImplemented
}

// Diff returns a unified diff of a and b with the given labels and 3 lines
// of context. Equal inputs give an empty string.
func Diff(aLabel, bLabel string, a, b []byte) (string, error) {
	return "", model.ErrNotImplemented
}

// PatchTemplate carries a hand edit of a rendered file back into its
// template. It diffs lastRender against target and applies each hunk to tmpl
// where the hunk's removed and context lines occur verbatim in tmpl. It fails
// when any hunk does not apply cleanly; the caller then re-renders and checks
// the round trip before accepting the result.
func PatchTemplate(tmpl, lastRender, target []byte) ([]byte, error) {
	return nil, model.ErrNotImplemented
}
