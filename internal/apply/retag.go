package apply

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/rules"
	"github.com/noahkiss/yadm/internal/store"
)

// Retag builds one atomic source change for a target: the manifest entry's
// `when` and `enclave`, the move between files/ and sealed/<enclave>/ with
// the content opened and resealed, and nothing else. Only a member of every
// enclave involved can retag. The change is protected: it never auto-commits,
// and machines that lose the target remove it on their next apply (if it is
// unchanged there; a drifted copy is held).
//
// Retag works on the source head and needs at most one manifest entry with
// this literal target; variants are refused. With no entry, it tracks an
// unmanaged file in $HOME: a new entry for the types and its live bytes
// (track). A file a glob entry covers is refused.
func (e *Engine) Retag(ctx context.Context, t model.Target, opts RetagOptions) (Capture, error) {
	if len(opts.Types) == 0 {
		return Capture{}, errors.New("retag: at least one type is required")
	}
	head, err := e.Store.Head(ctx)
	if err != nil {
		return Capture{}, err
	}
	snap, err := e.snapshot(ctx, head)
	if err != nil {
		return Capture{}, err
	}
	if snap.Manifest == nil {
		return Capture{}, errors.New("retag: snapshot has no manifest")
	}
	idx := -1
	for i, en := range snap.Manifest.Entries {
		if en.Target == t {
			if idx >= 0 {
				return Capture{}, fmt.Errorf("retag %s: more than one manifest entry names it; edit the manifest", t)
			}
			idx = i
		}
	}
	if err := checkRetagTypes(snap, opts); err != nil {
		return Capture{}, err
	}
	if idx < 0 {
		return e.track(ctx, head, snap, t, opts)
	}
	entry := snap.Manifest.Entries[idx]
	oldEnc, newEnc := entry.Enclave, opts.Enclave
	for _, enc := range []model.EnclaveName{oldEnc, newEnc} {
		if enc != "" && !snap.canOpen(enc) {
			return Capture{}, fmt.Errorf("retag %s: %w: %s", t, crypt.ErrNotMember, enc)
		}
	}

	oldSrc := entry.Source
	if oldSrc == "" {
		oldSrc = defaultSource(t, oldEnc)
	}
	newSrc, err := moveSource(oldSrc, oldEnc, newEnc)
	if err != nil {
		return Capture{}, fmt.Errorf("retag %s: %w", t, err)
	}
	raw, err := e.Store.ReadPath(ctx, head, oldSrc)
	if err != nil {
		return Capture{}, err
	}
	plain := raw
	if oldEnc != "" {
		if plain, err = snap.cr().OpenFile(oldEnc, oldSrc, raw); err != nil {
			return Capture{}, fmt.Errorf("retag %s: open: %w", t, err)
		}
	}
	// Sealed values and regions are bound to the source path: a move
	// opens them under the old path and seals them under the new one.
	if spec := rules.SpecOf(entry); newSrc != oldSrc && (len(spec.Seal) > 0 || spec.Regions) {
		if entry.Template {
			return Capture{}, fmt.Errorf("retag %s: a template with sealed values or regions cannot move; edit it by hand", t)
		}
		from, to := spec, spec
		from.Source, to.Source = oldSrc, newSrc
		open, err := e.Rules.ToTarget(plain, nil, from, snap.sealer())
		if err != nil {
			return Capture{}, fmt.Errorf("retag %s: open sealed parts: %w", t, err)
		}
		moved, vio, err := e.Rules.ToSource(open, nil, to, snap.sealer())
		if err != nil || len(vio) > 0 {
			return Capture{}, fmt.Errorf("retag %s: reseal sealed parts: %v %v", t, err, vio)
		}
		plain = moved
	}
	newRaw := plain
	if newEnc != "" {
		if newRaw, err = snap.cr().SealFile(newEnc, newSrc, plain); err != nil {
			return Capture{}, fmt.Errorf("retag %s: seal: %w", t, err)
		}
	}

	var conds []string
	for _, ty := range opts.Types {
		conds = append(conds, "type:"+string(ty))
	}
	when := strings.Join(conds, " | ")
	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return Capture{}, err
	}
	srcLine := ""
	if entry.Source != "" {
		srcLine = string(newSrc)
	}
	nm, err := editEntry(mb, idx, map[string]string{"when": when, "enclave": string(newEnc), "source": srcLine})
	if err != nil {
		return Capture{}, fmt.Errorf("retag %s: %w", t, err)
	}
	var check manifest.Manifest
	if err := toml.Unmarshal(nm, &check); err != nil {
		return Capture{}, fmt.Errorf("retag %s: edited manifest does not parse: %w", t, err)
	}
	if idx >= len(check.Entries) || check.Entries[idx].Target != t || check.Entries[idx].When != when ||
		check.Entries[idx].Enclave != newEnc || (entry.Source != "" && check.Entries[idx].Source != newSrc) {
		return Capture{}, fmt.Errorf("retag %s: edited manifest does not say what was asked", t)
	}

	mode := uint32(gitModeFile)
	if te, ok := snap.Tree[oldSrc]; ok && te.Mode == gitModeExec {
		mode = gitModeExec
	}
	changes := []store.Change{{Path: manifest.FileName, Blob: nm, Mode: gitModeFile}}
	if newSrc != oldSrc {
		changes = append(changes, store.Change{Path: oldSrc, Delete: true})
	}
	changes = append(changes, store.Change{Path: newSrc, Blob: newRaw, Mode: mode})

	scope := model.ScopeShared
	if newEnc != "" {
		scope = model.Scope(newEnc)
	}
	return Capture{
		Changes: changes,
		Paths:   []model.Target{t},
		Scopes:  map[model.Target]model.Scope{t: scope},
	}, nil
}

func checkRetagTypes(snap *Snapshot, opts RetagOptions) error {
	if snap.Fleet == nil {
		return nil
	}
	for _, ty := range opts.Types {
		if _, ok := snap.Fleet.Types[ty]; !ok {
			return fmt.Errorf("retag: unknown type %q", ty)
		}
	}
	if opts.Enclave != "" {
		if d, ok := snap.Fleet.Types[model.TypeName(opts.Enclave)]; !ok || !d.Enclave {
			return fmt.Errorf("retag: %q is not an enclave type", opts.Enclave)
		}
	}
	return nil
}

// track is Retag for a file no manifest entry names: an unmanaged regular
// file in $HOME. It appends a [[file]] entry with the types' `when` (and
// the enclave) and captures the live bytes into its source, in one change.
// A file a glob entry already produces is refused: edit the manifest.
func (e *Engine) track(ctx context.Context, head model.CommitID, snap *Snapshot, t model.Target, opts RetagOptions) (Capture, error) {
	for _, en := range snap.Manifest.Entries {
		if manifest.IsGlob(string(en.Target)) && manifest.Match(string(en.Target), string(t)) {
			return Capture{}, fmt.Errorf("retag %s: glob entry %q covers it; edit the manifest", t, en.Target)
		}
	}
	if snap.Manifest.Generated(t) {
		return Capture{}, fmt.Errorf("retag %s: a task generates it (outputs); it is never tracked", t)
	}
	enc := opts.Enclave
	if enc != "" && !snap.canOpen(enc) {
		return Capture{}, fmt.Errorf("retag %s: %w: %s", t, crypt.ErrNotMember, enc)
	}
	abs, err := e.abs(t)
	if err != nil {
		return Capture{}, err
	}
	lv, err := e.readTarget(ctx, abs)
	if err != nil {
		return Capture{}, err
	}
	if !lv.exists || !lv.info.Mode().IsRegular() {
		return Capture{}, fmt.Errorf("retag %s: no manifest entry names it, and it is not a regular file in $HOME to track", t)
	}
	var conds []string
	for _, ty := range opts.Types {
		conds = append(conds, "type:"+string(ty))
	}
	when := strings.Join(conds, " | ")
	mb, err := e.Store.ReadPath(ctx, head, manifest.FileName)
	if err != nil {
		return Capture{}, err
	}
	var add strings.Builder
	if len(mb) > 0 && mb[len(mb)-1] != '\n' {
		add.WriteString("\n")
	}
	fmt.Fprintf(&add, "\n[[file]]\ntarget = %s\nwhen = %s\n", tomlString(string(t)), tomlString(when))
	if enc != "" {
		fmt.Fprintf(&add, "enclave = %s\n", tomlString(string(enc)))
	}
	nm := append(append([]byte{}, mb...), add.String()...)
	check, err := manifest.Parse(nm)
	if err != nil {
		return Capture{}, fmt.Errorf("retag %s: edited manifest does not parse: %w", t, err)
	}
	last := check.Entries[len(check.Entries)-1]
	if last.Target != t || last.When != when || last.Enclave != enc {
		return Capture{}, fmt.Errorf("retag %s: edited manifest does not say what was asked", t)
	}
	src := defaultSource(t, enc)
	blob := lv.bytes
	if enc != "" {
		if blob, err = snap.cr().SealFile(enc, src, lv.bytes); err != nil {
			return Capture{}, fmt.Errorf("retag %s: seal: %w", t, err)
		}
	}
	mode := uint32(gitModeFile)
	if lv.info.Mode().Perm()&0o111 != 0 {
		mode = gitModeExec
	}
	scope := model.ScopeShared
	if enc != "" {
		scope = model.Scope(enc)
	}
	return Capture{
		Changes: []store.Change{{Path: manifest.FileName, Blob: nm, Mode: gitModeFile}, {Path: src, Blob: blob, Mode: mode}},
		Paths:   []model.Target{t},
		Scopes:  map[model.Target]model.Scope{t: scope},
	}, nil
}

// tomlString quotes s as a TOML basic string.
func tomlString(s string) string {
	b, err := toml.Marshal(map[string]string{"v": s})
	if err != nil {
		return fmt.Sprintf("%q", s)
	}
	_, v, _ := strings.Cut(strings.TrimSpace(string(b)), "= ")
	return v
}

func defaultSource(t model.Target, enc model.EnclaveName) model.SourcePath {
	if enc != "" {
		return model.SourcePath("sealed/" + string(enc) + "/" + string(t))
	}
	return model.SourcePath("files/" + string(t))
}

// moveSource maps a source path between files/ and sealed/<enclave>/.
func moveSource(src model.SourcePath, from, to model.EnclaveName) (model.SourcePath, error) {
	s := string(src)
	var rest string
	switch {
	case from != "" && strings.HasPrefix(s, "sealed/"+string(from)+"/"):
		rest = strings.TrimPrefix(s, "sealed/"+string(from)+"/")
	case from == "" && strings.HasPrefix(s, "files/"):
		rest = strings.TrimPrefix(s, "files/")
	default:
		return "", fmt.Errorf("source %s is not under files/ or sealed/<enclave>/", src)
	}
	if to != "" {
		return model.SourcePath("sealed/" + string(to) + "/" + rest), nil
	}
	return model.SourcePath("files/" + rest), nil
}

var (
	reTable = regexp.MustCompile(`^\s*\[`)
	reFile  = regexp.MustCompile(`^\s*\[\[\s*file\s*\]\]`)
	reKey   = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_-]*)\s*=`)
)

// editEntry sets or removes top-level string keys in the idx-th [[file]]
// table of a manifest, touching no other line. An empty value removes the key.
func editEntry(src []byte, idx int, set map[string]string) ([]byte, error) {
	lines := strings.SplitAfter(string(src), "\n")
	start, n := -1, 0
	for i, l := range lines {
		if reFile.MatchString(l) {
			if n == idx {
				start = i
				break
			}
			n++
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("manifest has no [[file]] entry %d", idx)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if reTable.MatchString(lines[i]) {
			end = i
			break
		}
	}
	done := map[string]bool{}
	var block []string
	anchor := 0 // insert new keys after the target line, or after the header
	for i := start + 1; i < end; i++ {
		l := lines[i]
		if m := reKey.FindStringSubmatch(l); m != nil {
			if v, ok := set[m[1]]; ok {
				done[m[1]] = true
				if v == "" {
					continue
				}
				l = m[1] + " = " + tomlQuote(v) + "\n"
			}
			if m[1] == "target" {
				anchor = len(block) + 1
			}
		}
		block = append(block, l)
	}
	var add []string
	for _, k := range []string{"source", "when", "enclave"} {
		if v, ok := set[k]; ok && v != "" && !done[k] {
			add = append(add, k+" = "+tomlQuote(v)+"\n")
		}
	}
	if anchor > 0 && !strings.HasSuffix(block[anchor-1], "\n") {
		block[anchor-1] += "\n"
	}
	block = append(block[:anchor], append(add, block[anchor:]...)...)
	out := strings.Join(lines[:start+1], "") + strings.Join(block, "") + strings.Join(lines[end:], "")
	return []byte(out), nil
}

// tomlQuote writes a TOML basic string.
func tomlQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\t", `\t`)
	return `"` + r.Replace(s) + `"`
}
