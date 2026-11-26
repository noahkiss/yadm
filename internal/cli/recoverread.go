package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/noahkiss/yadm/internal/crypt"
	"github.com/noahkiss/yadm/internal/model"
	"github.com/noahkiss/yadm/internal/store"
)

const enclaveRecoverLong = `Read an enclave's sealed files with its recovery identity, for when no member
machine is left. Only the read-only mode exists: re-admitting a machine is not
built yet, so --read-only is required.

  yadm enclave recover <enclave> [path...] --read-only --identity <file|-> \
    --out <new dir|-> [--expect <fingerprint>] [--repo <clone>]

recover reads main of the clone (default: the source clone; any plain
"git clone" of the remote works, and needs no "yadm init"). It verifies the
enclave's key-log chain, opens the epoch keys with the recovery identity,
and opens every whole sealed file of the enclave under sealed/<enclave>/, or
only those at or under the given paths (relative to $HOME, as the files are
stored). Sealed values and regions inside plain files are not opened.

--identity  the recovery identity.age.key file (mode 0600, not a symlink), or
            "-" to read it from stdin, for example from a password manager.
            The key never goes on the command line.
--out       a new directory. recover creates it with mode 0700 and writes each
            file at its path under it with mode 0600, subdirectories 0700. It
            must be outside the clone, yadm's source, state and config
            directories and ~/.local, and no file in it may be a path the
            manifest manages. "-" prints exactly one file to stdout instead.
--expect    the fingerprint of the enclave's newest key-log entry, kept with
            the recovery identity: the "fingerprint" of "enclave list --json"
            on a member. The log must contain that entry.

Trust: every file is authenticated under the keys the log wraps, so files
sealed under the enclave's real keys never open to other content. But a
writer to the remote can replace the key log and the sealed files together
with its own, and the recovery identity opens both: without --expect, the
output proves only that the log and the files agree. With --expect on the
head entry the log is the enclave's own, so every file was sealed by a
holder of the enclave's current keys; a writer can still roll a file back
to an older sealed version. With --expect on an older entry, the entries
after it are trusted only by their signatures: a machine removed after that
entry still holds its signing key and can fork the log from there. Output
"anchored" is true only when --expect names the head.

All or nothing: recover opens every selected file in memory first and writes
nothing when any fails. It writes only the output: nothing to the clone or
its key log, and it adds no member. With --out outside $HOME it runs only git
reads; inside $HOME it also loads this machine, as "show" does, to learn the
managed paths. Delete the output directory when you are done.`

type recoverData struct {
	Enclave     model.EnclaveName `json:"enclave"`
	Repo        string            `json:"repo"`
	Commit      model.CommitID    `json:"commit"`
	HeadSeq     uint64            `json:"head_seq"`
	Epoch       model.Epoch       `json:"epoch"`
	Fingerprint string            `json:"fingerprint"`      // the head entry's
	Root        string            `json:"root_fingerprint"` // entry 1's, the value to keep for --expect
	Anchored    bool              `json:"anchored"`         // --expect matched the log's head entry
	AnchoredSeq uint64            `json:"anchored_seq"`     // the seq of the entry --expect matched; 0 without --expect
	Out         string            `json:"out"`
	Files       []string          `json:"files"`
	Content     string            `json:"content,omitempty"`  // --out - only
	Encoding    string            `json:"encoding,omitempty"` // --out - only
}

// cmdEnclaveRecover reads an enclave with its recovery identity. It runs
// only git reads against the clone and writes only under --out (or to
// stdout).
func (a *app) cmdEnclaveRecover(cmd *cobra.Command, args []string) (result, error) {
	ctx := cmd.Context()
	if ro, _ := cmd.Flags().GetBool("read-only"); !ro {
		return result{next: []string{"yadm enclave recover --help"}},
			fmt.Errorf("enclave recover without --read-only (re-admitting a machine) is not built yet; --read-only reads the enclave: %w", model.ErrNotImplemented)
	}
	if len(args) == 0 {
		return result{}, usagef("name the enclave: yadm enclave recover <enclave> --read-only --identity <file|-> --out <dir>")
	}
	enc := model.EnclaveName(args[0])
	idArg, _ := cmd.Flags().GetString("identity")
	out, _ := cmd.Flags().GetString("out")
	expect, _ := cmd.Flags().GetString("expect")
	repoArg, _ := cmd.Flags().GetString("repo")
	switch {
	case idArg == "":
		return result{}, usagef("--identity is required: the recovery identity.age.key file, or - for stdin")
	case out == "":
		return result{}, usagef("--out is required: a new directory, or - for stdout")
	}
	prefixes, err := recoverPrefixes(args[1:])
	if err != nil {
		return result{}, err
	}
	p, err := DefaultPaths()
	if err != nil {
		return result{}, err
	}
	if repoArg == "" {
		repoArg = p.Source
	}
	repo, gitDir, err := recoverRepo(ctx, repoArg)
	if err != nil {
		return result{}, err
	}
	commit, entries, sealed, err := recoverRead(ctx, repo, enc)
	if err != nil {
		return result{}, err
	}
	var pin *crypt.Pin
	if expect != "" {
		if pin, err = pinFor(entries, expect); err != nil {
			return result{}, fmt.Errorf("enclave %s: %w", enc, err)
		}
	}
	head, err := crypt.VerifyLog(entries, pin)
	if err != nil {
		return result{}, fmt.Errorf("enclave %s: %w", enc, err)
	}
	key, err := recoverKey(idArg)
	if err != nil {
		return result{}, err
	}
	ring, err := crypt.OpenRecovery(head, key)
	if err != nil {
		return result{}, fmt.Errorf("enclave %s: %w", enc, err)
	}
	// Only a pin on the head anchors the whole log. Entries after an older
	// pinned entry are trusted only by their signatures, and a machine that
	// was a member there and was removed later still holds its signing key:
	// it can truncate the log and sign a fork with keys of its own.
	d := recoverData{Enclave: enc, Repo: repo, Commit: commit, HeadSeq: head.Seq, Epoch: head.Epoch, Out: out, Files: []string{}}
	if pin != nil {
		d.AnchoredSeq = pin.Seq
		d.Anchored = pin.Seq == head.Seq
	}
	d.Fingerprint, _ = crypt.Fingerprint(head)
	d.Root, _ = crypt.Fingerprint(entries[0])

	// Select and open everything in memory before writing anything.
	var names []string
	for rel := range sealed {
		if selected(rel, prefixes) {
			names = append(names, rel)
		}
	}
	sort.Strings(names)
	for _, pre := range prefixes {
		if !matchesAny(names, pre) {
			return result{}, fmt.Errorf("enclave %s has no sealed file at or under %s", enc, pre)
		}
	}
	if len(names) == 0 {
		return result{}, fmt.Errorf("enclave %s has no sealed files at %s", enc, commit)
	}
	plain := make(map[string][]byte, len(names))
	var failed []string
	for _, rel := range names {
		pt, err := ring.OpenFile(model.SourcePath("sealed/"+string(enc)+"/"+rel), sealed[rel])
		if err != nil {
			failed = append(failed, rel+": "+err.Error())
			continue
		}
		plain[rel] = pt
	}
	if len(failed) > 0 {
		return result{data: d}, fmt.Errorf("%w: %d of %d files of %s did not open with these keys, so nothing was written; a forged key log or a damaged file fails this way:\n  %s",
			ErrRefused, len(failed), len(names), enc, strings.Join(failed, "\n  "))
	}
	d.Files = names
	if !d.Anchored && !a.json {
		fmt.Fprintf(a.stderr, "yadm enclave recover: not anchored: %s\n", unanchoredWhy(d))
	}

	if out == "-" {
		if len(names) != 1 {
			return result{data: d}, usagef("--out - prints one file; %d match (name one path)", len(names))
		}
		pt := plain[names[0]]
		d.Content, d.Encoding = string(pt), "utf-8"
		if !utf8.Valid(pt) {
			d.Content, d.Encoding = base64.StdEncoding.EncodeToString(pt), "base64"
		}
		return result{data: d, raw: append([]byte{}, pt...)}, nil
	}
	abs, err := recoverWrite(ctx, p, []string{repo, gitDir}, out, names, plain)
	if err != nil {
		return result{data: d}, err
	}
	d.Out = abs
	next := []string{"delete " + abs + " and the restored recovery identity when you are done"}
	if !d.Anchored {
		next = append(next, "after every key-log change, keep the head fingerprint a member prints with the recovery identity, and pass it as --expect")
	}
	anchor := "anchored by --expect"
	switch {
	case d.AnchoredSeq == 0:
		anchor = "NOT anchored (no --expect)"
	case !d.Anchored:
		anchor = fmt.Sprintf("NOT anchored (--expect matched entry %d, not the head)", d.AnchoredSeq)
	}
	text := fmt.Sprintf("enclave %s: key log verified to seq %d (epoch %d), %s\nhead fingerprint %s\nroot fingerprint %s\nwrote %d files to %s",
		enc, head.Seq, head.Epoch, anchor, d.Fingerprint, d.Root, len(names), abs)
	return result{data: d, next: next, text: text}, nil
}

// unanchoredWhy says what an unanchored read does not prove.
func unanchoredWhy(d recoverData) string {
	if d.AnchoredSeq == 0 {
		return "without --expect, a writer to the remote could have replaced the key log and these files together"
	}
	return fmt.Sprintf("--expect matched entry %d of %d; a machine that was a member at entry %d and was removed later could have written entries %d to %d and these files; pass the newest head fingerprint you kept",
		d.AnchoredSeq, d.HeadSeq, d.AnchoredSeq, d.AnchoredSeq+1, d.HeadSeq)
}

// recoverPrefixes cleans the path arguments: slash paths relative to $HOME,
// as stored under sealed/<enclave>/. A leading ~/ is dropped.
func recoverPrefixes(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		s := strings.TrimPrefix(filepath.ToSlash(a), "~/")
		s = strings.TrimSuffix(path.Clean(s), "/")
		if s == "." || s == "" || !filepath.IsLocal(filepath.FromSlash(s)) || model.HasControl(s) {
			return nil, usagef("%q: give a path relative to $HOME, as the file is stored", a)
		}
		out = append(out, s)
	}
	return out, nil
}

func selected(rel string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if rel == p || strings.HasPrefix(rel, p+"/") {
			return true
		}
	}
	return false
}

func matchesAny(names []string, prefix string) bool {
	for _, n := range names {
		if selected(n, []string{prefix}) {
			return true
		}
	}
	return false
}

// recoverRepo resolves the clone's top directory (or a bare repository) and
// its git directory, with read-only git calls.
func recoverRepo(ctx context.Context, dir string) (string, string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		return "", "", usagef("--repo %s: not a directory (clone the remote first, or run yadm init)", abs)
	}
	gd, err := store.Output(ctx, abs, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", "", usagef("--repo %s: not a git repository", abs)
	}
	gitDir := strings.TrimSpace(string(gd))
	top := abs
	if t, err := store.Output(ctx, abs, "rev-parse", "--show-toplevel"); err == nil && len(bytes.TrimSpace(t)) > 0 {
		top = strings.TrimSpace(string(t))
	}
	return top, gitDir, nil
}

// recoverRead reads, at main, the enclave's key log in seq order and its
// whole sealed files keyed by their path under sealed/<enclave>/.
func recoverRead(ctx context.Context, repo string, enc model.EnclaveName) (model.CommitID, []crypt.LogEntry, map[string][]byte, error) {
	c, err := store.Output(ctx, repo, "rev-parse", "--verify", "--quiet", "--end-of-options", store.RefMain+"^{commit}")
	if err != nil {
		return "", nil, nil, fmt.Errorf("%s has no main branch", repo)
	}
	commit := model.CommitID(strings.TrimSpace(string(c)))
	logDir := string(crypt.LogDir(enc)) + "/"
	sealedDir := "sealed/" + string(enc) + "/"
	ls, err := store.Output(ctx, repo, "ls-tree", "-r", "-z", "--full-tree", string(commit), "--", strings.TrimSuffix(logDir, "/"), strings.TrimSuffix(sealedDir, "/"))
	if err != nil {
		return "", nil, nil, err
	}
	type logBlob struct {
		seq uint64
		oid string
	}
	var logs []logBlob
	sealedOID := map[string]string{}
	for _, rec := range bytes.Split(ls, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		meta, p, ok := strings.Cut(string(rec), "\t")
		f := strings.Fields(meta)
		if !ok || len(f) != 3 {
			return "", nil, nil, fmt.Errorf("git ls-tree: unexpected line %q", meta)
		}
		mode, typ, oid := f[0], f[1], f[2]
		switch {
		case strings.HasPrefix(p, logDir):
			e, seq, ok := crypt.ParseLogPath(model.SourcePath(p))
			if !ok || e != enc || typ != "blob" {
				return "", nil, nil, fmt.Errorf("%w: unexpected entry %s in the key log", crypt.ErrInvalidLog, p)
			}
			logs = append(logs, logBlob{seq, oid})
		case strings.HasPrefix(p, sealedDir):
			rel := strings.TrimPrefix(p, sealedDir)
			// Only regular files; a symlink or submodule is never a sealed file.
			if typ != "blob" || (mode != "100644" && mode != "100755") || !filepath.IsLocal(filepath.FromSlash(rel)) || model.HasControl(rel) {
				continue
			}
			sealedOID[rel] = oid
		}
	}
	if len(logs) == 0 {
		return "", nil, nil, fmt.Errorf("enclave %s has no key log at main of %s", enc, repo)
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].seq < logs[j].seq })
	entries := make([]crypt.LogEntry, 0, len(logs))
	for _, l := range logs {
		b, err := store.Output(ctx, repo, "cat-file", "blob", l.oid)
		if err != nil {
			return "", nil, nil, err
		}
		e, err := crypt.ParseLogEntry(b)
		if err != nil {
			return "", nil, nil, fmt.Errorf("%s: %w", crypt.LogPath(enc, l.seq), err)
		}
		entries = append(entries, e)
	}
	sealed := make(map[string][]byte, len(sealedOID))
	for rel, oid := range sealedOID {
		b, err := store.Output(ctx, repo, "cat-file", "blob", oid)
		if err != nil {
			return "", nil, nil, err
		}
		sealed[rel] = b
	}
	return commit, entries, sealed, nil
}

// pinFor finds the entry whose fingerprint is expect.
func pinFor(entries []crypt.LogEntry, expect string) (*crypt.Pin, error) {
	want := strings.ToLower(strings.TrimSpace(expect))
	for _, e := range entries {
		p, err := crypt.PinOf(e)
		if err != nil {
			return nil, err
		}
		if p.Hash == want {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("%w: no entry of the key log has fingerprint %s: this is not the log you kept the fingerprint for", crypt.ErrBrokenChain, expect)
}

// recoverKey reads the recovery key from a file or, for "-", from stdin.
func recoverKey(arg string) (*crypt.RecoveryKey, error) {
	var (
		k   *crypt.RecoveryKey
		err error
	)
	if arg == "-" {
		var b []byte
		b, err = io.ReadAll(io.LimitReader(hooks.stdin(), 64<<10))
		if err == nil {
			k, err = crypt.ParseRecoveryKey(b)
		}
	} else {
		k, err = crypt.LoadRecoveryKey(arg)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: recovery identity: %v", ErrRefused, err)
	}
	return k, nil
}

// recoverWrite creates out, a new directory, and writes each file under it:
// directories 0700, files 0600, every write inside an os.Root, so no path
// leaves out. The guard keeps out away from the clone and yadm's own
// directories, and, inside $HOME on a set-up machine, from every path the
// manifest manages.
func recoverWrite(ctx context.Context, p Paths, clone []string, out string, names []string, plain map[string][]byte) (string, error) {
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	g := guardFor(p)
	g.forbidden = append(g.forbidden, clone...)
	if inHome(g.home, abs) {
		// Only paths under $HOME can be managed. Loading the machine reads the
		// manifest; a machine that is set up but fails to load refuses here.
		m, err := openLoaded(ctx)
		switch {
		case err == nil:
			g = m.recoveryGuard()
			g.forbidden = append(g.forbidden, clone...)
		case !errors.Is(err, errNotInitialized):
			return "", fmt.Errorf("--out inside $HOME needs the manifest to keep the files out of managed paths (%v); give a directory outside $HOME", err)
		}
	}
	if err := g.checkFiles(abs, "--out", names); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return "", err
	}
	if err := os.Mkdir(abs, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", usagef("--out %s already exists; give a new directory", abs)
		}
		return "", err
	}
	// A parent swapped for a symlink since the check lands here.
	if err := g.checkFiles(abs, "--out", names); err != nil {
		os.Remove(abs)
		return "", err
	}
	if err := writeAll(abs, names, plain); err != nil {
		// Leave no partial plaintext behind.
		os.RemoveAll(abs)
		return "", fmt.Errorf("--out %s: %w (removed it again)", abs, err)
	}
	return abs, nil
}

// writeAll writes each file under dir through an os.Root.
func writeAll(dir string, names []string, plain map[string][]byte) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	for _, rel := range names {
		if d := path.Dir(rel); d != "." {
			if err := root.MkdirAll(d, 0o700); err != nil {
				return err
			}
		}
		f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, werr := f.Write(plain[rel])
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
	}
	return nil
}

// inHome reports whether p (or what its existing ancestors resolve to) lies
// under home.
func inHome(home, p string) bool {
	if home == "" {
		return true
	}
	for _, h := range []string{home, resolveExisting(home)} {
		for _, c := range []string{p, resolveExisting(p)} {
			if rel, err := filepath.Rel(h, c); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}
