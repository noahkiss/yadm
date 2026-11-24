package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/model"
)

// Rewrite is one ref a re-root replaces on the remote: Ref moves to New
// only while the remote still holds Old ("" means the remote must not have
// the ref).
type Rewrite struct {
	Ref string
	New model.CommitID
	Old model.CommitID
}

// PushRewrite pushes the rewrites and the plain refspecs atomically, in
// one call. Each rewrite is a forced update guarded by an explicit lease
// on its old value, so it replaces nothing the caller has not seen. It is
// the only forced push the tool makes: `yadm reroot`, which a signed
// re-root record announces. Held refs are never pushed. A remote that
// moved past a lease is ErrRejected.
func (r *Repo) PushRewrite(ctx context.Context, rewrites []Rewrite, plain []string) error {
	if len(rewrites) == 0 {
		return errors.New("push rewrite: nothing to rewrite")
	}
	args := []string{"push", "--atomic", "--porcelain", "--no-verify", "--no-recurse-submodules"}
	var specs []string
	for _, w := range rewrites {
		if err := checkRefName(w.Ref); err != nil {
			return err
		}
		if strings.HasPrefix(w.Ref, refHeldPrefix) {
			return fmt.Errorf("push %q: held refs are local only", w.Ref)
		}
		if err := checkRev(string(w.New)); err != nil || w.New == "" {
			return fmt.Errorf("push rewrite %s: invalid commit %q", w.Ref, w.New)
		}
		old := string(w.Old)
		if old != "" {
			if err := checkRev(old); err != nil {
				return err
			}
		}
		args = append(args, "--force-with-lease="+w.Ref+":"+old)
		specs = append(specs, string(w.New)+":"+w.Ref)
	}
	for _, s := range plain {
		src, _, _ := strings.Cut(s, ":")
		switch {
		case strings.HasPrefix(s, "+"), strings.HasPrefix(s, "-"), src == "":
			return fmt.Errorf("push %q: invalid refspec", s)
		case strings.HasPrefix(src, refHeldPrefix), strings.Contains(s, ":"+refHeldPrefix):
			return fmt.Errorf("push %q: held refs are local only", s)
		}
	}
	args = append(append(append(args, "origin"), specs...), plain...)
	out, err := run(ctx, call{dir: r.dir, base: r.env, network: true, args: args})
	if err == nil {
		return nil
	}
	var ge *gitError
	stderr := ""
	if errors.As(err, &ge) {
		stderr = ge.stderr
	}
	if pushRejected(string(out), stderr) {
		return fmt.Errorf("%w: %v", ErrRejected, err)
	}
	return fmt.Errorf("push: %w", err)
}

// bundleTimeout bounds one `git bundle create`.
const bundleTimeout = 10 * time.Minute

// Bundle writes `git bundle create <path> --all` of the source clone: every
// local ref with all its history. The file is created with mode 0600 in an
// existing directory; a partial file is removed on failure.
func (r *Repo) Bundle(ctx context.Context, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("bundle: %s is not absolute", path)
	}
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	// A large history takes longer than the default local timeout.
	ctx, cancel := context.WithTimeout(ctx, bundleTimeout)
	defer cancel()
	if _, err := r.git(ctx, "bundle", "create", "--quiet", tmp, "--all"); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("bundle: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
