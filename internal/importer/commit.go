package importer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/fleet"
	"github.com/noahkiss/yadm/internal/manifest"
	"github.com/noahkiss/yadm/internal/model"
)

// writeOutput creates the output repository, fetches the legacy head into it
// and writes one commit whose parent is that head. Content goes straight into
// the object store through fast-import; the importer writes no file of its
// own outside git. On failure it removes the output directory again.
func writeOutput(ctx context.Context, opts Options, conv *converted) (model.CommitID, error) {
	out, err := filepath.Abs(opts.Output)
	if err != nil {
		return "", err
	}
	_, statErr := os.Stat(out)
	created := os.IsNotExist(statErr)
	ok := false
	defer func() {
		if !ok {
			if created {
				os.RemoveAll(out)
			} else {
				clearDir(out)
			}
		}
	}()
	branch := opts.Branch
	if branch == "" {
		branch = "main"
	}
	legacy, err := filepath.Abs(opts.Legacy)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", err
	}
	if _, err := runGit(ctx, out, nil, "init", "-q", "-b", branch); err != nil {
		return "", err
	}
	if _, err := runGit(ctx, out, nil, "fetch", "-q", "--no-tags", legacy, "HEAD"); err != nil {
		return "", err
	}
	got, err := runGit(ctx, out, nil, "rev-parse", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(got)) != conv.LegacyHead {
		return "", fmt.Errorf("legacy head moved during the import")
	}

	stream := fastImportStream(branch, committerIdent(ctx, legacy), commitMessage(conv), conv)
	if _, err := runGit(ctx, out, bytes.NewReader(stream), "fast-import", "--quiet", "--done"); err != nil {
		return "", err
	}
	head, err := runGit(ctx, out, nil, "rev-parse", "refs/heads/"+branch)
	if err != nil {
		return "", err
	}
	if _, err := runGit(ctx, out, nil, "reset", "-q", "--hard", "refs/heads/"+branch); err != nil {
		return "", err
	}
	ok = true
	return model.CommitID(strings.TrimSpace(string(head))), nil
}

func clearDir(dir string) {
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}

func commitMessage(conv *converted) string {
	return fmt.Sprintf("chore: import legacy yadm repository\n\n%d files, %d machines.\n\nLegacy-Head: %s\n",
		len(conv.Mappings), conv.Machines, conv.LegacyHead)
}

// committerIdent returns "Name <email>" from the environment or the user's
// git config, with a neutral fallback.
func committerIdent(ctx context.Context, dir string) string {
	name, email := os.Getenv("GIT_COMMITTER_NAME"), os.Getenv("GIT_COMMITTER_EMAIL")
	if name == "" {
		name = gitConfigValue(ctx, dir, "user.name")
	}
	if email == "" {
		email = gitConfigValue(ctx, dir, "user.email")
	}
	if name == "" {
		name = "yadm import"
	}
	if email == "" {
		email = "import@yadm.invalid"
	}
	return name + " <" + email + ">"
}

// gitConfigValue reads one value from the user's normal git config.
func gitConfigValue(ctx context.Context, dir, key string) string {
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", key)
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// fastImportStream builds one commit: the whole new tree, parent the legacy head.
func fastImportStream(branch, ident, msg string, conv *converted) []byte {
	var b bytes.Buffer
	now := time.Now().Unix()
	fmt.Fprintf(&b, "commit refs/heads/%s\n", branch)
	fmt.Fprintf(&b, "author %s %d +0000\n", ident, now)
	fmt.Fprintf(&b, "committer %s %d +0000\n", ident, now)
	fmt.Fprintf(&b, "data %d\n%s\n", len(msg), msg)
	fmt.Fprintf(&b, "from %s\n", conv.LegacyHead)
	b.WriteString("deleteall\n")
	write := func(p string, mode string, data []byte) {
		fmt.Fprintf(&b, "M %s inline %s\n", mode, fastImportPath(p))
		fmt.Fprintf(&b, "data %d\n", len(data))
		b.Write(data)
		b.WriteByte('\n')
	}
	write(manifest.FileName, "100644", conv.Manifest)
	write(fleet.FileName, "100644", conv.Fleet)
	paths := make([]string, 0, len(conv.Files))
	for p := range conv.Files {
		paths = append(paths, string(p))
	}
	sort.Strings(paths)
	for _, p := range paths {
		f := conv.Files[model.SourcePath(p)]
		mode := "100644"
		if f.Exec {
			mode = "100755"
		}
		write(p, mode, f.Data)
	}
	b.WriteString("\ndone\n")
	return b.Bytes()
}

// fastImportPath quotes a path the way fast-import reads it.
func fastImportPath(p string) string {
	if !strings.ContainsAny(p, "\"\n\\") && !strings.HasPrefix(p, "\"") {
		return p
	}
	return strconv.Quote(p)
}
