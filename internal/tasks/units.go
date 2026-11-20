package tasks

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/noahkiss/yadm/internal/manifest"
)

// UnitReloader reloads one service unit.
type UnitReloader interface {
	Reload(ctx context.Context, u manifest.Unit, home string) error
}

// Commander runs one service-manager command. Tests pass a fake, so they
// never call launchctl or systemctl.
type Commander interface {
	Run(ctx context.Context, argv []string) (output []byte, err error)
}

// unitTimeout bounds each service-manager command.
const unitTimeout = 30 * time.Second

// SystemReloader returns the launchd/systemd reloader for this OS.
func SystemReloader(goos string) (UnitReloader, error) {
	return NewReloader(goos, ExecCommander{}, os.Getuid())
}

// NewReloader returns the reloader for goos with c running the commands.
// uid names the launchd GUI domain ("gui/<uid>").
//
//   - darwin reloads launchd units: `launchctl bootout gui/<uid> <plist>`
//     (an error there means it was not loaded and is ignored), then
//     `launchctl bootstrap gui/<uid> <plist>`.
//   - linux reloads systemd user units: `systemctl --user daemon-reload`,
//     then `systemctl --user restart <unit name>`.
//
// A unit of the other kind is an error, not a silent skip.
//
// A unit with reload = "never" is never reloaded. The launchd reloader also
// skips a job whose plist sets KeepAlive (a reload would restart a job that
// must stay up), the job that runs this reload (its label is
// $XPC_SERVICE_NAME), and a plist it cannot read as XML. Each skip returns a
// *SkipError: the runner records it as a result detail, not a failure.
func NewReloader(goos string, c Commander, uid int) (UnitReloader, error) {
	switch goos {
	case "darwin":
		return launchdReloader{c: c, uid: uid, getenv: os.Getenv}, nil
	case "linux":
		return systemdReloader{c: c}, nil
	}
	return nil, fmt.Errorf("unit reload: unsupported OS %q", goos)
}

// unitPath resolves a unit target under home and refuses one that escapes it.
func unitPath(u manifest.Unit, home string) (string, error) {
	t := string(u.Target)
	if t == "" || path.IsAbs(t) || strings.HasPrefix(path.Clean(t), "../") || path.Clean(t) == ".." {
		return "", fmt.Errorf("unit %q: target must be a path under $HOME", t)
	}
	if home == "" {
		return "", fmt.Errorf("unit %q: no home directory", t)
	}
	return filepath.Join(home, filepath.FromSlash(path.Clean(t))), nil
}

// SkipError reports a unit the reloader left alone on purpose.
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "reload skipped: " + e.Reason }

// IsSkip reports whether err is a deliberate skip, and its reason.
func IsSkip(err error) (string, bool) {
	var s *SkipError
	if errors.As(err, &s) {
		return s.Reason, true
	}
	return "", false
}

type launchdReloader struct {
	c      Commander
	uid    int
	getenv func(string) string
}

func (l launchdReloader) Reload(ctx context.Context, u manifest.Unit, home string) error {
	if u.Kind != manifest.UnitLaunchd {
		return fmt.Errorf("unit %s: kind %q cannot be reloaded on darwin", u.Target, u.Kind)
	}
	p, err := unitPath(u, home)
	if err != nil {
		return err
	}
	if u.Reload == manifest.ReloadNever {
		return &SkipError{Reason: `reload = "never"`}
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return &SkipError{Reason: "cannot read the plist: " + err.Error()}
	}
	info, err := readPlist(b)
	if err != nil {
		return &SkipError{Reason: "plist is not readable XML: " + err.Error()}
	}
	if info.keepAlive {
		return &SkipError{Reason: "KeepAlive job; it is not restarted, the new plist takes effect at its next load"}
	}
	if l.getenv != nil && info.label != "" && l.getenv("XPC_SERVICE_NAME") == info.label {
		return &SkipError{Reason: "the job runs this reload"}
	}
	domain := "gui/" + strconv.Itoa(l.uid)
	_, _ = l.c.Run(ctx, []string{"launchctl", "bootout", domain, p})
	if out, err := l.c.Run(ctx, []string{"launchctl", "bootstrap", domain, p}); err != nil {
		return fmt.Errorf("launchctl bootstrap %s: %w: %s", u.Target, err, strings.TrimSpace(string(out)))
	}
	return nil
}

type systemdReloader struct{ c Commander }

func (s systemdReloader) Reload(ctx context.Context, u manifest.Unit, home string) error {
	if u.Kind != manifest.UnitSystemd {
		return fmt.Errorf("unit %s: kind %q cannot be reloaded on linux", u.Target, u.Kind)
	}
	if _, err := unitPath(u, home); err != nil {
		return err
	}
	if u.Reload == manifest.ReloadNever {
		return &SkipError{Reason: `reload = "never"`}
	}
	name := path.Base(string(u.Target))
	if out, err := s.c.Run(ctx, []string{"systemctl", "--user", "daemon-reload"}); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := s.c.Run(ctx, []string{"systemctl", "--user", "restart", name}); err != nil {
		return fmt.Errorf("systemctl restart %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ExecCommander runs commands as child processes with a timeout.
type ExecCommander struct{}

// Run runs argv and returns its combined output.
func (ExecCommander) Run(ctx context.Context, argv []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	ctx, cancel := context.WithTimeout(ctx, unitTimeout)
	defer cancel()
	return exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
}

// plistInfo is what the launchd reloader reads from a plist.
type plistInfo struct {
	label     string
	keepAlive bool // KeepAlive is true or a dictionary of conditions
}

// readPlist reads Label and KeepAlive from the top-level dict of an XML
// property list. A binary plist is an error.
func readPlist(b []byte) (plistInfo, error) {
	var info plistInfo
	if bytes.HasPrefix(b, []byte("bplist")) {
		return info, errors.New("binary plist")
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	depth := 0     // element depth; the top-level dict is at depth 2 (plist > dict)
	key := ""      // the last top-level <key>
	inKey := false // reading a top-level <key>
	inLabel := false
	sawDict := false
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				if t.Name.Local != "dict" {
					return info, fmt.Errorf("top-level element is <%s>, want <dict>", t.Name.Local)
				}
				sawDict = true
			}
			if depth == 3 {
				switch t.Name.Local {
				case "key":
					inKey, key = true, ""
				case "true", "dict":
					if key == "KeepAlive" {
						info.keepAlive = true
					}
				case "string":
					inLabel = key == "Label"
				}
			}
		case xml.EndElement:
			if depth == 3 {
				if t.Name.Local != "key" {
					key = ""
				}
				inKey, inLabel = false, false
			}
			depth--
		case xml.CharData:
			if inKey {
				key += string(t)
			} else if inLabel {
				info.label += string(t)
			}
		}
	}
	if !sawDict {
		return info, errors.New("no top-level dict")
	}
	info.label = strings.TrimSpace(info.label)
	return info, nil
}
