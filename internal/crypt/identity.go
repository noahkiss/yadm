package crypt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"

	"github.com/noahkiss/yadm/internal/model"
)

// Both identity files start with a comment line that names the machine:
//
//	# machine: m-a1b2c3
//
// The age file's second line is the AGE-SECRET-KEY; the signing file's second
// line is the standard base64 of the 32-byte Ed25519 seed. age itself skips
// comment lines, so the age file stays a valid age identity file.
const machineComment = "# machine: "

// GenerateIdentity creates a fresh identity for a machine.
func GenerateIdentity(m model.MachineID) (*Identity, error) {
	if err := checkMachineID(m); err != nil {
		return nil, err
	}
	a, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{Machine: m, age: a, sign: priv}, nil
}

func checkMachineID(m model.MachineID) error {
	if m == "" || strings.ContainsAny(string(m), "\n\r\t \"\\") {
		return fmt.Errorf("invalid machine id %q", m)
	}
	return nil
}

// LoadIdentity reads the identity files. It refuses a state directory that
// is not a directory owned by this user with no group or other access, and
// a key file that is a symlink, not a regular file, owned by another user,
// or readable by group or others.
func LoadIdentity(stateDir string) (*Identity, error) {
	if err := checkStateDir(stateDir); err != nil {
		return nil, err
	}
	am, ab, err := readKeyFile(filepath.Join(stateDir, AgeIdentityFile))
	if err != nil {
		return nil, err
	}
	sm, sb, err := readKeyFile(filepath.Join(stateDir, SigningKeyFile))
	if err != nil {
		return nil, err
	}
	if am != sm {
		return nil, fmt.Errorf("identity files name different machines (%q, %q)", am, sm)
	}
	if err := checkMachineID(am); err != nil {
		return nil, err
	}
	a, err := age.ParseX25519Identity(ab)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", AgeIdentityFile, err)
	}
	seed, err := base64.StdEncoding.Strict().DecodeString(sb)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: malformed signing key", SigningKeyFile)
	}
	return &Identity{Machine: am, age: a, sign: ed25519.NewKeyFromSeed(seed)}, nil
}

// checkStateDir requires the state directory to be a directory, owned by
// this user, with no group or other access. It follows a symlink to the
// directory: the checks apply to the directory itself.
func checkStateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("state directory %s is not a directory", dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state directory has mode %04o; want 0700 (chmod 700 it)", fi.Mode().Perm())
	}
	if !ownedByMe(fi) {
		return errors.New("state directory is owned by another user")
	}
	return nil
}

func readKeyFile(p string) (model.MachineID, string, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return "", "", err
	}
	if !fi.Mode().IsRegular() {
		return "", "", fmt.Errorf("%s: not a regular file (a symlink or other type is refused)", filepath.Base(p))
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", "", fmt.Errorf("%s: mode %04o is readable by group or others; want 0600", filepath.Base(p), fi.Mode().Perm())
	}
	if !ownedByMe(fi) {
		return "", "", fmt.Errorf("%s: owned by another user", filepath.Base(p))
	}
	f, err := openNoFollow(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	if after, err := f.Stat(); err != nil || !os.SameFile(fi, after) {
		return "", "", fmt.Errorf("%s: changed while it was read", filepath.Base(p))
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return "", "", err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], machineComment) {
		return "", "", fmt.Errorf("%s: malformed identity file", filepath.Base(p))
	}
	return model.MachineID(strings.TrimPrefix(lines[0], machineComment)), strings.TrimSpace(lines[1]), nil
}

// Save writes the identity files with mode 0600.
func (id *Identity) Save(stateDir string) error {
	if id == nil || id.age == nil || id.sign == nil {
		return errors.New("incomplete identity")
	}
	if err := checkMachineID(id.Machine); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	// The state directory is this tool's own; LoadIdentity refuses it with
	// group or other access.
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return err
	}
	head := machineComment + string(id.Machine) + "\n"
	if err := writeSecret(filepath.Join(stateDir, AgeIdentityFile), []byte(head+id.age.String()+"\n")); err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(id.sign.Seed())
	return writeSecret(filepath.Join(stateDir, SigningKeyFile), []byte(head+seed+"\n"))
}

// writeSecret writes b to p with mode 0600 through a temp file and rename, so
// the key never exists with a wider mode.
func writeSecret(p string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-key-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Member returns the public half of the identity.
func (id *Identity) Member() Member {
	return Member{
		Machine:   id.Machine,
		Recipient: id.age.Recipient().String(),
		SignKey:   base64.StdEncoding.EncodeToString(id.sign.Public().(ed25519.PublicKey)),
	}
}

// matches reports whether m holds this identity's public keys.
func (id *Identity) matches(m Member) bool {
	pub := id.Member()
	return pub.Machine == m.Machine && pub.Recipient == m.Recipient && pub.SignKey == m.SignKey
}

func (m Member) publicKey() (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(m.SignKey)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: member %s has a malformed sign_key", ErrInvalidLog, m.Machine)
	}
	return ed25519.PublicKey(b), nil
}

func (m Member) recipient() (*age.X25519Recipient, error) {
	r, err := age.ParseX25519Recipient(m.Recipient)
	if err != nil {
		return nil, fmt.Errorf("%w: member %s has a malformed recipient", ErrInvalidLog, m.Machine)
	}
	return r, nil
}

func equalMembers(a, b []Member) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
