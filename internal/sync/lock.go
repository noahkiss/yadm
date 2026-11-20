package sync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// lockPoll is how often a waiting Acquire retries the lock.
const lockPoll = 50 * time.Millisecond

// Lock file names in the state directory. The sync lock serializes local
// writes: capture, commit, replay, apply, publish. The network lock
// serializes fetch, push and `git ls-remote`. No process waits on the
// network while it holds the sync lock.
const (
	LockFile    = "lock"
	NetLockFile = "netlock"
)

// Lock names in a LockedError and a HeldLock.
const (
	LockSync    = "sync"
	LockNetwork = "network"
)

// ErrLocked means another yadm process holds the sync lock.
var ErrLocked = errors.New("another yadm process holds the lock")

// ErrNetBusy means another yadm process holds the network lock. A caller
// that meets it skips its network step; the next sync does it.
var ErrNetBusy = errors.New("another yadm process is using the network")

// Holder is the record a lock's holder writes into the lock file: its pid,
// its command (the binary's base name and subcommand words, no paths) and
// when it took the lock.
type Holder struct {
	PID     int       `json:"pid"`
	Command string    `json:"command"`
	Since   time.Time `json:"since"`
}

// LockedError is a lock held by another process, with its holder when the
// record is readable and the holder is alive. It matches ErrLocked for the
// sync lock and ErrNetBusy for the network lock.
type LockedError struct {
	Lock   string  // LockSync or LockNetwork
	Holder *Holder // nil: unknown
	Cause  error   // the context error when the wait was cut short
}

func (e *LockedError) Error() string {
	base := ErrLocked.Error()
	if e.Lock == LockNetwork {
		base = ErrNetBusy.Error()
	}
	if h := e.Holder; h != nil {
		base += fmt.Sprintf(" (%s lock: pid %d, %s, held %s)", e.Lock, h.PID, h.Command, holdAge(h.Since))
	}
	if e.Cause != nil {
		base += ": " + e.Cause.Error()
	}
	return base
}

func (e *LockedError) Unwrap() error { return e.Cause }

func (e *LockedError) Is(target error) bool {
	if e.Lock == LockNetwork {
		return target == ErrNetBusy
	}
	return target == ErrLocked
}

// holdAge is the wall-clock age of a lock, rounded to the second.
func holdAge(since time.Time) time.Duration {
	d := time.Since(since).Round(time.Second)
	if d < 0 {
		return 0
	}
	return d
}

// HeldLock is a lock another live process holds.
type HeldLock struct {
	Lock   string        `json:"lock"`
	Holder Holder        `json:"holder"`
	Age    time.Duration `json:"-"` // wall-clock time since Holder.Since
}

// HeldLocks reads the holder records of the sync and network locks in
// stateDir. A record that is empty, does not parse or names a dead pid is
// ignored. It never takes a lock.
func HeldLocks(stateDir string) []HeldLock {
	var out []HeldLock
	for _, l := range []struct{ name, file string }{{LockSync, LockFile}, {LockNetwork, NetLockFile}} {
		if h := readHolder(filepath.Join(stateDir, l.file)); h != nil {
			out = append(out, HeldLock{Lock: l.name, Holder: *h, Age: holdAge(h.Since)})
		}
	}
	return out
}

// readHolder returns the live holder recorded in a lock file, or nil.
func readHolder(path string) *Holder {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return nil
	}
	var h Holder
	if json.Unmarshal(b, &h) != nil || h.PID <= 0 || !pidAlive(h.PID) {
		return nil
	}
	return &h
}

// selfCommand names this process for a holder record: the binary's base
// name and the words of its command line that are subcommands or bare
// flags. Anything with a path separator or a value is left out.
func selfCommand() string {
	if len(os.Args) == 0 {
		return "?"
	}
	words := []string{filepath.Base(os.Args[0])}
	for _, a := range os.Args[1:] {
		if len(words) >= 5 {
			break
		}
		if a == "" || strings.ContainsAny(a, "/\\=:~ ") || len(a) > 24 {
			continue
		}
		words = append(words, a)
	}
	return strings.Join(words, " ")
}

// FileLock returns the flock-based sync lock in stateDir. Acquire waits at
// most LockTimeout, then fails with ErrLocked.
func FileLock(stateDir string) Lock {
	return fileLock{dir: stateDir, file: LockFile, timeout: LockTimeout}
}

// FileLockTimeout is FileLock with another bound on the wait.
func FileLockTimeout(stateDir string, d time.Duration) Lock {
	return fileLock{dir: stateDir, file: LockFile, timeout: d}
}

// NetLock serializes network calls on one machine. TryAcquire never waits:
// when another process holds it, it fails with an error that matches
// ErrNetBusy, and the caller skips its network step.
type NetLock interface {
	TryAcquire() (release func(), err error)
}

// FileNetLock returns the flock-based network lock in stateDir.
func FileNetLock(stateDir string) NetLock { return fileLock{dir: stateDir, file: NetLockFile} }

type fileLock struct {
	dir     string
	file    string
	timeout time.Duration
}

func (l fileLock) name() string {
	if l.file == NetLockFile {
		return LockNetwork
	}
	return LockSync
}

// TryAcquire takes the lock if it is free, without waiting.
func (l fileLock) TryAcquire() (func(), error) {
	f, err := l.open()
	if err != nil {
		return nil, err
	}
	ok, err := tryLock(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	if !ok {
		f.Close()
		return nil, &LockedError{Lock: l.name(), Holder: readHolder(filepath.Join(l.dir, l.file))}
	}
	return l.hold(f), nil
}

// Acquire takes the exclusive lock, waiting at most the lock's timeout.
// Call the returned release once.
func (l fileLock) Acquire(ctx context.Context) (func(), error) {
	f, err := l.open()
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(l.timeout)
	for {
		ok, err := tryLock(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		if ok {
			return l.hold(f), nil
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, &LockedError{Lock: l.name(), Holder: readHolder(filepath.Join(l.dir, l.file))}
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, &LockedError{Lock: l.name(), Holder: readHolder(filepath.Join(l.dir, l.file)), Cause: ctx.Err()}
		case <-time.After(lockPoll):
		}
	}
}

func (l fileLock) open() (*os.File, error) {
	if l.dir == "" {
		return nil, fmt.Errorf("lock: no state directory")
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(l.dir, l.file), os.O_RDWR|os.O_CREATE, 0o600)
}

// hold writes the holder record into the locked file and returns the
// release, which clears the record before it unlocks. A record that cannot
// be written leaves the lock held and its holder unknown.
func (l fileLock) hold(f *os.File) func() {
	if b, err := json.Marshal(Holder{PID: os.Getpid(), Command: selfCommand(), Since: time.Now()}); err == nil {
		if f.Truncate(0) == nil {
			_, _ = f.WriteAt(b, 0)
		}
	}
	return func() {
		_ = f.Truncate(0)
		unlock(f)
		f.Close()
	}
}

// noNetLock is the network lock of a Syncer without a state directory.
type noNetLock struct{}

func (noNetLock) TryAcquire() (func(), error) { return func() {}, nil }
