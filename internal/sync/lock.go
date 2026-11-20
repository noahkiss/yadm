package sync

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// lockPoll is how often a waiting Acquire retries the lock.
const lockPoll = 50 * time.Millisecond

// FileLock returns the flock-based lock in stateDir. Acquire waits at most
// LockTimeout, then fails with ErrLocked.
func FileLock(stateDir string) Lock { return fileLock{dir: stateDir, timeout: LockTimeout} }

// FileLockTimeout is FileLock with another bound on the wait.
func FileLockTimeout(stateDir string, d time.Duration) Lock {
	return fileLock{dir: stateDir, timeout: d}
}

type fileLock struct {
	dir     string
	timeout time.Duration
}

// Acquire takes the exclusive lock. Call the returned release once.
func (l fileLock) Acquire(ctx context.Context) (func(), error) {
	if l.dir == "" {
		return nil, fmt.Errorf("lock: no state directory")
	}
	if err := os.MkdirAll(l.dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(l.dir, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
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
			return func() { unlock(f); f.Close() }, nil
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, ErrLocked
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, fmt.Errorf("%w: %v", ErrLocked, ctx.Err())
		case <-time.After(lockPoll):
		}
	}
}
