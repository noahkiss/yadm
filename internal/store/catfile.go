package store

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// catFileIdle is how long the batch reader process may sit unused before it
// is stopped. The next read starts a new one.
const catFileIdle = 30 * time.Second

// errUnbatchable marks an object name the batch protocol cannot carry.
var errUnbatchable = errors.New("object name cannot be sent to cat-file --batch")

// catFile is a long-lived `git cat-file --batch` process shared by every
// read of one Repo. It starts on first use, serializes reads with a mutex,
// restarts when the process dies, and stops after catFileIdle without use.
// Its stdout carries only what git stores: shared plaintext or sealed
// ciphertext, never enclave plaintext. Nothing here logs object bytes.
type catFile struct {
	dir  string
	env  []string
	idle time.Duration
	bin  string // "git"; tests swap in a stand-in

	mu      sync.Mutex
	proc    *catProc
	lastUse time.Time
	timer   *time.Timer
}

type catProc struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *bufio.Reader
}

// catResult is one answer of the batch reader.
type catResult struct {
	typ     string // blob, tree, commit or tag; "" when missing
	data    []byte
	missing bool
}

func newCatFile(dir string, env []string) *catFile {
	return &catFile{dir: dir, env: env, idle: catFileIdle, bin: "git"}
}

// read looks up one object name (an id or a "rev:path" expression). A
// cancelled ctx kills the process and returns ctx.Err(); the next read
// starts a fresh one. A process that died between reads is restarted once,
// transparently.
func (c *catFile) read(ctx context.Context, name string) (catResult, error) {
	if name == "" || strings.ContainsAny(name, "\n\r\x00") {
		return catResult{}, errUnbatchable
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, localTimeout)
		defer cancel()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if cerr := ctx.Err(); cerr != nil {
			return catResult{}, cerr
		}
		if c.proc == nil {
			if c.proc, err = c.start(); err != nil {
				return catResult{}, err
			}
		}
		p := c.proc
		stop := context.AfterFunc(ctx, func() { p.cmd.Process.Kill() })
		var res catResult
		res, err = p.roundTrip(name)
		if !stop() {
			// The kill ran: the process is gone whatever the read returned.
			c.stopLocked()
			if err != nil || ctx.Err() != nil {
				return catResult{}, ctx.Err()
			}
		}
		if err == nil {
			c.touchLocked()
			return res, nil
		}
		c.stopLocked()
		if cerr := ctx.Err(); cerr != nil {
			return catResult{}, cerr
		}
	}
	return catResult{}, fmt.Errorf("cat-file --batch: %w", err)
}

func (c *catFile) start() (*catProc, error) {
	args := append([]string{"-C", c.dir}, secrecyArgs...)
	args = append(args, "cat-file", "--batch")
	cmd := exec.Command(c.bin, args...)
	cmd.Env = c.env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cat-file --batch: %w", err)
	}
	spawns.Add(1)
	return &catProc{cmd: cmd, stdin: stdin, out: bufio.NewReaderSize(stdout, 64<<10)}, nil
}

// roundTrip sends one name and reads "<oid> <type> <size>\n<bytes>\n" or
// "<name> missing\n". Errors never quote the stream: after a desync it
// could hold object bytes.
func (p *catProc) roundTrip(name string) (catResult, error) {
	if _, err := io.WriteString(p.stdin, name+"\n"); err != nil {
		return catResult{}, err
	}
	line, err := p.out.ReadString('\n')
	if err != nil {
		return catResult{}, err
	}
	line = strings.TrimSuffix(line, "\n")
	if strings.HasSuffix(line, " missing") || strings.HasSuffix(line, " ambiguous") {
		return catResult{missing: true}, nil
	}
	f := strings.Fields(line)
	if len(f) != 3 {
		return catResult{}, errors.New("bad batch header")
	}
	size, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil || size < 0 {
		return catResult{}, errors.New("bad batch header")
	}
	data := make([]byte, size+1)
	if _, err := io.ReadFull(p.out, data); err != nil {
		return catResult{}, err
	}
	if data[size] != '\n' {
		return catResult{}, errors.New("missing record terminator")
	}
	return catResult{typ: f[1], data: data[:size:size]}, nil
}

// touchLocked records a use and arms the idle timer.
func (c *catFile) touchLocked() {
	c.lastUse = time.Now()
	if c.timer == nil {
		c.timer = time.AfterFunc(c.idle, c.reap)
	}
}

// reap stops the process once it has been idle for c.idle.
func (c *catFile) reap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc == nil {
		c.timer = nil
		return
	}
	if left := c.idle - time.Since(c.lastUse); left > 0 {
		c.timer.Reset(left)
		return
	}
	c.timer = nil
	c.stopLocked()
}

// stopLocked ends the process, if any. Closing stdin lets git exit on its
// own; the kill covers a process that is stuck.
func (c *catFile) stopLocked() {
	p := c.proc
	if p == nil {
		return
	}
	c.proc = nil
	p.stdin.Close()
	p.cmd.Process.Kill()
	p.cmd.Wait()
}

// reset stops the process so the next read starts afresh; it is not closed
// for good. Fetch calls it so new packs are seen without relying on git's
// pack rescan.
func (c *catFile) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

// close stops the process and the idle timer. A later read starts a new
// process, so a closed Repo still works; it only stops holding one open.
func (c *catFile) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.stopLocked()
}

// pid returns the running process id, or 0. Tests use it.
func (c *catFile) pid() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.proc == nil {
		return 0
	}
	return c.proc.cmd.Process.Pid
}
