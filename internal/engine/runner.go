package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	startupGrace = 800 * time.Millisecond // a process that dies inside this window failed to start
	stopTimeout  = 3 * time.Second        // SIGTERM -> SIGKILL escalation
	maxLogLines  = 1000
)

// ErrAlreadyRunning is returned by Start when a process is already managed.
var ErrAlreadyRunning = errors.New("the proxy engine is already running")

// StartOptions describes how to launch an engine process.
type StartOptions struct {
	Binary string
	Args   []string
	Env    []string // added to the inherited environment

	// Elevate runs the engine through the privileged helper instead (TUN).
	Elevate *Elevation
}

// Elevation describes an engine that runs as root. Command is what the app
// starts (sudo, or the system's password dialog); the helper it launches
// reports through three files in the user's data directory.
type Elevation struct {
	Command   []string
	StopFile  string // created to ask the helper to stop sing-box
	ReadyFile string // created by the helper once sing-box has been running for a moment
	LogFile   string // sing-box's output; read into the activity log
}

// elevatedStartTimeout leaves time for the user to type a password.
const (
	elevatedStartTimeout = 2 * time.Minute
	elevatedStopTimeout  = 8 * time.Second
)

// Status is a snapshot of the runner.
type Status struct {
	Running    bool      `json:"running"`
	PID        int       `json:"pid,omitempty"`
	StartedAt  time.Time `json:"startedAt,omitempty"`
	LastExit   string    `json:"lastExit,omitempty"`
	LastExitAt time.Time `json:"lastExitAt,omitempty"`
}

// process is one launched engine. Each launch gets its own struct so that the
// exit of an old process can never touch the state of a newer one.
type process struct {
	cmd      *exec.Cmd
	elev     *Elevation
	done     chan struct{}
	started  time.Time
	stopping atomic.Bool
}

// Runner supervises a single engine process (Xray or sing-box).
type Runner struct {
	mu         sync.Mutex
	cur        *process
	lastExit   string
	lastExitAt time.Time
	pidFile    string
	onExit     func(unexpected bool, err error)
	logs       *logRing
	prefix     string // prepended to this runner's log lines (chain segments)
}

// NewSegmentRunner creates a runner for a further process of a multi-process
// chain. It writes to parent's log, each line prefixed with label.
func NewSegmentRunner(pidFile string, parent *Runner, label string) *Runner {
	return &Runner{pidFile: pidFile, logs: parent.logs, prefix: "[" + label + "] "}
}

func (r *Runner) emit(s string) { r.logs.add(r.prefix + s) }

// NewRunner creates a runner. pidFile (optional) records the child's PID so a
// stale process from a crashed previous run can be reaped (see ReapStale).
func NewRunner(pidFile string) *Runner {
	return &Runner{pidFile: pidFile, logs: &logRing{}}
}

// OnExit registers a callback invoked (from a goroutine) whenever the process ends.
// unexpected is true when the exit was not caused by Stop.
func (r *Runner) OnExit(fn func(unexpected bool, err error)) {
	r.mu.Lock()
	r.onExit = fn
	r.mu.Unlock()
}

// Start launches the engine and returns once it has survived the startup grace period.
func (r *Runner) Start(opts StartOptions) error {
	r.mu.Lock()
	if r.cur != nil {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	if opts.Elevate != nil {
		r.mu.Unlock()
		return r.startElevated(opts)
	}
	cmd := exec.Command(opts.Binary, opts.Args...)
	cmd.Env = append(os.Environ(), opts.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // survive terminal Ctrl-C; we stop it ourselves
	w := &lineWriter{emit: r.emit}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		r.mu.Unlock()
		return fmt.Errorf("start engine: %w", err)
	}
	p := &process{cmd: cmd, done: make(chan struct{}), started: time.Now()}
	r.cur = p
	r.writePID(cmd.Process.Pid)
	r.emit(fmt.Sprintf("started %s (pid %d)", opts.Binary, cmd.Process.Pid))
	r.mu.Unlock()

	go r.wait(p)

	select {
	case <-p.done:
		return fmt.Errorf("the engine exited right after start: %s", r.logs.tail(5))
	case <-time.After(startupGrace):
		return nil
	}
}

func (r *Runner) wait(p *process) {
	err := p.cmd.Wait()
	w, _ := p.cmd.Stdout.(*lineWriter)
	if w != nil {
		w.flush()
	}
	unexpected := !p.stopping.Load()

	r.mu.Lock()
	if r.cur == p {
		r.cur = nil
		r.removePID()
	}
	r.lastExit = describeExit(err, unexpected)
	r.lastExitAt = time.Now()
	cb := r.onExit
	r.mu.Unlock()

	r.emit("exited: " + describeExit(err, unexpected))
	close(p.done)
	if cb != nil {
		cb(unexpected, err)
	}
}

func describeExit(err error, unexpected bool) string {
	s := "stopped"
	if err != nil {
		s = err.Error()
	}
	if unexpected {
		s = "crashed: " + s
	}
	return s
}

// startElevated launches the helper and waits until it reports sing-box running
// (or until it fails: the user cancelled the password dialog, sudo asked for a
// password, sing-box refused its config).
func (r *Runner) startElevated(opts StartOptions) error {
	el := opts.Elevate
	for _, f := range []string{el.StopFile, el.ReadyFile, el.LogFile} {
		_ = os.Remove(f)
	}
	r.mu.Lock()
	if r.cur != nil {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	cmd := exec.Command(el.Command[0], el.Command[1:]...)
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	w := &lineWriter{emit: r.emit}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		r.mu.Unlock()
		return fmt.Errorf("start the privileged helper: %w", err)
	}
	p := &process{cmd: cmd, elev: el, done: make(chan struct{}), started: time.Now()}
	r.cur = p
	r.writePID(cmd.Process.Pid)
	r.emit("waiting for administrator approval to start sing-box with a TUN interface")
	r.mu.Unlock()

	go r.wait(p)
	go r.tailLog(p)

	deadline := time.After(elevatedStartTimeout)
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			return fmt.Errorf("could not start with administrator rights: %s", r.logs.tail(4))
		case <-deadline:
			_ = r.Stop()
			return errors.New("timed out waiting for administrator approval")
		case <-tick.C:
			if _, err := os.Stat(el.ReadyFile); err == nil {
				r.emit("sing-box is running with administrator rights")
				return nil
			}
		}
	}
}

// tailLog copies the elevated engine's log file into the activity log.
func (r *Runner) tailLog(p *process) {
	lw := &lineWriter{emit: r.emit}
	var off int64
	read := func() {
		f, err := os.Open(p.elev.LogFile)
		if err != nil {
			return
		}
		defer f.Close()
		if _, err := f.Seek(off, 0); err != nil {
			return
		}
		buf := make([]byte, 64<<10)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				off += int64(n)
				_, _ = lw.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-p.done:
			time.Sleep(200 * time.Millisecond)
			read()
			lw.flush()
			return
		case <-tick.C:
			read()
		}
	}
}

// Stop terminates the process (SIGTERM, then SIGKILL) and waits for it to exit.
func (r *Runner) Stop() error {
	r.mu.Lock()
	p := r.cur
	r.mu.Unlock()
	if p == nil {
		return nil
	}
	p.stopping.Store(true)
	if p.elev != nil {
		// root's process cannot be signalled by us: ask the helper to stop it
		_ = os.WriteFile(p.elev.StopFile, nil, 0o600)
		select {
		case <-p.done:
			return nil
		case <-time.After(elevatedStopTimeout):
		}
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(stopTimeout):
		_ = p.cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(2 * time.Second):
			return errors.New("the engine did not exit after SIGKILL")
		}
	}
	return nil
}

// IsRunning reports whether a managed process is alive.
func (r *Runner) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cur != nil
}

// Status returns a snapshot.
func (r *Runner) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{LastExit: r.lastExit, LastExitAt: r.lastExitAt}
	if r.cur != nil {
		st.Running = true
		st.PID = r.cur.cmd.Process.Pid
		st.StartedAt = r.cur.started
	}
	return st
}

// Logs returns log lines with sequence number >= since, and the next sequence to ask for.
func (r *Runner) Logs(since int) ([]string, int) { return r.logs.since(since) }

func (r *Runner) writePID(pid int) {
	if r.pidFile != "" {
		_ = os.WriteFile(r.pidFile, []byte(strconv.Itoa(pid)), 0o600)
	}
}

func (r *Runner) removePID() {
	if r.pidFile != "" {
		_ = os.Remove(r.pidFile)
	}
}

// ReapStale kills a leftover engine process from a previous crashed run, but only if the
// recorded PID still belongs to a command containing mustContain (so a reused
// PID of an unrelated process is never signalled).
func ReapStale(pidFile, mustContain string) (reaped bool) {
	b, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}
	defer os.Remove(pidFile)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil || !bytes.Contains(out, []byte(mustContain)) {
		return false
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	time.Sleep(300 * time.Millisecond)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	return true
}

// ---- log ring ----

type logRing struct {
	mu    sync.Mutex
	lines []string
	first int // sequence number of lines[0]
}

func (l *logRing) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, time.Now().Format("15:04:05")+" "+s)
	if over := len(l.lines) - maxLogLines; over > 0 {
		l.lines = append([]string(nil), l.lines[over:]...)
		l.first += over
	}
}

func (l *logRing) since(seq int) ([]string, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	next := l.first + len(l.lines)
	if seq < l.first {
		seq = l.first
	}
	if seq >= next {
		return []string{}, next
	}
	return append([]string(nil), l.lines[seq-l.first:]...), next
}

func (l *logRing) tail(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.lines) < n {
		n = len(l.lines)
	}
	return strings.Join(l.lines[len(l.lines)-n:], " | ")
}

// lineWriter splits a byte stream into lines.
type lineWriter struct {
	mu   sync.Mutex
	buf  []byte
	emit func(string)
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(w.buf[:i])); line != "" {
			w.emit(line)
		}
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > 64<<10 { // pathological line without newline
		w.emit(strings.TrimSpace(string(w.buf)))
		w.buf = nil
	}
	return len(p), nil
}

func (w *lineWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s := strings.TrimSpace(string(w.buf)); s != "" {
		w.emit(s)
	}
	w.buf = nil
}
