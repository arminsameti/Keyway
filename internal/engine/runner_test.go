package engine

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-xray")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func opts(bin string) StartOptions {
	return StartOptions{Binary: bin, Args: []string{"-c", "/dev/null"}}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestStartStopAndLogs(t *testing.T) {
	r := NewRunner(filepath.Join(t.TempDir(), "x.pid"))
	if err := r.Start(opts(script(t, "echo hello-from-xray\nexec sleep 30"))); err != nil {
		t.Fatal(err)
	}
	if !r.IsRunning() {
		t.Fatal("should be running")
	}
	if err := r.Start(opts("/bin/true")); err != ErrAlreadyRunning {
		t.Fatalf("second start: %v", err)
	}
	waitFor(t, func() bool { l, _ := r.Logs(0); return strings.Contains(strings.Join(l, "\n"), "hello-from-xray") }, "log line")
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if r.IsRunning() {
		t.Fatal("should be stopped")
	}
	if st := r.Status(); st.Running || !strings.Contains(st.LastExit, "") {
		t.Fatalf("status: %+v", st)
	}
}

func TestImmediateExitIsReportedAsFailure(t *testing.T) {
	r := NewRunner("")
	err := r.Start(opts(script(t, "echo bad-config >&2\nexit 3")))
	if err == nil || !strings.Contains(err.Error(), "bad-config") {
		t.Fatalf("want failure including output, got %v", err)
	}
	if r.IsRunning() {
		t.Fatal("must not report running")
	}
}

// The old implementation let a previous process's Wait goroutine flip the
// "running" flag of the NEW process. Restart repeatedly and verify that never happens.
func TestRestartDoesNotClobberNewProcess(t *testing.T) {
	r := NewRunner("")
	bin := script(t, "exec sleep 30")
	for i := 0; i < 5; i++ {
		if err := r.Stop(); err != nil {
			t.Fatal(err)
		}
		if err := r.Start(opts(bin)); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond) // let the previous Wait goroutine finish
		if !r.IsRunning() {
			t.Fatalf("iteration %d: new process reported as stopped", i)
		}
	}
	_ = r.Stop()
}

func TestUnexpectedExitCallback(t *testing.T) {
	r := NewRunner("")
	var unexpected, calls atomic.Int32
	r.OnExit(func(u bool, err error) {
		calls.Add(1)
		if u {
			unexpected.Add(1)
		}
	})
	// survives the startup grace, then dies by itself
	if err := r.Start(opts(script(t, "sleep 1.2\nexit 1"))); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return calls.Load() == 1 }, "exit callback")
	if unexpected.Load() != 1 {
		t.Fatal("self-exit must be reported as unexpected")
	}
	if r.IsRunning() {
		t.Fatal("should be stopped")
	}

	if err := r.Start(opts(script(t, "exec sleep 30"))); err != nil {
		t.Fatal(err)
	}
	_ = r.Stop()
	waitFor(t, func() bool { return calls.Load() == 2 }, "second callback")
	if unexpected.Load() != 1 {
		t.Fatal("Stop() must not count as unexpected")
	}
}

func TestStopEscalatesToKill(t *testing.T) {
	r := NewRunner("")
	// ignores SIGTERM
	if err := r.Start(opts(script(t, "trap '' TERM\nwhile true; do sleep 1; done"))); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	if r.IsRunning() {
		t.Fatal("still running after Stop")
	}
	if time.Since(start) > 8*time.Second {
		t.Fatal("kill escalation too slow")
	}
}

func TestLogRingSequence(t *testing.T) {
	l := &logRing{}
	for i := 0; i < maxLogLines+10; i++ {
		l.add("x")
	}
	lines, next := l.since(0)
	if len(lines) != maxLogLines || next != maxLogLines+10 {
		t.Fatalf("len=%d next=%d", len(lines), next)
	}
	l.add("y")
	more, next2 := l.since(next)
	if len(more) != 1 || next2 != next+1 || !strings.HasSuffix(more[0], "y") {
		t.Fatalf("incremental read: %v %d", more, next2)
	}
	if none, n3 := l.since(next2); len(none) != 0 || n3 != next2 {
		t.Fatal("expected empty read")
	}
}

func TestPIDFileLifecycle(t *testing.T) {
	pid := filepath.Join(t.TempDir(), "x.pid")
	r := NewRunner(pid)
	if err := r.Start(opts(script(t, "exec sleep 30"))); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(pid); err != nil {
		t.Fatal("pid file missing while running")
	}
	_ = r.Stop()
	waitFor(t, func() bool { _, err := os.Stat(pid); return err != nil }, "pid file removal")
}

func TestReapStaleOnlyKillsMatchingCommand(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "x.pid")
	// our own test process: its command does not contain the marker, so it must survive
	_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	if ReapStale(pidFile, "/definitely/not/in/this/cmdline") {
		t.Fatal("must not kill a non-matching process")
	}
	if _, err := os.Stat(pidFile); err == nil {
		t.Fatal("pid file should be consumed")
	}
	_ = os.WriteFile(pidFile, []byte("garbage"), 0o600)
	if ReapStale(pidFile, "x") {
		t.Fatal("garbage pid must be ignored")
	}
}

// fakeHelper behaves like xf-tun-helper: log, ready file, stop on the stop file.
func fakeHelper(t *testing.T, readyAfter string) (StartOptions, *Elevation) {
	t.Helper()
	dir := t.TempDir()
	el := &Elevation{StopFile: filepath.Join(dir, "stop"), ReadyFile: filepath.Join(dir, "ready"), LogFile: filepath.Join(dir, "log")}
	body := "echo tun-up >> " + el.LogFile + "\nsleep " + readyAfter + "\ntouch " + el.ReadyFile + "\n" +
		"while [ ! -e " + el.StopFile + " ]; do sleep 0.1; done\necho bye >> " + el.LogFile
	el.Command = []string{script(t, body)}
	return StartOptions{Elevate: el}, el
}

func TestElevatedStartWaitsForReadyAndStopsThroughTheStopFile(t *testing.T) {
	o, _ := fakeHelper(t, "0.5")
	r := NewRunner(filepath.Join(t.TempDir(), "x.pid"))
	begin := time.Now()
	if err := r.Start(o); err != nil {
		t.Fatal(err)
	}
	if time.Since(begin) < 400*time.Millisecond {
		t.Error("Start must wait for the ready file, not just the startup grace")
	}
	if !r.IsRunning() {
		t.Fatal("not running")
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !r.IsRunning() }, "stop")
	var all string
	waitFor(t, func() bool {
		lines, _ := r.Logs(0)
		all = strings.Join(lines, "\n")
		return strings.Contains(all, "tun-up") && strings.Contains(all, "bye")
	}, "the helper's log file in the activity log")
	if st := r.Status(); st.LastExit != "stopped" {
		t.Errorf("a requested stop is not a crash: %q", st.LastExit)
	}
}

func TestElevatedStartReportsACancelledPasswordDialog(t *testing.T) {
	r := NewRunner("")
	err := r.Start(StartOptions{Elevate: &Elevation{Command: []string{script(t, "echo 'User canceled.' >&2\nexit 1")},
		StopFile: filepath.Join(t.TempDir(), "s"), ReadyFile: filepath.Join(t.TempDir(), "r"), LogFile: filepath.Join(t.TempDir(), "l")}})
	if err == nil || !strings.Contains(err.Error(), "User canceled") {
		t.Errorf("err = %v", err)
	}
	if r.IsRunning() {
		t.Error("nothing is running after a failed start")
	}
}
