package engine

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func elevation(t *testing.T, primary, fallback string) *Elevation {
	t.Helper()
	dir := t.TempDir()
	el := &Elevation{
		StopFile: filepath.Join(dir, "stop"), ReadyFile: filepath.Join(dir, "ready"), LogFile: filepath.Join(dir, "log"),
	}
	repl := strings.NewReplacer("READY", el.ReadyFile, "STOP", el.StopFile)
	el.Command = []string{"/bin/sh", "-c", repl.Replace(primary)}
	if fallback != "" {
		el.Fallback = []string{"/bin/sh", "-c", repl.Replace(fallback)}
	}
	return el
}

const serves = `touch READY; while [ ! -e STOP ]; do sleep 0.05; done`

// Touch ID goes through sudo, which has no terminal to fall back to a password
// on. When sudo cannot authenticate, the password dialog takes over, and the
// failed first attempt is not a crash of the engine.
func TestElevatedStartFallsBackWhenSudoCannotAuthenticate(t *testing.T) {
	el := elevation(t, `echo "sudo: a terminal is required to read the password"; exit 1`, serves)
	r := NewRunner("")
	var unexpected atomic.Int32
	r.OnExit(func(u bool, _ error) {
		if u {
			unexpected.Add(1)
		}
	})
	if err := r.Start(StartOptions{Elevate: el}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !r.IsRunning() {
		t.Fatal("the fallback should be running")
	}
	if n := unexpected.Load(); n != 0 {
		t.Errorf("the failed first attempt was reported as a crash %d times", n)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestElevatedStartDoesNotFallBackOnOtherFailures(t *testing.T) {
	el := elevation(t, `echo "config refused: touches files"; exit 1`, serves)
	r := NewRunner("")
	err := r.Start(StartOptions{Elevate: el})
	if err == nil || !strings.Contains(err.Error(), "config refused") {
		t.Fatalf("err = %v, want the helper's own message", err)
	}
	if r.IsRunning() {
		t.Error("a refused config must not be retried through the password dialog")
	}
}

func TestElevatedStartWithoutFallbackReportsSudoError(t *testing.T) {
	el := elevation(t, `echo "sudo: a password is required"; exit 1`, "")
	r := NewRunner("")
	if err := r.Start(StartOptions{Elevate: el}); err == nil || !strings.Contains(err.Error(), "sudo: a password is required") {
		t.Fatalf("err = %v", err)
	}
}

func TestSudoAuthFailed(t *testing.T) {
	for out, want := range map[string]bool{
		"sudo: a terminal is required to read the password; either use the -S option": true,
		"sudo: a password is required":                          true,
		"sudo: no tty present and no askpass program specified": true,
		"sudo: 1 incorrect password attempt":                    true,
		"config refused":                                        false,
		"":                                                      false,
	} {
		if got := SudoAuthFailed(out); got != want {
			t.Errorf("SudoAuthFailed(%q) = %v, want %v", out, got, want)
		}
	}
}
