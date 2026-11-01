package privileged

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// InstallDir holds the root-owned copy of the helper and of sing-box that
// one-time authorization runs.
const InstallDir = "/Library/Application Support/Keyway"

// PinnedBinary is the sing-box that "run-pinned" executes.
var PinnedBinary = filepath.Join(InstallDir, "sing-box")

// RunOptions describe one supervised sing-box.
type RunOptions struct {
	Binary     string // sing-box to run; Pinned requires it to be root-owned and unwritable by others
	Pinned     bool   // run Binary in place instead of a fresh root-owned copy
	ConfigPath string
	ParentPID  int // exit when this process is gone
	UID        int // owner of the files handed back to the user
	LogFile    string
	StopFile   string // the user's app creates it to ask for a clean stop
	ReadyFile  string // created once sing-box has been running for a moment
	PIDFile    string
	// TempRoot is where the private working directory is made (default /var/run).
	TempRoot string
	// AllowNonRoot lets tests run without administrator rights.
	AllowNonRoot bool
}

const (
	readyAfter  = 1500 * time.Millisecond
	pollEvery   = 300 * time.Millisecond
	killTimeout = 5 * time.Second
)

// Run starts sing-box with the validated config and supervises it until it
// exits, the stop file appears or the parent app disappears.
func Run(o RunOptions) error {
	if os.Geteuid() != 0 && !o.AllowNonRoot {
		return errors.New("this must run as root")
	}
	if o.ParentPID <= 1 {
		return errors.New("a parent process is required")
	}
	raw, err := readSmall(o.ConfigPath, maxConfigBytes+1)
	if err != nil {
		return fmt.Errorf("read the config: %w", err)
	}
	if err := ValidateConfig(raw); err != nil {
		return err
	}
	root := o.TempRoot
	if root == "" {
		root = "/var/run"
	}
	work, err := os.MkdirTemp(root, "xf-tun-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	_ = os.Chmod(work, 0o700)

	bin := o.Binary
	if o.Pinned {
		if err := checkRootOwned(bin, o.AllowNonRoot); err != nil {
			return err
		}
	} else {
		bin = filepath.Join(work, "sing-box")
		if err := copyFile(o.Binary, bin, 0o755); err != nil {
			return fmt.Errorf("copy sing-box: %w", err)
		}
	}
	cfg := filepath.Join(work, "config.json")
	if err := os.WriteFile(cfg, raw, 0o600); err != nil {
		return err
	}

	logf, err := openOwned(o.LogFile, o.UID, 0)
	if err != nil {
		return fmt.Errorf("open the log file: %w", err)
	}
	defer logf.Close()
	if err := writeOwned(o.PIDFile, o.UID, strconv.Itoa(os.Getpid())); err != nil {
		return err
	}
	defer os.Remove(o.PIDFile)

	cmd := exec.Command(bin, "run", "-c", cfg, "-D", work, "--disable-color")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(sig)

	started := time.Now()
	ready := false
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for {
		select {
		case err := <-exited:
			return err
		case <-sig:
			return stop(cmd, exited)
		case <-tick.C:
			if !ready && time.Since(started) >= readyAfter {
				ready = true
				if err := writeOwned(o.ReadyFile, o.UID, "ready"); err != nil {
					_ = stop(cmd, exited)
					return err
				}
			}
			if parentGone(o.ParentPID) || exists(o.StopFile) {
				return stop(cmd, exited)
			}
		}
	}
}

func stop(cmd *exec.Cmd, exited <-chan error) error {
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-exited:
	case <-time.After(killTimeout):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-exited
	}
	return nil
}

func parentGone(pid int) bool { return syscall.Kill(pid, 0) == syscall.ESRCH }

func exists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Lstat(path)
	return err == nil
}

// readSmall reads a regular file without following a symbolic link.
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// openOwned creates path for the user: never through a symbolic link, never
// in a directory the user does not own and never over a file the user does not
// own, so asking root to write a log cannot damage system files.
func openOwned(path string, uid int, _ int) (*os.File, error) {
	if path == "" {
		return nil, errors.New("no path given")
	}
	if os.Geteuid() == 0 {
		dir, err := os.Lstat(filepath.Dir(path))
		if err != nil {
			return nil, err
		}
		if sys, ok := dir.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != uid || !dir.IsDir() {
			return nil, fmt.Errorf("%s is not a directory of the user", filepath.Dir(path))
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	if os.Geteuid() == 0 {
		if sys, ok := st.Sys().(*syscall.Stat_t); !ok || (int(sys.Uid) != uid && sys.Uid != 0 || sys.Uid == 0 && st.Size() > 0) {
			f.Close()
			return nil, fmt.Errorf("%s belongs to someone else", path)
		}
		if err := f.Chown(uid, -1); err != nil {
			f.Close()
			return nil, err
		}
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func writeOwned(path string, uid int, content string) error {
	f, err := openOwned(path, uid, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// checkRootOwned refuses a binary (or its directory) that a normal user could
// swap, which would turn the pinned copy into a way to run anything as root.
func checkRootOwned(path string, allowNonRoot bool) error {
	if allowNonRoot {
		return nil
	}
	for _, p := range []string{path, filepath.Dir(path)} {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s must be owned by root and not writable by others", p)
		}
	}
	return nil
}
