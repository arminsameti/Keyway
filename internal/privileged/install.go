package privileged

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// SudoersPath is the file that lets the user run the pinned helper without a password.
const SudoersPath = "/etc/sudoers.d/xray-friendly"

// HelperPath is the root-owned copy of the helper.
var HelperPath = filepath.Join(InstallDir, "xf-tun-helper")

var userName = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)

// Install makes one-time authorization possible. It runs as root (the user
// approves it once in the system's password dialog): it copies the helper and
// sing-box into a root-owned directory and lets this user run exactly
// "xf-tun-helper run-pinned" without a password.
func Install(helperSrc, singBoxSrc, user string) error {
	if os.Geteuid() != 0 {
		return errors.New("this must run as root")
	}
	if !userName.MatchString(user) {
		return fmt.Errorf("unexpected user name %q", user)
	}
	if err := os.MkdirAll(InstallDir, 0o755); err != nil {
		return err
	}
	_ = os.Chown(InstallDir, 0, 0)
	_ = os.Chmod(InstallDir, 0o755)
	for _, f := range []struct{ src, dst string }{{helperSrc, HelperPath}, {singBoxSrc, PinnedBinary}} {
		tmp := f.dst + ".new"
		_ = os.Remove(tmp)
		if err := copyFile(f.src, tmp, 0o755); err != nil {
			return fmt.Errorf("copy %s: %w", filepath.Base(f.dst), err)
		}
		if err := os.Chown(tmp, 0, 0); err != nil {
			return err
		}
		if err := os.Rename(tmp, f.dst); err != nil {
			return err
		}
	}
	rule := fmt.Sprintf("%s ALL=(root) NOPASSWD: %s run-pinned *\n", user, strings.ReplaceAll(HelperPath, " ", `\ `))
	tmp := SudoersPath + ".new"
	if err := os.WriteFile(tmp, []byte(rule), 0o440); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	if out, err := exec.Command("/usr/sbin/visudo", "-cf", tmp).CombinedOutput(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("the sudoers rule was rejected: %s", strings.TrimSpace(string(out)))
	}
	return os.Rename(tmp, SudoersPath)
}

// Uninstall removes everything Install created.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("this must run as root")
	}
	var first error
	for _, p := range []string{SudoersPath, HelperPath, PinnedBinary} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	_ = os.Remove(InstallDir)
	return first
}

// Installed reports whether one-time authorization is set up.
func Installed() bool {
	for _, p := range []string{HelperPath, PinnedBinary} {
		if _, err := os.Stat(p); err != nil {
			return false
		}
	}
	return true
}
