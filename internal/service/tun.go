package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/models"
	"keyway/internal/privileged"
	"keyway/internal/profile"
)

// ErrTUNHelperMissing is returned when one-time authorization is chosen but not set up.
var ErrTUNHelperMissing = errors.New("TUN is set to use one-time authorization, which is not set up yet: choose Allow Once… in Settings › Network")

// helperBinary is the keyway-tun-helper shipped next to the backend.
var helperBinary = func() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	p := filepath.Join(filepath.Dir(self), "keyway-tun-helper")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("TUN mode needs keyway-tun-helper next to the app, and it is missing")
	}
	return p, nil
}

// tunFiles are how the helper and the app talk, all in the data directory.
func (s *Service) tunFiles() (stop, ready, logf, pid string) {
	return filepath.Join(s.dir, "tun.stop"), filepath.Join(s.dir, "tun.ready"), filepath.Join(s.dir, "tun.log"), filepath.Join(s.dir, "tun.pid")
}

// tunOptions describes the interface for the segment that serves the user:
// every engine program of the connection must reach the internet directly.
func tunOptions(t models.TUNSettings, pl *connPlan) *profile.TUNOptions {
	o := &profile.TUNOptions{Stack: t.Stack, MTU: t.MTU, Strict: t.Strict}
	seen := map[string]bool{}
	for k, in := range pl.installs {
		if !seen[in.Bin] {
			seen[in.Bin] = true
			o.ExcludePaths = append(o.ExcludePaths, in.Bin)
		}
		if pl.steps[k].Engine.Name() == engine.NameTor {
			// lyrebird (obfs4, meek, Snowflake) opens the connections to the bridges
			o.ExcludePaths = append(o.ExcludePaths, filepath.Join(in.AssetDir, "lyrebird"))
		}
	}
	return o
}

// elevation builds the command that runs the last segment's sing-box as root.
// When one-time authorization is chosen but not set up yet, this is where it
// gets set up: the user authorizes once, on this first connect, and never again.
func (s *Service) elevation(ctx context.Context, d models.AppData, in engine.Install, cfgPath string) (*engine.Elevation, error) {
	helper, err := helperBinary()
	if err != nil {
		return nil, err
	}
	stop, ready, logf, pid := s.tunFiles()
	common := []string{"--config", cfgPath, "--parent", strconv.Itoa(os.Getpid()), "--uid", strconv.Itoa(os.Getuid()),
		"--log", logf, "--stop", stop, "--ready", ready, "--pid", pid}
	el := &engine.Elevation{StopFile: stop, ReadyFile: ready, LogFile: logf}
	if d.Settings.TUN.Privilege == "helper" {
		if !privileged.Installed() {
			s.log.Info("setting up one-time authorization for TUN")
			if _, err := s.SetTUNHelper(ctx, true); err != nil {
				return nil, err
			}
			if !privileged.Installed() {
				return nil, ErrTUNHelperMissing
			}
		}
		el.Command = append([]string{"/usr/bin/sudo", "-n", privileged.HelperPath, "run-pinned"}, common...)
		return el, nil
	}
	el.Command, el.Fallback = adminCommand(append([]string{helper, "run-copy", "--bin", in.Bin}, common...),
		"Keyway needs administrator rights to capture all traffic (TUN mode).")
	return el, nil
}

// runAdmin runs a command with administrator rights. A fingerprint that sudo
// cannot take falls back to the password dialog.
func runAdmin(ctx context.Context, args []string, why string) ([]byte, error) {
	primary, fallback := adminCommand(args, why)
	out, err := exec.CommandContext(ctx, primary[0], primary[1:]...).CombinedOutput()
	if err != nil && len(fallback) > 0 && engine.SudoAuthFailed(string(out)) {
		out, err = exec.CommandContext(ctx, fallback[0], fallback[1:]...).CombinedOutput()
	}
	return out, err
}

// adminCommand is how a command gets administrator rights, and what to try
// instead if that does not work. With Touch ID set up for sudo, sudo shows the
// system's fingerprint prompt (it has no terminal for a password, so the
// password dialog is the fallback). Otherwise the system's password dialog,
// which says why it asks. Tests replace it.
var adminCommand = func(args []string, why string) (primary, fallback []string) {
	return adminCommandFor(touchIDForSudo(os.ReadFile), args, why)
}

func adminCommandFor(touchID bool, args []string, why string) (primary, fallback []string) {
	dialog := []string{"/usr/bin/osascript", "-e", adminScript(shellJoin(args), why)}
	if touchID {
		return append([]string{"/usr/bin/sudo", "--"}, args...), dialog
	}
	return dialog, nil
}

// touchIDForSudo reports whether sudo accepts a fingerprint: the user turned on
// pam_tid for it, in /etc/pam.d/sudo_local (which survives macOS updates) or
// the older way, in /etc/pam.d/sudo.
func touchIDForSudo(read func(string) ([]byte, error)) bool {
	for _, f := range []string{"/etc/pam.d/sudo_local", "/etc/pam.d/sudo"} {
		b, err := read(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#") && strings.Contains(line, "pam_tid.so") {
				return true
			}
		}
	}
	return false
}

// adminScript asks macOS to run a shell command with administrator rights; the
// system shows its own password dialog, headed by why.
func adminScript(shell, why string) string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `do shell script "` + esc.Replace(shell) + `" with prompt "` + esc.Replace(why) + `" with administrator privileges`
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func shellJoin(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

// stopStaleHelper asks a helper left over from a crashed run to stop. It cannot
// be killed from here (it is root's); it also exits by itself once the app it
// belongs to is gone.
func (s *Service) stopStaleHelper() {
	stop, _, _, pid := s.tunFiles()
	if _, err := os.Stat(pid); err == nil {
		_ = os.WriteFile(stop, nil, 0o600)
		s.log.Warn("asked a TUN helper from a previous run to stop")
	}
}

// ---- one-time authorization ----

// TUNHelper is the state of one-time authorization.
type TUNHelper struct {
	Available     bool   `json:"available"`               // the helper program is present in the app
	Installed     bool   `json:"installed"`               // authorization is set up
	PinnedVersion string `json:"pinnedVersion,omitempty"` // the sing-box it runs
	Outdated      bool   `json:"outdated"`                // the active sing-box is newer than the pinned one
}

// TUNHelperStatus reports whether one-time authorization is set up.
func (s *Service) TUNHelperStatus() TUNHelper {
	_, err := helperBinary()
	h := TUNHelper{Available: err == nil, Installed: privileged.Installed()}
	if h.Installed {
		if f := strings.Fields(core.VersionOf(privileged.PinnedBinary)); len(f) > 0 {
			h.PinnedVersion = f[len(f)-1] // "sing-box version 1.14.4"
		}
		if sl, ok := s.slot(engine.NameSingBox); ok {
			active := s.store.Get().Engines[engine.NameSingBox]
			if _, _, ver, err := sl.Manager.Resolve(active); err == nil && h.PinnedVersion != "" {
				h.Outdated = strings.TrimPrefix(ver, "v") != strings.TrimPrefix(h.PinnedVersion, "v")
			}
		}
	}
	return h
}

// SetTUNHelper installs or removes one-time authorization. The system asks for
// the administrator password; nothing else in the app can do this.
func (s *Service) SetTUNHelper(ctx context.Context, install bool) (TUNHelper, error) {
	helper, err := helperBinary()
	if err != nil {
		return TUNHelper{}, err
	}
	var args []string
	why := "Keyway needs administrator rights to remove the one-time authorization for TUN mode."
	if install {
		why = "Keyway needs administrator rights once, so TUN mode does not ask again."
		d := s.store.Get()
		sl, ok := s.slot(engine.NameSingBox)
		if !ok {
			return TUNHelper{}, errors.New("sing-box is not available")
		}
		bin, _, _, err := sl.Manager.Resolve(d.Engines[engine.NameSingBox])
		if err != nil {
			return TUNHelper{}, fmt.Errorf("download sing-box first (Settings › Engines): %w", err)
		}
		u, err := user.Current()
		if err != nil {
			return TUNHelper{}, err
		}
		args = []string{helper, "install", "--bin", bin, "--user", u.Username}
	} else {
		args = []string{helper, "uninstall"}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	out, err := runAdmin(ctx, args, why)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "User canceled") {
			return TUNHelper{}, errors.New("cancelled")
		}
		return TUNHelper{}, fmt.Errorf("%s", engine.TailOf(msg, err))
	}
	return s.TUNHelperStatus(), nil
}
