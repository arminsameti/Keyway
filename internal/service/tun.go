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
	for _, in := range pl.installs {
		if !seen[in.Bin] {
			seen[in.Bin] = true
			o.ExcludePaths = append(o.ExcludePaths, in.Bin)
		}
	}
	return o
}

// elevation builds the command that runs the last segment's sing-box as root.
func (s *Service) elevation(d models.AppData, in engine.Install, cfgPath string) (*engine.Elevation, error) {
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
			return nil, ErrTUNHelperMissing
		}
		el.Command = append([]string{"/usr/bin/sudo", "-n", privileged.HelperPath, "run-pinned"}, common...)
		return el, nil
	}
	cmd := shellJoin(append([]string{helper, "run-copy", "--bin", in.Bin}, common...))
	el.Command = adminCommand(cmd)
	return el, nil
}

// adminCommand is how a shell command gets administrator rights: the system's
// own password dialog. Tests replace it.
var adminCommand = func(shell string) []string { return []string{"/usr/bin/osascript", "-e", adminScript(shell)} }

// adminScript asks macOS to run a shell command with administrator rights; the
// system shows its own password dialog.
func adminScript(shell string) string {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(shell)
	return `do shell script "` + esc + `" with administrator privileges`
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
	var shell string
	if install {
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
		shell = shellJoin([]string{helper, "install", "--bin", bin, "--user", u.Username})
	} else {
		shell = shellJoin([]string{helper, "uninstall"})
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := adminCommand(shell)
	out, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "User canceled") {
			return TUNHelper{}, errors.New("cancelled")
		}
		return TUNHelper{}, fmt.Errorf("%s", engine.TailOf(msg, err))
	}
	return s.TUNHelperStatus(), nil
}
