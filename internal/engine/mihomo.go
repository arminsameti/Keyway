package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"keyway/internal/mihomo"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// MihomoDisplayName is the user-facing name of the Mihomo engine.
const MihomoDisplayName = "Mihomo"

// Mihomo is the Mihomo (Clash.Meta) engine. Mihomo is GPL-3.0: Keyway downloads
// it and runs it as a separate process, and never links or bundles it. The
// engine is opt-in: it runs a server only under the mihomo preference.
//
// It serves the user's apps itself (SOCKS and HTTP inbounds, routing rules). A
// TUN interface and per-app rules are left to sing-box, which follows it as a
// relay like it follows any engine when the settings ask for them.
type Mihomo struct{}

func (Mihomo) Name() string        { return NameMihomo }
func (Mihomo) DisplayName() string { return MihomoDisplayName }

// OptIn: the planner considers Mihomo only when the user chose it.
func (Mihomo) OptIn() bool { return true }

func (Mihomo) Supports(p profile.Profile) error { return mihomo.Supports(p) }

func (Mihomo) SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	return mihomo.SupportsSegment(hops, hasUpstream)
}

func (Mihomo) Config(seg profile.Segment, s models.Settings) ([]byte, error) {
	return mihomo.BuildConfig(seg, s)
}

func (Mihomo) ProbeConfig(seg profile.Segment, port int) ([]byte, error) {
	return mihomo.ProbeConfig(seg, port)
}

// GeoData lists the geodata files the routing settings need.
func (Mihomo) GeoData(s models.Settings) []string { return mihomo.GeoData(s) }

// mihomoHome is the directory Mihomo runs in (-d): the "data" directory next to
// the version directories, where the geodata lives. It is created on demand.
func mihomoHome(in Install) string {
	home := filepath.Join(filepath.Dir(in.AssetDir), "data")
	_ = os.MkdirAll(home, 0o700)
	return home
}

func mihomoCheckArgs(in Install, cfgPath string) []string {
	return []string{"-t", "-d", mihomoHome(in), "-f", cfgPath}
}

func (Mihomo) Check(ctx context.Context, in Install, cfgPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Bin, mihomoCheckArgs(in, cfgPath)...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", TailOf(string(out), err))
	}
	return nil
}

func (Mihomo) Launch(in Install, cfgPath string) Launch {
	return Launch{Binary: in.Bin, Args: []string{"-d", mihomoHome(in), "-f", cfgPath}}
}
