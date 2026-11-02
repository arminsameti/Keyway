package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"keyway/internal/models"
	"keyway/internal/profile"
	"keyway/internal/tor"
)

// Tor is the Tor client engine. It runs a single Tor hop, and a relay always
// follows it because it only offers SOCKS.
type Tor struct{}

func (Tor) Name() string        { return NameTor }
func (Tor) DisplayName() string { return TorDisplayName }

func (Tor) RelayRequired() bool { return true }

func (Tor) Supports(p profile.Profile) error {
	if p.Protocol != profile.Tor {
		return fmt.Errorf("Tor runs only Tor servers")
	}
	return p.Validate()
}

func (t Tor) SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	if len(hops) != 1 {
		return fmt.Errorf("Tor runs one hop at a time")
	}
	if err := t.Supports(hops[0]); err != nil {
		return err
	}
	if hasUpstream && hops[0].Tor.Bridges == profile.TorBridgeSnowflake {
		return fmt.Errorf("Snowflake needs UDP and cannot go through the hop before it")
	}
	return nil
}

func (Tor) Config(seg profile.Segment, _ models.Settings) ([]byte, error) {
	if seg.Listen == nil {
		return nil, fmt.Errorf("internal error: Tor must feed a relay")
	}
	return tor.BuildConfig(seg, seg.Listen.Port)
}

func (Tor) ProbeConfig(seg profile.Segment, port int) ([]byte, error) {
	if seg.Listen != nil {
		port = seg.Listen.Port
	}
	return tor.BuildConfig(seg, port)
}

func (Tor) Check(ctx context.Context, in Install, cfgPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Bin, "--verify-config", "-f", cfgPath)
	cmd.Dir = in.AssetDir
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", TailOf(string(out), err))
	}
	return nil
}

func (Tor) Launch(in Install, cfgPath string) Launch {
	return Launch{Binary: in.Bin, Args: []string{"-f", cfgPath}}
}

func (Tor) WaitReady(ctx context.Context, seg profile.Segment, progress func(int, string)) error {
	return tor.WaitReady(ctx, seg, progress)
}
