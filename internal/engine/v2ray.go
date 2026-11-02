package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"keyway/internal/models"
	"keyway/internal/profile"
	"keyway/internal/v2ray"
)

// V2Ray is the v2ray-core engine. It is opt-in: it sits last in the engine list,
// so it runs a server only under the v2ray preference.
type V2Ray struct{}

func (V2Ray) Name() string        { return NameV2Ray }
func (V2Ray) DisplayName() string { return V2RayDisplayName }

func (V2Ray) Supports(p profile.Profile) error { return v2ray.Supports(p) }

func (V2Ray) SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	return v2ray.SupportsSegment(hops, hasUpstream)
}

func (V2Ray) Config(seg profile.Segment, s models.Settings) ([]byte, error) {
	return v2ray.BuildConfig(seg, s)
}

func (V2Ray) ProbeConfig(seg profile.Segment, port int) ([]byte, error) {
	return v2ray.ProbeConfig(seg, port)
}

func (V2Ray) Check(ctx context.Context, in Install, cfgPath string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Bin, "test", "-c", cfgPath)
	cmd.Env = append(os.Environ(), "V2RAY_LOCATION_ASSET="+in.AssetDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", TailOf(string(out), err))
	}
	return nil
}

func (V2Ray) Launch(in Install, cfgPath string) Launch {
	return Launch{Binary: in.Bin, Args: []string{"run", "-c", cfgPath}, Env: []string{"V2RAY_LOCATION_ASSET=" + in.AssetDir}}
}
