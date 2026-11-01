package engine

import (
	"context"
	"encoding/json"
	"fmt"

	"keyway/internal/models"
	"keyway/internal/profile"
	"keyway/internal/xray"
)

// Xray is the Xray-core engine.
type Xray struct{}

func (Xray) Name() string        { return NameXray }
func (Xray) DisplayName() string { return "Xray core" }

func (Xray) Supports(p profile.Profile) error { return xray.Supports(p) }

func (Xray) SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	return xray.SupportsSegment(hops, hasUpstream)
}

func (Xray) Config(seg profile.Segment, s models.Settings) ([]byte, error) {
	cfg, err := xray.BuildConfig(seg, s)
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return b, nil
}

func (Xray) ProbeConfig(seg profile.Segment, port int) ([]byte, error) {
	cfg, err := xray.ProbeConfig(seg, port)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cfg)
}

func (Xray) Check(ctx context.Context, in Install, cfgPath string) error {
	return xray.Test(ctx, in.Bin, cfgPath, in.AssetDir)
}

func (Xray) Launch(in Install, cfgPath string) Launch {
	return Launch{Binary: in.Bin, Args: []string{"-c", cfgPath}, Env: []string{"XRAY_LOCATION_ASSET=" + in.AssetDir}}
}
