package service

import (
	"context"
	"fmt"
	"time"

	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// allProtocols is the order protocols are listed in for an engine.
var allProtocols = []string{
	profile.VLESS, profile.VMess, profile.Trojan, profile.Shadowsocks, profile.Hysteria2, profile.WireGuard,
	profile.SOCKS, profile.HTTP, profile.TUIC, profile.Hysteria, profile.AnyTLS, profile.ShadowTLS, profile.Naive, profile.SSH,
	profile.Tor,
}

// EngineView describes one engine for Settings › Engines.
type EngineView struct {
	Name            string    `json:"name"`
	DisplayName     string    `json:"displayName"`
	Installed       []string  `json:"installed"`
	Active          string    `json:"active"`  // version tag that runs, "" when none installed
	Version         string    `json:"version"` // the binary's own version line
	Latest          string    `json:"latest,omitempty"`
	UpdateAvailable bool      `json:"updateAvailable"`
	CheckedAt       time.Time `json:"checkedAt,omitempty"`
	CheckError      string    `json:"checkError,omitempty"`
	Protocols       []string  `json:"protocols"` // display names this engine runs
	Dir             string    `json:"dir"`
}

func (s *Service) engineView(d models.AppData, sl EngineSlot) EngineView {
	name := sl.Engine.Name()
	v := EngineView{
		Name: name, DisplayName: sl.Engine.DisplayName(), Installed: sl.Manager.Installed(),
		Dir: sl.Manager.Dir(),
	}
	if v.Installed == nil {
		v.Installed = []string{}
	}
	if bin, _, active, err := sl.Manager.Resolve(d.Engines[name]); err == nil {
		v.Active, v.Version = active, s.engineVersion(bin)
	}
	if c, ok := d.EngineChecks[name]; ok {
		v.Latest, v.CheckedAt, v.CheckError = c.Latest, c.CheckedAt, c.Error
		v.UpdateAvailable = v.Active != "" && c.Latest != "" && core.CompareVersions(c.Latest, v.Active) > 0
	}
	v.Protocols = engineProtocols(sl.Engine)
	return v
}

// engineProtocols lists the display names of the protocols an engine runs.
func engineProtocols(e engine.Engine) []string {
	out := []string{}
	for _, p := range allProtocols {
		// a minimal valid shape: some protocols require options (Hysteria v1 bandwidth)
		probe := profile.Profile{Protocol: p, Hysteria: &profile.HysteriaOpts{UpMbps: 1, DownMbps: 1}}
		if p == profile.Hysteria2 {
			probe.Hysteria = nil
		}
		if p == profile.VLESS {
			probe.Security.Kind = "tls" // cores differ on VLESS without TLS, not on VLESS itself
		}
		probe.Tor = &profile.TorOpts{Bridges: profile.TorBridgeNone}
		if e.Supports(probe) == nil {
			out = append(out, profile.ProtocolName(p))
		}
	}
	return out
}

// Engines lists every engine with its install and update state.
func (s *Service) Engines() []EngineView {
	d := s.store.Get()
	slots := s.visibleSlots()
	out := make([]EngineView, 0, len(slots))
	for _, sl := range slots {
		out = append(out, s.engineView(d, sl))
	}
	return out
}

// ErrUnknownEngine is returned for an engine name that does not exist.
var ErrUnknownEngine = &models.ValidationError{Msg: "unknown engine"}

func (s *Service) mustSlot(name string) (EngineSlot, error) {
	sl, ok := s.slot(name)
	if !ok {
		return EngineSlot{}, ErrUnknownEngine
	}
	return sl, nil
}

// EngineReleases lists downloadable releases of one engine.
func (s *Service) EngineReleases(ctx context.Context, name string) ([]core.Release, error) {
	sl, err := s.mustSlot(name)
	if err != nil {
		return nil, err
	}
	return sl.Manager.FetchReleases(ctx, 10)
}

// DownloadEngine installs a release (checksum-verified) and makes it active.
// An empty version means the latest stable release.
func (s *Service) DownloadEngine(ctx context.Context, name, version string) (string, error) {
	sl, err := s.mustSlot(name)
	if err != nil {
		return "", err
	}
	version = core.NormalizeVersion(version)
	if version != "" && !core.ValidVersion(version) {
		return "", &models.ValidationError{Msg: fmt.Sprintf("invalid version %q (expected like v25.1.1)", version)}
	}
	if !s.coreMu.TryLock() {
		return "", ErrBusy
	}
	defer s.coreMu.Unlock()
	if version == "" {
		rs, err := sl.Manager.FetchReleases(ctx, 1)
		if err != nil {
			return "", err
		}
		if len(rs) == 0 {
			return "", fmt.Errorf("no stable %s release found", sl.Engine.DisplayName())
		}
		version = rs[0].Tag
	}
	if err := sl.Manager.Download(ctx, version); err != nil {
		return "", err
	}
	if err := s.setActiveEngine(name, version); err != nil {
		return "", err
	}
	s.syncTags()
	return version, nil
}

// UseEngine switches an engine to an installed version.
func (s *Service) UseEngine(name, version string) (string, error) {
	sl, err := s.mustSlot(name)
	if err != nil {
		return "", err
	}
	version = core.NormalizeVersion(version)
	if !core.ValidVersion(version) {
		return "", &models.ValidationError{Msg: fmt.Sprintf("invalid version %q", version)}
	}
	if !contains(sl.Manager.Installed(), version) {
		return "", &models.ValidationError{Msg: fmt.Sprintf("%s %s is not installed", sl.Engine.DisplayName(), version)}
	}
	if err := s.setActiveEngine(name, version); err != nil {
		return "", err
	}
	s.syncTags()
	return version, nil
}

// CheckEngine looks up the latest stable release and records the result.
func (s *Service) CheckEngine(ctx context.Context, name string) (EngineView, error) {
	sl, err := s.mustSlot(name)
	if err != nil {
		return EngineView{}, err
	}
	rs, ferr := sl.Manager.FetchReleases(ctx, 1)
	c := models.EngineCheck{CheckedAt: time.Now().UTC()}
	switch {
	case ferr != nil:
		c.Error = ferr.Error()
	case len(rs) > 0:
		c.Latest = rs[0].Tag
	}
	d, err := s.store.Update(func(d *models.AppData) error {
		d.EngineChecks[name] = c
		return nil
	})
	if err != nil {
		return EngineView{}, err
	}
	return s.engineView(d, sl), ferr
}

func (s *Service) setActiveEngine(name, v string) error {
	_, err := s.store.Update(func(d *models.AppData) error {
		d.Engines[name] = v
		return nil
	})
	return err
}

// ---- Xray-only API kept for /api/cores* ----

// CoresView lists installed Xray cores.
type CoresView struct {
	Installed []string `json:"installed"`
	Active    string   `json:"active"`
	Dir       string   `json:"dir"`
}

// Cores returns installed Xray versions and the effective active one.
func (s *Service) Cores() CoresView {
	v := s.engineView(s.store.Get(), s.engines[0])
	return CoresView{Installed: v.Installed, Active: v.Active, Dir: v.Dir}
}

// FetchReleases lists downloadable Xray-core releases.
func (s *Service) FetchReleases(ctx context.Context) ([]core.Release, error) {
	return s.EngineReleases(ctx, engine.NameXray)
}

// DownloadCore installs an Xray release and makes it active.
func (s *Service) DownloadCore(ctx context.Context, version string) (string, error) {
	if core.NormalizeVersion(version) == "" {
		return "", &models.ValidationError{Msg: "a version is required"}
	}
	return s.DownloadEngine(ctx, engine.NameXray, version)
}

// UseCore switches the active Xray version.
func (s *Service) UseCore(version string) (string, error) {
	return s.UseEngine(engine.NameXray, version)
}
