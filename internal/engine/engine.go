// Package engine abstracts the proxy cores (Xray, sing-box, v2ray-core): which servers each
// can run, how to build its configuration, how to preflight and launch it. The
// process runner and the latency probe are shared by all engines.
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"keyway/internal/models"
	"keyway/internal/profile"
)

// Engine names (stable: persisted and used by the API).
const (
	NameXray    = "xray"
	NameSingBox = "sing-box"
	NameTor     = "tor"
	NameV2Ray   = "v2ray"
	NameMihomo  = "mihomo"

	// TorDisplayName is the user-facing name of the Tor engine.
	TorDisplayName = "Tor"
	// V2RayDisplayName is the user-facing name of the v2ray-core engine.
	V2RayDisplayName = "V2Ray core"
)

// Install locates one installed engine version.
type Install struct {
	Version  string
	Bin      string
	AssetDir string // directory holding the engine's data files (geoip, rule sets)
}

// Launch is the command line that runs an engine with a config file.
type Launch struct {
	Binary string
	Args   []string
	Env    []string
}

// Engine is one proxy core.
type Engine interface {
	Name() string
	// DisplayName is the user-facing name ("Xray core", "sing-box").
	DisplayName() string
	// Supports returns nil when the engine can run the profile as a single
	// server, else the reason.
	Supports(p profile.Profile) error
	// SupportsSegment returns nil when one process of the engine can run the
	// hops as a chain (each hop dialing through the one before it); hasUpstream
	// says the first hop dials through another process's bridge.
	SupportsSegment(hops []profile.Profile, hasUpstream bool) error
	// Config renders the full client configuration of one segment.
	Config(seg profile.Segment, s models.Settings) ([]byte, error)
	// ProbeConfig renders a minimal config for measuring: a SOCKS inbound on
	// 127.0.0.1:port, or the segment's bridge when it is a middle segment.
	ProbeConfig(seg profile.Segment, port int) ([]byte, error)
	// Check preflights a config file without starting the proxy.
	Check(ctx context.Context, in Install, cfgPath string) error
	Launch(in Install, cfgPath string) Launch
}

// RuleSetUser is implemented by engines whose configuration refers to rule-set
// files that must be downloaded before the engine can run.
type RuleSetUser interface {
	RuleSets(s models.Settings) []string
}

// GeoDataUser is implemented by engines whose configuration needs geodata files
// that Keyway downloads, verified, before the engine can run (Mihomo).
type GeoDataUser interface {
	GeoData(s models.Settings) []string
}

// OptIn is implemented by engines that run a server only when the user chose
// them as the preferred engine. The planner leaves them out of every other
// plan, so adding one never changes what existing users run, whatever is
// installed.
type OptIn interface{ OptIn() bool }

// eligible reports whether the planner may consider e under preference pref.
func eligible(e Engine, pref string) bool {
	if o, ok := e.(OptIn); ok && o.OptIn() {
		return e.Name() == pref
	}
	return true
}

// Bootstrapper is implemented by engines whose process is not usable when its
// port opens (Tor must finish building a circuit first). WaitReady blocks until
// it is, reporting progress, and fails with the reason when it never is.
type Bootstrapper interface {
	WaitReady(ctx context.Context, seg profile.Segment, progress func(percent int, summary string)) error
}

// RelayRequired is implemented by engines that cannot serve the user's apps
// themselves (no HTTP proxy, routing rules or TUN): the planner follows them
// with a sing-box relay.
type RelayRequired interface{ RelayRequired() bool }

// TagAware is implemented by engines whose capabilities depend on the build
// tags of the installed binary.
type TagAware interface {
	SetTags(tags map[string]bool)
}

// NotInstalledError means a server needs an engine that is not installed yet.
type NotInstalledError struct{ Engine Engine }

func (e *NotInstalledError) Error() string {
	return fmt.Sprintf("%s is needed for this server but is not installed; download it in Settings › Engines", e.Engine.DisplayName())
}

// ErrNoEngine is wrapped when no engine supports a profile at all.
var ErrNoEngine = errors.New("no engine supports this server")

// Select picks the engine that runs p. Engines that cannot run p are skipped;
// among the rest the preferred one wins, then the first in order. An engine
// that can run p but is not installed only wins when no installed one can.
//
// When the profile pins an engine (Overrides.Engine, the manual per-server
// choice), the pin is strict: only that engine may run it. A pin to an
// opt-in engine is honoured even when the global preference names another
// engine; a pin to an engine that cannot run the server is an error, not a
// silent fallback.
func Select(p profile.Profile, pref string, engines []Engine, installed func(name string) bool) (Engine, error) {
	if pin := p.PinnedEngine(); pin != "" {
		return selectPinned(p, pin, engines, installed)
	}
	var capable []Engine
	var reasons []string
	for _, e := range engines {
		if !eligible(e, pref) {
			continue
		}
		if err := e.Supports(p); err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		capable = append(capable, e)
	}
	if len(capable) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoEngine, strings.Join(reasons, "; "))
	}
	capable = preferredFirst(capable, pref)
	for _, e := range capable {
		if installed(e.Name()) {
			return e, nil
		}
	}
	return capable[0], &NotInstalledError{Engine: capable[0]}
}

// selectPinned runs Select for a manually pinned engine: no fallback to
// another engine.
func selectPinned(p profile.Profile, pin string, engines []Engine, installed func(string) bool) (Engine, error) {
	var pinned Engine
	for _, e := range engines {
		if e.Name() == pin {
			pinned = e
			break
		}
	}
	if pinned == nil {
		return nil, fmt.Errorf("%w: pinned engine %q is not available (is it turned off?)", ErrNoEngine, pin)
	}
	if err := pinned.Supports(p); err != nil {
		return nil, fmt.Errorf("%w: pinned engine %s cannot run this server: %v", ErrNoEngine, pinned.DisplayName(), err)
	}
	if installed(pinned.Name()) {
		return pinned, nil
	}
	return pinned, &NotInstalledError{Engine: pinned}
}

// preferredFirst moves the preferred engine to the front and keeps the others in
// order, so an opt-in engine at the end of the list never promotes the last
// engine into its place. The input is not changed.
func preferredFirst(engines []Engine, pref string) []Engine {
	out := make([]Engine, 0, len(engines))
	for _, e := range engines {
		if e.Name() == pref {
			out = append(out, e)
		}
	}
	for _, e := range engines {
		if e.Name() != pref {
			out = append(out, e)
		}
	}
	return out
}
