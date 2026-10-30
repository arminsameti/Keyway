// Package engine abstracts the proxy cores (Xray, sing-box): which servers each
// can run, how to build its configuration, how to preflight and launch it. The
// process runner and the latency probe are shared by all engines.
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// Engine names (stable: persisted and used by the API).
const (
	NameXray    = "xray"
	NameSingBox = "sing-box"
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
	// Supports returns nil when the engine can run the profile, else the reason.
	Supports(p profile.Profile) error
	// Config renders the full client configuration.
	Config(p profile.Profile, s models.Settings) ([]byte, error)
	// ProbeConfig renders a minimal config with one SOCKS inbound on 127.0.0.1:port.
	ProbeConfig(p profile.Profile, port int) ([]byte, error)
	// Check preflights a config file without starting the proxy.
	Check(ctx context.Context, in Install, cfgPath string) error
	Launch(in Install, cfgPath string) Launch
}

// RuleSetUser is implemented by engines whose configuration refers to rule-set
// files that must be downloaded before the engine can run.
type RuleSetUser interface {
	RuleSets(s models.Settings) []string
}

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
func Select(p profile.Profile, pref string, engines []Engine, installed func(name string) bool) (Engine, error) {
	var capable []Engine
	var reasons []string
	for _, e := range engines {
		if err := e.Supports(p); err != nil {
			reasons = append(reasons, err.Error())
			continue
		}
		capable = append(capable, e)
	}
	if len(capable) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoEngine, strings.Join(reasons, "; "))
	}
	for i, e := range capable {
		if e.Name() == pref && i > 0 {
			capable[0], capable[i] = capable[i], capable[0]
			break
		}
	}
	for _, e := range capable {
		if installed(e.Name()) {
			return e, nil
		}
	}
	return capable[0], &NotInstalledError{Engine: capable[0]}
}

// Candidate returns the engine Select would choose, ignoring installation
// state; used for display ("uses sing-box").
func Candidate(p profile.Profile, pref string, engines []Engine) (Engine, error) {
	e, err := Select(p, pref, engines, func(string) bool { return true })
	return e, err
}
