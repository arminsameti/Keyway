// Package tor builds the configuration of a Tor client and talks to its
// control port. It knows nothing about the engine abstraction; internal/engine
// wraps it.
package tor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"keyway/internal/profile"
)

// quote makes a value safe as one torrc argument.
func quote(s string) string { return strconv.Quote(s) }

// ptConfig is the part of the bundle's pt_config.json that lists default bridges.
type ptConfig struct {
	Bridges map[string][]string `json:"bridges"`
}

// defaultBridges returns the bundled default bridge lines for a mode.
func defaultBridges(assetDir, mode string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(assetDir, "pt_config.json"))
	if err != nil {
		return nil, fmt.Errorf("Tor: the built-in %s bridges are not available in this Tor download; paste bridge lines instead", mode)
	}
	var c ptConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("Tor: read the built-in bridges: %w", err)
	}
	keys := map[string][]string{
		profile.TorBridgeObfs4:     {"obfs4"},
		profile.TorBridgeMeek:      {"meek-azure", "meek"},
		profile.TorBridgeSnowflake: {"snowflake"},
	}[mode]
	for _, k := range keys {
		if l := c.Bridges[k]; len(l) > 0 {
			return l, nil
		}
	}
	return nil, fmt.Errorf("Tor: no built-in %s bridges in this Tor download; paste bridge lines instead", mode)
}

// BuildConfig renders the torrc of one Tor hop. socksPort is the loopback port
// that serves the next process (the segment's bridge, or the probe's port).
func BuildConfig(seg profile.Segment, socksPort int) ([]byte, error) {
	if len(seg.Hops) != 1 || seg.Hops[0].Protocol != profile.Tor || seg.Hops[0].Tor == nil {
		return nil, fmt.Errorf("Tor runs exactly one Tor hop")
	}
	rt := seg.Runtime
	if rt == nil || rt.Dir == "" || rt.ControlPort == 0 {
		return nil, fmt.Errorf("internal error: Tor needs a run directory and a control port")
	}
	o := *seg.Hops[0].Tor
	if err := o.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("ClientOnly 1")
	w("AvoidDiskWrites 1")
	w("DataDirectory %s", quote(rt.Dir))
	w("SocksPort 127.0.0.1:%d", socksPort)
	w("ControlPort 127.0.0.1:%d", rt.ControlPort)
	w("CookieAuthentication 1")
	w("Log notice stdout")
	w("SafeLogging 1")
	for _, f := range []struct{ key, file string }{{"GeoIPFile", "geoip"}, {"GeoIPv6File", "geoip6"}} {
		if p := filepath.Join(rt.AssetDir, f.file); fileExists(p) {
			w("%s %s", f.key, quote(p))
		}
	}
	if u := seg.Upstream; u != nil {
		w("Socks5Proxy 127.0.0.1:%d", u.Port)
		w("Socks5ProxyUsername %s", quote(u.User))
		w("Socks5ProxyPassword %s", quote(u.Pass))
	}
	if o.Bridges == profile.TorBridgeNone {
		return []byte(b.String()), nil
	}
	lines := o.Lines
	if o.Bridges != profile.TorBridgeCustom {
		var err error
		if lines, err = defaultBridges(rt.AssetDir, o.Bridges); err != nil {
			return nil, err
		}
	}
	// every transport Keyway offers (obfs4, meek, Snowflake, webtunnel) is
	// served by the one lyrebird program
	var transports []string
	seen := map[string]bool{}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if err := profile.SafeTorValue(l); err != nil {
			return nil, err
		}
		t, _, _ := strings.Cut(l, " ")
		switch t {
		case "obfs4", "meek_lite", "webtunnel", "scramblesuit", "snowflake":
			if t == "snowflake" && seg.Upstream != nil {
				return nil, fmt.Errorf("Tor: Snowflake needs UDP and cannot go through the hop before it")
			}
			if !seen[t] {
				seen[t] = true
				transports = append(transports, t)
			}
		}
	}
	w("UseBridges 1")
	if len(transports) > 0 {
		p := filepath.Join(rt.AssetDir, "lyrebird")
		if strings.ContainsAny(p, " \t") {
			return nil, fmt.Errorf("Tor: the install path %q contains spaces, which Tor cannot use for bridge programs", p)
		}
		if !fileExists(p) {
			return nil, fmt.Errorf("Tor: the lyrebird program is missing from this Tor download")
		}
		w("ClientTransportPlugin %s exec %s", strings.Join(transports, ","), p)
	}
	for _, l := range lines {
		w("Bridge %s", strings.TrimSpace(l))
	}
	return []byte(b.String()), nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
