// Package v2ray adapts the Xray configuration for v2ray-core. The two share a
// JSON format, but v2ray-core silently ignores fields it does not know, and
// "v2ray test" passes them. So a server runs here only if every setting it uses
// is known to take effect, and a finished config is refused if it still holds an
// Xray-only key.
package v2ray

import (
	"encoding/json"
	"fmt"
	"strings"

	"keyway/internal/models"
	"keyway/internal/profile"
	"keyway/internal/xray"
)

// Supports reports whether v2ray-core can run the profile, with the reason if
// not. Whatever it accepts also passes xray.Supports, so the Xray builder can
// always render it.
func Supports(p profile.Profile) error {
	if err := xray.Supports(p); err != nil {
		return err
	}
	switch p.Protocol {
	case profile.VMess, profile.Trojan, profile.SOCKS, profile.HTTP:
	case profile.VLESS:
		if p.Security.Kind != "tls" {
			return fmt.Errorf("V2Ray core runs VLESS only over TLS; Xray core or sing-box can run this server")
		}
		if p.Flow != "" {
			return fmt.Errorf("the VLESS flow %q needs Xray core", p.Flow)
		}
		if p.Encryption != "" && p.Encryption != "none" {
			return fmt.Errorf("VLESS encryption needs Xray core")
		}
	case profile.Shadowsocks:
		if strings.HasPrefix(strings.ToLower(p.Cipher), "2022-") {
			return fmt.Errorf("Shadowsocks 2022 needs Xray core or sing-box")
		}
	default:
		return fmt.Errorf("%s needs Xray core or sing-box", profile.ProtocolName(p.Protocol))
	}
	switch p.Security.Kind {
	case "", "none", "tls":
	default:
		return fmt.Errorf("%s security needs Xray core", p.Security.Kind)
	}
	switch p.Transport.Type {
	case "", "tcp", "ws", "grpc", "h2", "kcp":
	default:
		return fmt.Errorf("the %s transport needs Xray core", p.Transport.Type)
	}
	if p.Security.PinSHA256 != "" || p.Security.Insecure {
		return fmt.Errorf("certificate pinning and insecure TLS need Xray core or sing-box")
	}
	if p.Transport.Authority != "" {
		return fmt.Errorf("a gRPC authority needs Xray core")
	}
	if p.Security.Fingerprint != "" {
		return fmt.Errorf("a TLS fingerprint needs Xray core")
	}
	if o := p.Overrides; o != nil {
		if o.Fragment != nil {
			return fmt.Errorf("fragmentation needs Xray core")
		}
		if o.Fingerprint != "" {
			return fmt.Errorf("a TLS fingerprint needs Xray core")
		}
	}
	return nil
}

// SupportsSegment reports whether one v2ray-core process can run the hops as a
// chain. Chains follow Xray's rule: TCP-stream hops only.
func SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	for _, h := range hops {
		if err := Supports(h); err != nil {
			return err
		}
	}
	return xray.SupportsSegment(hops, hasUpstream)
}

// BuildConfig renders the full client configuration of one segment.
func BuildConfig(seg profile.Segment, s models.Settings) ([]byte, error) {
	if err := SupportsSegment(seg.Hops, seg.Upstream != nil); err != nil {
		return nil, err
	}
	cfg, err := xray.BuildConfig(seg, s)
	if err != nil {
		return nil, err
	}
	return render(cfg)
}

// ProbeConfig renders a minimal config for measuring.
func ProbeConfig(seg profile.Segment, port int) ([]byte, error) {
	if err := SupportsSegment(seg.Hops, seg.Upstream != nil); err != nil {
		return nil, err
	}
	cfg, err := xray.ProbeConfig(seg, port)
	if err != nil {
		return nil, err
	}
	return render(cfg)
}

func render(cfg *xray.Config) ([]byte, error) {
	adapt(cfg)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	if err := refuseXrayKeys(b); err != nil {
		return nil, err
	}
	return b, nil
}

// adapt moves chain dialing from Xray's sockopt to v2ray-core's proxySettings.
func adapt(cfg *xray.Config) {
	for i := range cfg.Outbounds {
		ob := &cfg.Outbounds[i]
		if ob.StreamSettings == nil || ob.StreamSettings.Sockopt == nil {
			continue
		}
		ob.ProxySettings = &xray.ProxySettings{Tag: ob.StreamSettings.Sockopt.DialerProxy, TransportLayer: true}
		ob.StreamSettings.Sockopt = nil
	}
}

// xrayOnlyKeys would be accepted by v2ray-core and then silently do nothing.
var xrayOnlyKeys = map[string]bool{
	"dialerProxy": true, "realitySettings": true, "xhttpSettings": true, "httpupgradeSettings": true,
	"flow": true, "pinnedPeerCertSha256": true, "fragment": true,
}

// refuseXrayKeys fails when the config holds an Xray-only key at any depth. That
// is a bug in the allowlist, never something to fall back from.
func refuseXrayKeys(b []byte) error {
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	return walk(doc)
}

func walk(v any) error {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if xrayOnlyKeys[k] {
				return fmt.Errorf("internal error: v2ray config contains %q", k)
			}
			if err := walk(val); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range x {
			if err := walk(val); err != nil {
				return err
			}
		}
	}
	return nil
}
