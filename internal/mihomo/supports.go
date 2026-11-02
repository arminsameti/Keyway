// Package mihomo builds configurations for Mihomo (the Clash.Meta core). Mihomo
// silently ignores keys and values it does not know, and "mihomo -t" passes
// them, so a server runs here only if every setting it uses is known to take
// effect. What is allowed was checked against the real binary (see
// integration_test.go); everything else goes to Xray or sing-box.
package mihomo

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"keyway/internal/profile"
)

// Shadowsocks ciphers and VMess security values Mihomo was run with. Exact
// match: anything else goes to another engine.
var (
	ssCiphers = map[string]string{ // Keyway name -> Mihomo name
		"aes-128-gcm": "aes-128-gcm", "aes-256-gcm": "aes-256-gcm",
		"chacha20-ietf-poly1305": "chacha20-ietf-poly1305", "chacha20-poly1305": "chacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm": "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm": "2022-blake3-aes-256-gcm",
		"2022-blake3-chacha20-poly1305": "2022-blake3-chacha20-poly1305",
	}
	vmessCiphers = map[string]bool{"": true, "auto": true, "none": true, "zero": true, "aes-128-gcm": true, "chacha20-poly1305": true}
)

// earlyData reports whether a WebSocket path asks for early data with "?ed=",
// which Mihomo would send on as a literal query.
func earlyData(path string) bool {
	u, err := url.Parse(path)
	return err != nil || u.Query().Has("ed")
}

func quic(p profile.Profile) bool {
	switch p.Protocol {
	case profile.Hysteria2, profile.TUIC:
		return true
	}
	return false
}

// Supports reports whether Mihomo can run the profile, with the reason if not.
func Supports(p profile.Profile) error {
	switch p.Protocol {
	case profile.VLESS:
		if p.Flow != "" && p.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("the VLESS flow %q needs Xray core", p.Flow)
		}
		if p.Encryption != "" && p.Encryption != "none" {
			return fmt.Errorf("VLESS encryption needs Xray core")
		}
	case profile.VMess:
		if !vmessCiphers[p.Cipher] {
			return fmt.Errorf("the VMess security %q needs Xray core or sing-box", p.Cipher)
		}
	case profile.Trojan:
		if p.Security.Kind != "tls" {
			return fmt.Errorf("Mihomo runs Trojan only over TLS")
		}
	case profile.Shadowsocks:
		if _, ok := ssCiphers[p.Cipher]; !ok {
			return fmt.Errorf("the Shadowsocks cipher %s needs Xray core or sing-box", p.Cipher)
		}
	case profile.SOCKS, profile.HTTP, profile.Hysteria2, profile.TUIC, profile.AnyTLS:
	case profile.WireGuard:
		if err := checkWireGuard(p); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s needs Xray core or sing-box", profile.ProtocolName(p.Protocol))
	}
	if err := checkTransport(p); err != nil {
		return err
	}
	if err := checkSecurity(p); err != nil {
		return err
	}
	if o := p.Overrides; o != nil {
		if o.Fragment != nil {
			return fmt.Errorf("fragmentation needs Xray core or sing-box")
		}
		if o.Fingerprint != "" && quic(p) {
			return fmt.Errorf("a TLS fingerprint does not apply to %s", profile.ProtocolName(p.Protocol))
		}
	}
	return nil
}

func checkTransport(p profile.Profile) error {
	t := p.Transport
	switch p.Protocol {
	case profile.VLESS, profile.VMess, profile.Trojan:
	default:
		// no stream layer of their own (UDP protocols, SOCKS, HTTP, Shadowsocks without a plugin, ...)
		if t.Type != "" && t.Type != "tcp" && t.Type != "udp" && t.Type != "quic" {
			return fmt.Errorf("the %s transport needs Xray core or sing-box", t.Type)
		}
		if t.Type == "tcp" || t.Type == "" {
			return plainTCP(t)
		}
		return nil
	}
	switch t.Type {
	case "", "tcp":
		return plainTCP(t)
	case "ws":
		if earlyData(t.Path) {
			return fmt.Errorf("WebSocket early data needs Xray core or sing-box")
		}
	case "httpupgrade":
		if p.Protocol == profile.Trojan {
			return fmt.Errorf("HTTPUpgrade with Trojan needs Xray core or sing-box")
		}
		if earlyData(t.Path) {
			return fmt.Errorf("HTTPUpgrade early data needs Xray core or sing-box")
		}
	case "grpc":
		if t.Mode == "multi" {
			return fmt.Errorf("gRPC multi mode needs Xray core or sing-box")
		}
		if t.Authority != "" {
			return fmt.Errorf("a gRPC authority needs Xray core")
		}
	case "h2":
		if p.Protocol == profile.Trojan {
			return fmt.Errorf("HTTP/2 with Trojan needs Xray core or sing-box")
		}
		if p.Security.Kind != "tls" {
			return fmt.Errorf("Mihomo runs HTTP/2 only over TLS")
		}
	default:
		return fmt.Errorf("the %s transport needs Xray core or sing-box", t.Type)
	}
	return nil
}

func plainTCP(t profile.Transport) error {
	if t.HeaderType != "" && t.HeaderType != "none" {
		return fmt.Errorf("TCP header obfuscation needs Xray core")
	}
	return nil
}

func checkSecurity(p profile.Profile) error {
	s := p.Security
	switch s.Kind {
	case "", "none", "tls":
	case "reality":
		if p.Protocol != profile.VLESS {
			return fmt.Errorf("Reality needs VLESS")
		}
		if p.Transport.Type != "" && p.Transport.Type != "tcp" {
			return fmt.Errorf("Mihomo runs Reality only over plain TCP")
		}
		if s.SpiderX != "" && s.SpiderX != "/" {
			return fmt.Errorf("a Reality spiderX path needs Xray core")
		}
	default:
		return fmt.Errorf("%s security needs Xray core or sing-box", s.Kind)
	}
	if s.Kind == "tls" || s.Kind == "reality" {
		switch p.Protocol {
		case profile.Shadowsocks, profile.WireGuard:
			return fmt.Errorf("TLS does not apply to %s", profile.ProtocolName(p.Protocol))
		}
	}
	if s.Fingerprint != "" && quic(p) {
		return fmt.Errorf("a TLS fingerprint does not apply to %s", profile.ProtocolName(p.Protocol))
	}
	if s.Fingerprint != "" {
		switch p.Protocol {
		case profile.VLESS, profile.VMess, profile.Trojan, profile.AnyTLS:
		default:
			return fmt.Errorf("a TLS fingerprint needs Xray core or sing-box for %s", profile.ProtocolName(p.Protocol))
		}
	}
	if p.Protocol == profile.SOCKS && s.Kind == "tls" && s.SNI != "" && s.SNI != p.Server {
		return fmt.Errorf("Mihomo cannot set a different server name for SOCKS over TLS")
	}
	return nil
}

func checkWireGuard(p profile.Profile) error {
	w := p.WireGuard
	if w == nil {
		return fmt.Errorf("WireGuard settings are missing")
	}
	if len(w.Reserved) != 0 {
		return fmt.Errorf("WireGuard reserved bytes (Cloudflare WARP) need Xray core or sing-box")
	}
	if v4, v6 := localAddresses(w.LocalAddress); v4 == "" && v6 == "" {
		return fmt.Errorf("WireGuard needs a local IPv4 or IPv6 address")
	}
	return nil
}

// localAddresses picks the first IPv4 and IPv6 address of a WireGuard interface.
func localAddresses(addrs []string) (v4, v6 string) {
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		ip, err := netip.ParsePrefix(a)
		if err != nil {
			addr, aerr := netip.ParseAddr(a)
			if aerr != nil {
				continue
			}
			ip = netip.PrefixFrom(addr, addr.BitLen())
		}
		if ip.Addr().Is4() && v4 == "" {
			v4 = ip.String()
		} else if ip.Addr().Is6() && v6 == "" {
			v6 = ip.String()
		}
	}
	return v4, v6
}

// tcpHop reports whether the hop can be dialed through another hop and can
// carry one: the protocols that run over a TCP stream. UDP-based ones
// (Hysteria2, TUIC, WireGuard) are only ever run as a single server.
func tcpHop(p profile.Profile) bool {
	switch p.Protocol {
	case profile.VLESS, profile.VMess, profile.Trojan, profile.Shadowsocks, profile.SOCKS, profile.HTTP:
		return true
	}
	return false
}

// SupportsSegment reports whether one Mihomo process can run the hops as a
// chain, dialing the first through an upstream bridge when hasUpstream.
func SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	for i, h := range hops {
		if err := Supports(h); err != nil {
			return err
		}
		if (len(hops) > 1 || (hasUpstream && i == 0)) && !tcpHop(h) {
			return fmt.Errorf("Mihomo can only chain TCP-based protocols, not %s", profile.ProtocolName(h.Protocol))
		}
	}
	return nil
}
