package profile

import (
	"strconv"
	"strings"
)

var protocolNames = map[string]string{
	VLESS: "VLESS", VMess: "VMess", Trojan: "Trojan", Shadowsocks: "Shadowsocks", SOCKS: "SOCKS",
	HTTP: "HTTP", Hysteria2: "Hysteria2", WireGuard: "WireGuard", TUIC: "TUIC", Hysteria: "Hysteria",
	AnyTLS: "AnyTLS", ShadowTLS: "ShadowTLS", Naive: "NaiveProxy", SSH: "SSH", OpenVPN: "OpenVPN", Tor: "Tor", Chain: "Chain", Custom: "Custom",
}

var transportNames = map[string]string{
	"tcp": "TCP", "ws": "WebSocket", "grpc": "gRPC", "httpupgrade": "HTTPUpgrade", "xhttp": "XHTTP",
	"h2": "HTTP/2", "kcp": "mKCP", "quic": "QUIC", "udp": "UDP",
}

// ProtocolName is the user-facing protocol label ("VLESS", "Hysteria2").
func ProtocolName(protocol string) string {
	if n, ok := protocolNames[protocol]; ok {
		return n
	}
	return protocol
}

// DisplayTransport is the "Transport" column: the stream layer, except that a
// plain-TCP Reality server shows "Reality", which is what users recognise.
func (p Profile) DisplayTransport() string {
	if p.Protocol == Custom {
		return "Custom"
	}
	t := p.Transport.Type
	if p.Protocol == Naive && t == "" {
		t = "h2"
	}
	if t == "" {
		t = "tcp"
		if p.Protocol == OpenVPN {
			t = "udp"
		}
		if p.UDPBased() {
			t = "udp"
			if p.Protocol != WireGuard {
				t = "quic"
			}
		}
	}
	if p.Protocol == OpenVPN && p.Transport.Type == "" {
		t = "udp"
	}
	if t == "tcp" && p.Security.Kind == "reality" {
		return "Reality"
	}
	if n, ok := transportNames[t]; ok {
		return n
	}
	return t
}

// DisplaySecurity is the inspector's "Security" row.
func (p Profile) DisplaySecurity() string {
	switch p.Protocol {
	case Custom:
		return "—"
	case Shadowsocks:
		if strings.HasPrefix(p.Cipher, "2022-blake3-") {
			return "2022-blake3"
		}
		return p.Cipher
	case WireGuard:
		return "Curve25519 keys"
	case OpenVPN:
		s := "TLS"
		if p.OpenVPN != nil && p.OpenVPN.ControlWrap != nil {
			s += " · " + strings.ReplaceAll(p.OpenVPN.ControlWrap.Type, "_", "-")
		}
		return s
	case ShadowTLS:
		v := 3
		if p.ShadowTLS != nil {
			v = p.ShadowTLS.Version
		}
		return "ShadowTLS v" + strconv.Itoa(v)
	case SSH:
		if p.SSH != nil && (p.SSH.PrivateKeyPath != "" || p.SSH.PrivateKey != "") {
			return "SSH key"
		}
		return "Password"
	case TUIC:
		if p.TUIC != nil && p.TUIC.CongestionControl != "" {
			return "TLS · " + strings.ToUpper(p.TUIC.CongestionControl)
		}
	case Hysteria2, Hysteria:
		if p.Hysteria != nil && p.Hysteria.Obfs != "" {
			return "TLS · obfuscated"
		}
	}
	switch p.Security.Kind {
	case "reality":
		if strings.Contains(p.Flow, "vision") {
			return "Reality · Vision"
		}
		return "Reality"
	case "tls":
		if p.Security.PinSHA256 != "" {
			return "TLS · pinned"
		}
		return "TLS"
	}
	return "None"
}

// DisplaySNI is the server name used for TLS, or "—".
func (p Profile) DisplaySNI() string {
	if p.Security.Kind == "" || p.Security.Kind == "none" {
		return "—"
	}
	if p.Security.SNI != "" {
		return p.Security.SNI
	}
	return p.Server
}
