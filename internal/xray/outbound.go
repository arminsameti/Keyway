package xray

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"xray-friendly/internal/profile"
)

// Supports reports whether Xray can run the profile, with the reason if not.
func Supports(p profile.Profile) error {
	switch p.Protocol {
	case profile.VLESS, profile.VMess, profile.Trojan, profile.Shadowsocks, profile.SOCKS, profile.HTTP, profile.WireGuard:
	case profile.Hysteria2:
		if h := p.Hysteria; h != nil && h.Obfs != "" {
			return fmt.Errorf("Hysteria2 obfuscation needs sing-box")
		}
		if h := p.Hysteria; h != nil && (h.UpMbps > 0 || h.DownMbps > 0) {
			return fmt.Errorf("Hysteria2 bandwidth settings need sing-box")
		}
	default:
		return fmt.Errorf("%s needs sing-box", profile.ProtocolName(p.Protocol))
	}
	if p.Security.Insecure && p.Security.PinSHA256 == "" {
		// Xray 26 removed allowInsecure; sing-box still offers it.
		return fmt.Errorf("skipping certificate verification needs sing-box (Xray accepts only a pinned certificate)")
	}
	if t := p.Transport.Type; t == "quic" && p.Protocol != profile.Hysteria2 {
		return fmt.Errorf("transport %q is not supported by Xray", t)
	}
	return nil
}

// tcpHop reports whether the hop is a TCP-stream proxy, the only kind Xray can
// chain: a hop dials through the previous one with sockopt.dialerProxy, which
// needs both ends to be TCP streams.
func tcpHop(p profile.Profile) bool {
	switch p.Protocol {
	case profile.VLESS, profile.VMess, profile.Trojan, profile.Shadowsocks, profile.SOCKS, profile.HTTP:
		return p.Transport.Type != "kcp"
	}
	return false
}

// SupportsSegment reports whether one Xray process can run the hops as a
// chain, dialing the first through an upstream bridge when hasUpstream.
func SupportsSegment(hops []profile.Profile, hasUpstream bool) error {
	for i, h := range hops {
		if err := Supports(h); err != nil {
			return err
		}
		chained := len(hops) > 1 || (hasUpstream && i == 0)
		if chained && !tcpHop(h) {
			return fmt.Errorf("Xray can only chain TCP-based protocols, not %s", profile.ProtocolName(h.Protocol))
		}
	}
	return nil
}

// bridgeTag is the outbound that reaches the previous segment's bridge.
const bridgeTag = "bridge"

func hopTag(i, n int) string {
	if i == n-1 {
		return "proxy"
	}
	return fmt.Sprintf("hop-%d", i)
}

// chainOutbound renders one hop; dialer is the tag of the outbound it dials
// through ("" = directly).
func chainOutbound(p profile.Profile, tag, dialer string) (Outbound, error) {
	ob, err := FromProfile(p)
	if err != nil {
		return Outbound{}, err
	}
	ob.Tag, ob.Mux = tag, nil
	if dialer != "" {
		if ob.StreamSettings == nil {
			ob.StreamSettings = &StreamSettings{Network: "tcp"}
		}
		ob.StreamSettings.Sockopt = &Sockopt{DialerProxy: dialer}
	}
	return ob, nil
}

// segmentOutbounds renders the hops of a segment. The exit hop comes first:
// Xray sends traffic that matches no rule to the first outbound.
func segmentOutbounds(seg profile.Segment) ([]Outbound, error) {
	n := len(seg.Hops)
	if n == 0 {
		return nil, fmt.Errorf("a segment needs at least one hop")
	}
	if err := SupportsSegment(seg.Hops, seg.Upstream != nil); err != nil {
		return nil, err
	}
	var bridge []Outbound
	dialer := ""
	if u := seg.Upstream; u != nil {
		bridge = []Outbound{{Tag: bridgeTag, Protocol: "socks", Settings: &ServersSettings{Servers: []Server{{
			Address: "127.0.0.1", Port: u.Port, Users: []Account{{User: u.User, Pass: u.Pass}}}}}}}
		dialer = bridgeTag
	}
	hops := make([]Outbound, n)
	for i, h := range seg.Hops {
		ob, err := chainOutbound(h, hopTag(i, n), dialer)
		if err != nil {
			return nil, err
		}
		hops[i], dialer = ob, ob.Tag
	}
	out := []Outbound{hops[n-1]}
	out = append(out, hops[:n-1]...)
	return append(out, bridge...), nil
}

// FromProfile maps an engine-neutral profile onto a typed Xray outbound.
func FromProfile(p profile.Profile) (Outbound, error) {
	if err := p.Validate(); err != nil {
		return Outbound{}, err
	}
	if err := Supports(p); err != nil {
		return Outbound{}, err
	}
	var ob Outbound
	switch p.Protocol {
	case profile.VLESS:
		ob = Outbound{Protocol: "vless", Settings: &VNextSettings{VNext: []VNext{{
			Address: p.Server, Port: p.Port,
			Users: []User{{ID: p.UUID, Encryption: orDefault(p.Encryption, "none"), Flow: p.Flow}},
		}}}}
	case profile.VMess:
		aid := p.AlterID
		ob = Outbound{Protocol: "vmess", Settings: &VNextSettings{VNext: []VNext{{
			Address: p.Server, Port: p.Port,
			Users: []User{{ID: p.UUID, AlterID: &aid, Security: orDefault(p.Cipher, "auto")}},
		}}}}
	case profile.Trojan:
		ob = Outbound{Protocol: "trojan", Settings: &ServersSettings{Servers: []Server{{
			Address: p.Server, Port: p.Port, Password: p.Password,
		}}}}
	case profile.Shadowsocks:
		return Outbound{Protocol: "shadowsocks", Settings: &ServersSettings{Servers: []Server{{
			Address: p.Server, Port: p.Port, Method: p.Cipher, Password: p.Password,
		}}}}, nil
	case profile.SOCKS, profile.HTTP:
		srv := Server{Address: p.Server, Port: p.Port}
		if p.Username != "" {
			srv.Users = []Account{{User: p.Username, Pass: p.Password}}
		}
		ob = Outbound{Protocol: p.Protocol, Settings: &ServersSettings{Servers: []Server{srv}}}
		if p.Protocol == profile.SOCKS || p.Security.Kind != "tls" {
			return ob, nil
		}
		// HTTPS proxy: HTTP CONNECT over TLS.
	case profile.WireGuard:
		w := p.WireGuard
		allowed := w.AllowedIPs
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		return Outbound{Protocol: "wireguard", Settings: &WireGuardSettings{
			SecretKey: w.PrivateKey, Address: w.LocalAddress, MTU: w.MTU, Reserved: w.Reserved,
			Peers: []WireGuardPeer{{
				PublicKey: w.PeerPublicKey, PreSharedKey: w.PreSharedKey, KeepAlive: w.Keepalive, AllowedIPs: allowed,
				Endpoint: net.JoinHostPort(p.Server, strconv.Itoa(p.Port)),
			}},
		}}, nil
	case profile.Hysteria2:
		return Outbound{
			Protocol: "hysteria",
			Settings: &HysteriaSettings{Version: 2, Address: p.Server, Port: p.Port},
			StreamSettings: &StreamSettings{
				Network:  "hysteria",
				Security: "tls",
				TLS:      tlsSettings(p.Security, []string{"h3"}),
				Hysteria: &HysteriaStream{Version: 2, Auth: p.Password},
			},
		}, nil
	}
	ss, err := streamSettings(p)
	if err != nil {
		return Outbound{}, err
	}
	ob.StreamSettings = ss
	return ob, nil
}

// tlsSettings maps the profile's TLS layer. Recent cores reject allowInsecure,
// and Supports sends unpinned insecure servers to sing-box, so it is never set.
func tlsSettings(sec profile.Security, defaultALPN []string) *TLSSettings {
	t := &TLSSettings{
		ServerName:           sec.SNI,
		ALPN:                 sec.ALPN,
		Fingerprint:          sec.Fingerprint,
		PinnedPeerCertSha256: sec.PinSHA256,
	}
	if len(t.ALPN) == 0 {
		t.ALPN = defaultALPN
	}
	return t
}

func streamSettings(p profile.Profile) (*StreamSettings, error) {
	tr := p.Transport
	if tr.Type == "" {
		tr.Type = "tcp"
	}
	ss := &StreamSettings{Network: tr.Type, Security: orDefault(p.Security.Kind, "none")}
	switch ss.Security {
	case "none":
	case "tls":
		ss.TLS = tlsSettings(p.Security, nil)
	case "reality":
		ss.Reality = &RealitySettings{
			ServerName:  p.Security.SNI,
			Fingerprint: orDefault(p.Security.Fingerprint, "chrome"),
			PublicKey:   p.Security.PublicKey,
			ShortID:     p.Security.ShortID,
			SpiderX:     p.Security.SpiderX,
		}
	default:
		return nil, fmt.Errorf("unsupported security %q", ss.Security)
	}

	switch tr.Type {
	case "tcp":
		if strings.EqualFold(tr.HeaderType, "http") {
			req := &TCPRequest{Path: []string{orDefault(tr.Path, "/")}}
			if tr.Host != "" {
				req.Headers = map[string][]string{"Host": splitComma(tr.Host)}
			}
			ss.TCP = &TCPSettings{Header: &TCPHeader{Type: "http", Request: req}}
		}
	case "ws":
		ws := &WSSettings{Path: orDefault(tr.Path, "/")}
		if tr.Host != "" {
			ws.Headers = map[string]string{"Host": tr.Host}
		}
		ss.WS = ws
	case "grpc":
		ss.GRPC = &GRPCSettings{ServiceName: tr.ServiceName, Authority: tr.Authority, MultiMode: tr.Mode == "multi"}
	case "httpupgrade":
		ss.HTTPUpgrade = &HTTPUpgradeSettings{Path: orDefault(tr.Path, "/"), Host: tr.Host}
	case "xhttp":
		ss.XHTTP = &XHTTPSettings{Path: orDefault(tr.Path, "/"), Host: tr.Host, Mode: tr.Mode}
	case "h2":
		ss.H2 = &H2Settings{Path: orDefault(tr.Path, "/"), Host: splitComma(tr.Host)}
	case "kcp":
		k := &KCPSettings{Seed: tr.Seed}
		if tr.HeaderType != "" && tr.HeaderType != "none" {
			k.Header = &KCPHeader{Type: tr.HeaderType}
		}
		ss.KCP = k
	default:
		return nil, fmt.Errorf("transport %q is not supported by Xray", tr.Type)
	}
	return ss, nil
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
