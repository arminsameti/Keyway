package link

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"keyway/internal/profile"
)

// LooksLikeClash reports whether text is a Clash / Clash Meta (mihomo) config.
func LooksLikeClash(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimRight(line, " \r"), "proxies:") {
			return true
		}
	}
	return false
}

// ParseClash converts the "proxies" list of a Clash config. Every entry yields
// an Item: ready, or skipped with the reason.
func ParseClash(text string) ([]Item, error) {
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, fmt.Errorf("invalid Clash YAML: %s", firstLine(err.Error()))
	}
	items := make([]Item, 0, len(doc.Proxies))
	for i, m := range doc.Proxies {
		c := cfg(m)
		name, typ := strings.TrimSpace(c.str("name")), strings.ToLower(c.str("type"))
		it := Item{Line: i + 1, Scheme: typ, Label: labelOf(name, typ), Name: name}
		p, err := clashProfile(c, typ)
		if err == nil {
			it.Result, err = ProfileNode(p, name)
		}
		if err != nil {
			it.Kind, it.Reason = KindSkipped, capitalize(err.Error())
		} else {
			it.Kind = KindReady
		}
		items = append(items, it)
	}
	return items, nil
}

func labelOf(name, typ string) string {
	if name == "" {
		return typ
	}
	return name + " (" + typ + ")"
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func clashProfile(c cfg, typ string) (profile.Profile, error) {
	p := profile.Profile{Server: c.str("server"), Port: c.num("port")}
	switch typ {
	case "ss":
		p.Protocol, p.Cipher, p.Password = profile.Shadowsocks, strings.ToLower(c.str("cipher")), c.str("password")
		switch plugin := c.str("plugin"); plugin {
		case "":
		case "shadow-tls":
			o := c.obj("plugin-opts")
			p.Protocol = profile.ShadowTLS
			p.ShadowTLS = &profile.ShadowTLSOpts{Version: max(o.num("version"), 2), Password: o.str("password"), SNI: o.str("host")}
		default:
			return p, fmt.Errorf("shadowsocks plugin %q is not supported", plugin)
		}
		if !ssMethodOK(p.Cipher) {
			return p, fmt.Errorf("unsupported cipher %q", p.Cipher)
		}
	case "vmess", "vless", "trojan":
		p.Protocol = typ
		switch typ {
		case "vmess":
			p.UUID, p.AlterID, p.Cipher = c.str("uuid"), c.num("alterId"), orDefault(c.str("cipher"), "auto")
		case "vless":
			p.UUID, p.Flow, p.Encryption = c.str("uuid"), c.str("flow"), orDefault(c.str("encryption"), "none")
		case "trojan":
			p.Password = c.str("password")
		}
		if err := clashStream(&p, c, typ == "trojan"); err != nil {
			return p, err
		}
	case "socks5":
		p.Protocol, p.Username, p.Password = profile.SOCKS, c.str("username"), c.str("password")
		if c.flag("tls") {
			return p, fmt.Errorf("SOCKS over TLS is not supported")
		}
	case "http":
		p.Protocol, p.Username, p.Password = profile.HTTP, c.str("username"), c.str("password")
		if c.flag("tls") {
			p.Security = clashTLS(c)
		}
	case "hysteria2":
		p.Protocol, p.Password = profile.Hysteria2, c.str("password", "auth")
		p.Transport, p.Security = profile.Transport{Type: "quic"}, clashTLS(c)
		if len(p.Security.ALPN) == 0 {
			p.Security.ALPN = []string{"h3"}
		}
		h := &profile.HysteriaOpts{UpMbps: mbps(c, "up"), DownMbps: mbps(c, "down")}
		if o := c.str("obfs"); o != "" {
			h.Obfs, h.ObfsPassword = o, c.str("obfs-password")
		}
		if *h != (profile.HysteriaOpts{}) {
			p.Hysteria = h
		}
	case "hysteria":
		if pr := c.str("protocol"); pr != "" && pr != "udp" {
			return p, fmt.Errorf("hysteria %s mode is not supported", pr)
		}
		p.Protocol, p.Password = profile.Hysteria, c.str("auth-str", "auth_str", "auth")
		p.Transport, p.Security = profile.Transport{Type: "quic"}, clashTLS(c)
		if len(p.Security.ALPN) == 0 {
			p.Security.ALPN = []string{"hysteria"}
		}
		p.Hysteria = &profile.HysteriaOpts{UpMbps: mbps(c, "up"), DownMbps: mbps(c, "down")}
		if o := c.str("obfs"); o != "" {
			p.Hysteria.Obfs, p.Hysteria.ObfsPassword = "xplus", o
		}
	case "tuic":
		if c.str("token") != "" {
			return p, fmt.Errorf("TUIC v4 is not supported; use v5")
		}
		p.Protocol, p.UUID, p.Password = profile.TUIC, c.str("uuid"), c.str("password")
		p.Transport, p.Security = profile.Transport{Type: "quic"}, clashTLS(c)
		if len(p.Security.ALPN) == 0 {
			p.Security.ALPN = []string{"h3"}
		}
		p.TUIC = &profile.TUICOpts{CongestionControl: c.str("congestion-controller"), UDPRelayMode: c.str("udp-relay-mode"), ZeroRTT: c.flag("reduce-rtt")}
	case "wireguard":
		p.Protocol, p.Transport = profile.WireGuard, profile.Transport{Type: "udp"}
		w := &profile.WireGuardOpts{PrivateKey: c.str("private-key"), MTU: c.num("mtu")}
		for _, a := range []string{c.str("ip"), c.str("ipv6")} {
			if a != "" && !strings.Contains(a, "/") {
				if strings.Contains(a, ":") {
					a += "/128"
				} else {
					a += "/32"
				}
			}
			if a != "" {
				w.LocalAddress = append(w.LocalAddress, a)
			}
		}
		peer := c
		if peers := c.objs("peers"); len(peers) > 0 {
			peer = peers[0]
			p.Server, p.Port = peer.str("server"), peer.num("port")
		}
		w.PeerPublicKey, w.PreSharedKey, w.AllowedIPs = peer.str("public-key"), peer.str("pre-shared-key"), peer.list("allowed-ips")
		var err error
		if w.Reserved, err = peer.ints("reserved"); err != nil {
			return p, err
		}
		p.WireGuard = w
	case "anytls":
		p.Protocol, p.Password = profile.AnyTLS, c.str("password")
		p.Transport, p.Security = profile.Transport{Type: "tcp"}, clashTLS(c)
		if idle := c.num("idle-session-timeout"); idle > 0 {
			p.AnyTLS = &profile.AnyTLSOpts{IdleTimeoutSec: idle}
		}
	case "ssh":
		p.Protocol, p.Username, p.Password = profile.SSH, c.str("username"), c.str("password")
		key := c.str("private-key")
		o := &profile.SSHOpts{Passphrase: c.str("private-key-passphrase"), HostKeys: c.list("host-key")}
		if strings.Contains(key, "PRIVATE KEY") {
			o.PrivateKey = key
		} else {
			o.PrivateKeyPath = key
		}
		p.SSH = o
	case "ssr":
		return p, fmt.Errorf("ShadowsocksR is retired — skipped")
	default:
		return p, fmt.Errorf("Clash type %q is not supported", typ)
	}
	return p, p.Validate()
}

// clashTLS reads the TLS keys shared by Clash proxy types.
func clashTLS(c cfg) profile.Security {
	sec := profile.Security{
		Kind:        "tls",
		SNI:         c.str("sni", "servername", "peer"),
		ALPN:        c.list("alpn"),
		Fingerprint: c.str("client-fingerprint"),
	}
	if pin := c.str("fingerprint"); profile.ValidPin(pin) {
		sec.PinSHA256 = pin // mihomo: certificate fingerprint
	}
	sec.Insecure = sec.PinSHA256 == "" && c.flag("skip-cert-verify")
	return sec
}

func clashStream(p *profile.Profile, c cfg, tlsDefault bool) error {
	network := c.str("network")
	if network == "http" { // Clash: HTTP/1.1 header obfuscation over TCP, not HTTP/2
		network = "tcp"
	}
	sp := streamParams{Network: normalizeNetwork(network), Security: "none"}
	if c.flag("tls") || (tlsDefault && c["tls"] == nil) {
		sp.Security = "tls"
	}
	sec := clashTLS(c)
	sp.SNI, sp.FP, sp.AllowInsecure = sec.SNI, sec.Fingerprint, sec.Insecure
	sp.ALPN = strings.Join(sec.ALPN, ",")
	if r := c.obj("reality-opts"); r.str("public-key") != "" {
		sp.Security, sp.PublicKey, sp.ShortID = "reality", r.str("public-key"), r.str("short-id")
	}
	switch sp.Network {
	case "ws":
		o := c.obj("ws-opts")
		sp.Path, sp.Host = o.str("path"), o.obj("headers").str("Host", "host")
		if o.flag("v2ray-http-upgrade") {
			sp.Network = "httpupgrade"
		}
	case "grpc":
		sp.ServiceName = c.obj("grpc-opts").str("grpc-service-name")
	case "h2":
		o := c.obj("h2-opts")
		sp.Path, sp.Host = o.str("path"), strings.Join(o.list("host"), ",")
	case "tcp":
		if o := c.obj("http-opts"); len(o) > 0 {
			sp.HeaderType, sp.Path = "http", strings.Join(o.list("path"), ",")
			sp.Host = strings.Join(o.obj("headers").list("Host", "host"), ",")
		}
	}
	if err := applyStream(p, sp); err != nil {
		return err
	}
	if p.Security.Kind == "tls" {
		p.Security.PinSHA256 = sec.PinSHA256
	}
	return nil
}
