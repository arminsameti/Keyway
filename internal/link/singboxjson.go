package link

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"xray-friendly/internal/profile"
)

// LooksLikeSingBox reports whether text is a sing-box JSON config.
func LooksLikeSingBox(text string) bool {
	t := strings.TrimSpace(text)
	return strings.HasPrefix(t, "{") && (strings.Contains(t, `"outbounds"`) || strings.Contains(t, `"endpoints"`))
}

// sbIgnored are outbound types that route traffic rather than describe a server.
var sbIgnored = map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}

// ParseSingBox converts the outbounds (and WireGuard endpoints) of a sing-box
// config. A shadowsocks outbound whose detour is a shadowtls outbound becomes
// one ShadowTLS server.
func ParseSingBox(text string) ([]Item, error) {
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid sing-box JSON: %v", err)
	}
	byTag := map[string]cfg{}
	for _, m := range doc.Outbounds {
		byTag[cfg(m).str("tag")] = cfg(m)
	}
	usedAsDetour := map[string]bool{}
	for _, m := range doc.Outbounds {
		if d := cfg(m).str("detour"); d != "" && byTag[d].str("type") == "shadowtls" {
			usedAsDetour[d] = true
		}
	}
	var items []Item
	all := append(append([]map[string]any{}, doc.Outbounds...), doc.Endpoints...)
	for i, m := range all {
		c := cfg(m)
		typ, tag := strings.ToLower(c.str("type")), c.str("tag")
		if sbIgnored[typ] || (typ == "shadowtls" && usedAsDetour[tag]) {
			continue
		}
		it := Item{Line: i + 1, Scheme: typ, Label: labelOf(tag, typ)}
		p, err := singBoxProfile(c, typ, byTag)
		if err == nil {
			it.Result, err = ProfileNode(p, tag)
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

func singBoxProfile(c cfg, typ string, byTag map[string]cfg) (profile.Profile, error) {
	p := profile.Profile{Server: c.str("server"), Port: c.num("server_port")}
	tls := c.obj("tls")
	switch typ {
	case "shadowsocks":
		p.Protocol, p.Cipher, p.Password = profile.Shadowsocks, strings.ToLower(c.str("method")), c.str("password")
		if c.str("plugin") != "" {
			return p, fmt.Errorf("shadowsocks plugin %q is not supported", c.str("plugin"))
		}
		if d := c.str("detour"); d != "" {
			st, ok := byTag[d]
			if !ok || st.str("type") != "shadowtls" {
				return p, fmt.Errorf("chained outbounds are not supported")
			}
			p.Protocol, p.Server, p.Port = profile.ShadowTLS, st.str("server"), st.num("server_port")
			p.ShadowTLS = &profile.ShadowTLSOpts{Version: max(st.num("version"), 1), Password: st.str("password"), SNI: st.obj("tls").str("server_name")}
		}
	case "shadowtls":
		return p, fmt.Errorf("a shadowtls outbound needs a shadowsocks outbound that uses it as detour")
	case "vmess", "vless", "trojan":
		p.Protocol = typ
		switch typ {
		case "vmess":
			p.UUID, p.AlterID, p.Cipher = c.str("uuid"), c.num("alter_id"), orDefault(c.str("security"), "auto")
		case "vless":
			p.UUID, p.Flow, p.Encryption = c.str("uuid"), c.str("flow"), "none"
		case "trojan":
			p.Password = c.str("password")
		}
		if err := singBoxStream(&p, c); err != nil {
			return p, err
		}
	case "socks":
		p.Protocol, p.Username, p.Password = profile.SOCKS, c.str("username"), c.str("password")
		if v := c.str("version"); v != "" && v != "5" {
			return p, fmt.Errorf("SOCKS%s is not supported; use SOCKS5", v)
		}
	case "http":
		p.Protocol, p.Username, p.Password = profile.HTTP, c.str("username"), c.str("password")
		if tls.flag("enabled") {
			p.Security = singBoxTLS(tls)
		}
	case "hysteria2":
		p.Protocol, p.Password = profile.Hysteria2, c.str("password")
		p.Transport, p.Security = profile.Transport{Type: "quic"}, singBoxTLS(tls)
		if len(p.Security.ALPN) == 0 {
			p.Security.ALPN = []string{"h3"}
		}
		h := &profile.HysteriaOpts{UpMbps: c.num("up_mbps"), DownMbps: c.num("down_mbps")}
		if o := c.obj("obfs"); o.str("type") != "" {
			h.Obfs, h.ObfsPassword = o.str("type"), o.str("password")
		}
		if *h != (profile.HysteriaOpts{}) {
			p.Hysteria = h
		}
	case "hysteria":
		p.Protocol, p.Password = profile.Hysteria, c.str("auth_str")
		p.Transport, p.Security = profile.Transport{Type: "quic"}, singBoxTLS(tls)
		p.Hysteria = &profile.HysteriaOpts{UpMbps: c.num("up_mbps"), DownMbps: c.num("down_mbps")}
		if o := c.str("obfs"); o != "" {
			p.Hysteria.Obfs, p.Hysteria.ObfsPassword = "xplus", o
		}
	case "tuic":
		p.Protocol, p.UUID, p.Password = profile.TUIC, c.str("uuid"), c.str("password")
		p.Transport, p.Security = profile.Transport{Type: "quic"}, singBoxTLS(tls)
		p.TUIC = &profile.TUICOpts{CongestionControl: c.str("congestion_control"), UDPRelayMode: c.str("udp_relay_mode"), ZeroRTT: c.flag("zero_rtt_handshake")}
	case "wireguard":
		p.Protocol, p.Transport = profile.WireGuard, profile.Transport{Type: "udp"}
		w := &profile.WireGuardOpts{PrivateKey: c.str("private_key"), MTU: c.num("mtu"), LocalAddress: c.list("address", "local_address")}
		peer := c
		if peers := c.objs("peers"); len(peers) > 0 { // endpoint format (1.11+)
			peer = peers[0]
			p.Server, p.Port = peer.str("address", "server"), peer.num("port", "server_port")
		}
		w.PeerPublicKey = peer.str("public_key", "peer_public_key")
		w.PreSharedKey, w.AllowedIPs, w.Keepalive = peer.str("pre_shared_key"), peer.list("allowed_ips"), durationSec(peer.str("persistent_keepalive_interval"))
		var err error
		if w.Reserved, err = peer.ints("reserved"); err != nil {
			return p, err
		}
		p.WireGuard = w
	case "anytls":
		p.Protocol, p.Password = profile.AnyTLS, c.str("password")
		p.Transport, p.Security = profile.Transport{Type: "tcp"}, singBoxTLS(tls)
		if idle := durationSec(c.str("idle_session_timeout")); idle > 0 {
			p.AnyTLS = &profile.AnyTLSOpts{IdleTimeoutSec: idle}
		}
	case "naive":
		p.Protocol, p.Username, p.Password = profile.Naive, c.str("username"), c.str("password")
		p.Transport, p.Security = profile.Transport{Type: "h2"}, singBoxTLS(tls)
		if len(p.Security.ALPN) == 0 {
			p.Security.ALPN = []string{"h2"}
		}
		if h := c.obj("extra_headers"); len(h) > 0 {
			p.Naive = &profile.NaiveOpts{ExtraHeaders: map[string]string{}}
			for k := range h {
				p.Naive.ExtraHeaders[k] = h.str(k)
			}
		}
	case "ssh":
		p.Protocol, p.Username, p.Password = profile.SSH, c.str("user"), c.str("password")
		p.SSH = &profile.SSHOpts{PrivateKeyPath: c.str("private_key_path"), PrivateKey: strings.Join(c.list("private_key"), "\n"),
			Passphrase: c.str("private_key_passphrase"), HostKeys: c.list("host_key")}
	default:
		return p, fmt.Errorf("sing-box type %q is not supported", typ)
	}
	return p, p.Validate()
}

// durationSec reads a sing-box duration ("30s", "1m") or a plain number of seconds.
func durationSec(s string) int {
	if s == "" {
		return 0
	}
	if d, err := time.ParseDuration(s); err == nil {
		return int(d.Seconds())
	}
	n, _ := optInt(s)
	return n
}

func singBoxTLS(t cfg) profile.Security {
	sec := profile.Security{
		Kind:        "tls",
		SNI:         t.str("server_name"),
		ALPN:        t.list("alpn"),
		Fingerprint: t.obj("utls").str("fingerprint"),
	}
	if pins := t.list("certificate_public_key_sha256"); len(pins) > 0 && profile.ValidPin(pins[0]) {
		sec.PinSHA256 = pins[0]
	}
	sec.Insecure = sec.PinSHA256 == "" && t.flag("insecure")
	if r := t.obj("reality"); r.flag("enabled") {
		sec.Kind, sec.PublicKey, sec.ShortID = "reality", r.str("public_key"), r.str("short_id")
		sec.Fingerprint = orDefault(sec.Fingerprint, "chrome")
	}
	return sec
}

func singBoxStream(p *profile.Profile, c cfg) error {
	if t := c.obj("tls"); t.flag("enabled") {
		p.Security = singBoxTLS(t)
		if p.Security.Kind == "reality" && p.Security.PublicKey == "" {
			return fmt.Errorf("reality without public key")
		}
	} else {
		p.Security = profile.Security{Kind: "none"}
	}
	tr := c.obj("transport")
	switch typ := tr.str("type"); typ {
	case "":
		p.Transport = profile.Transport{Type: "tcp"}
	case "ws":
		p.Transport = profile.Transport{Type: "ws", Path: orDefault(tr.str("path"), "/"), Host: tr.obj("headers").str("Host", "host")}
	case "grpc":
		p.Transport = profile.Transport{Type: "grpc", ServiceName: tr.str("service_name")}
	case "http":
		p.Transport = profile.Transport{Type: "h2", Path: orDefault(tr.str("path"), "/"), Host: strings.Join(tr.list("host"), ",")}
	case "httpupgrade":
		p.Transport = profile.Transport{Type: "httpupgrade", Path: orDefault(tr.str("path"), "/"), Host: tr.str("host")}
	default:
		return fmt.Errorf("transport %q is not supported", typ)
	}
	return nil
}
