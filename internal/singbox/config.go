package singbox

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// Build-tag names reported by "sing-box version" that some protocols need.
const (
	TagQUIC      = "with_quic"
	TagWireGuard = "with_wireguard"
	TagUTLS      = "with_utls"
	TagNaive     = "with_naive_outbound"
	TagOpenVPN   = "with_openvpn"
)

// Supports reports whether sing-box can run the profile. tags are the build
// tags of the installed binary; nil means unknown (not installed yet) and is
// treated like an official release build.
func Supports(p profile.Profile, tags map[string]bool) error {
	need := func(tag, what string) error {
		if tags != nil && !tags[tag] {
			return fmt.Errorf("this sing-box build has no %s support", what)
		}
		return nil
	}
	switch p.Protocol {
	case profile.VLESS:
		if p.Flow != "" && p.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("VLESS flow %q is not supported by sing-box", p.Flow)
		}
		if p.Encryption != "" && p.Encryption != "none" {
			return fmt.Errorf("VLESS encryption is not supported by sing-box")
		}
	case profile.VMess, profile.Trojan, profile.Shadowsocks, profile.SOCKS, profile.HTTP, profile.AnyTLS, profile.ShadowTLS, profile.SSH:
	case profile.Hysteria2, profile.TUIC:
		if err := need(TagQUIC, "QUIC"); err != nil {
			return err
		}
	case profile.Hysteria:
		if err := need(TagQUIC, "QUIC"); err != nil {
			return err
		}
		if p.Hysteria == nil || p.Hysteria.UpMbps <= 0 || p.Hysteria.DownMbps <= 0 {
			return fmt.Errorf("Hysteria needs upload and download bandwidth on sing-box")
		}
	case profile.WireGuard:
		if err := need(TagWireGuard, "WireGuard"); err != nil {
			return err
		}
	case profile.OpenVPN:
		if err := need(TagOpenVPN, "OpenVPN"); err != nil {
			return err
		}
	case profile.Naive:
		if err := need(TagNaive, "NaiveProxy"); err != nil {
			return err
		}
		if p.Security.Insecure {
			return fmt.Errorf("NaiveProxy cannot skip certificate verification")
		}
		if p.Security.Fingerprint != "" {
			return fmt.Errorf("NaiveProxy always uses Chrome's own TLS fingerprint")
		}
	default:
		return fmt.Errorf("%s is not supported by sing-box", profile.ProtocolName(p.Protocol))
	}
	switch t := p.Transport; t.Type {
	case "", "tcp", "udp", "quic":
		if t.HeaderType != "" && t.HeaderType != "none" {
			return fmt.Errorf("TCP header obfuscation is not supported by sing-box")
		}
	case "ws", "grpc", "h2", "httpupgrade":
	default:
		if p.Protocol != profile.Naive {
			return fmt.Errorf("transport %q is not supported by sing-box", t.Type)
		}
	}
	if p.Security.PinSHA256 != "" {
		return fmt.Errorf("certificate pinning (pinSHA256) is only supported by Xray")
	}
	if p.Security.Kind == "reality" || p.Security.Fingerprint != "" {
		if err := need(TagUTLS, "uTLS/Reality"); err != nil {
			return err
		}
	}
	return nil
}

// RequiredRuleSets lists the rule sets (e.g. "geosite-cn") the routing
// settings refer to, so they can be downloaded before building.
func RequiredRuleSets(s models.Settings) []string {
	seen := map[string]bool{}
	for _, list := range routeLists(s) {
		for _, e := range list.entries {
			if name, ok := ruleSetName(e); ok {
				seen[name] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// bridgeTag is the outbound that reaches the previous segment's bridge.
const bridgeTag = "bridge"

func hopTag(i, n int) string {
	if i == n-1 {
		return "proxy" // the exit hop: the routing rules' "proxy" target
	}
	return fmt.Sprintf("hop-%d", i)
}

// SupportsSegment reports whether one sing-box process can run the hops as a
// chain. Every hop must be supported; sing-box dials each hop through the one
// before it with the "detour" dial field.
func SupportsSegment(hops []profile.Profile, tags map[string]bool) error {
	for i, h := range hops {
		if err := Supports(h, tags); err != nil {
			if len(hops) > 1 {
				return fmt.Errorf("hop %d (%s): %w", i+1, profile.ProtocolName(h.Protocol), err)
			}
			return err
		}
	}
	return nil
}

// BuildConfig renders the client configuration of one segment. The last
// segment of a chain carries the user's inbounds and routing; a segment with
// Listen set is a middle segment and only exposes its exit on that bridge.
// ruleSetPath maps a rule set name to its local file.
func BuildConfig(seg profile.Segment, s models.Settings, ruleSetPath func(string) string) (*Config, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	cfg, err := base(seg)
	if err != nil {
		return nil, err
	}
	cfg.Log = logFor(s.LogLevel)
	if seg.Listen != nil {
		cfg.Inbounds = []Inbound{bridgeInbound(*seg.Listen)}
		cfg.Route.Rules = []Rule{}
		return cfg, nil
	}
	exit := seg.Hops[len(seg.Hops)-1]
	if s.Mux && muxCapable(exit) {
		for i := range cfg.Outbounds {
			if cfg.Outbounds[i].Tag == "proxy" {
				cfg.Outbounds[i].Multiplex = &Multiplex{Enabled: true, MaxStreams: s.MuxConcurrency}
			}
		}
	}
	for _, ib := range s.Inbounds {
		if !ib.Enabled {
			continue
		}
		in := Inbound{Type: ib.Protocol, Tag: ib.Tag, Listen: s.EffectiveListen(ib), ListenPort: ib.Port}
		if ib.Username != "" {
			in.Users = []User{{Username: ib.Username, Password: ib.Password}}
		}
		cfg.Inbounds = append(cfg.Inbounds, in)
	}
	rules, sets, err := buildRules(s, ruleSetPath)
	if err != nil {
		return nil, err
	}
	cfg.Route.Rules, cfg.Route.RuleSet = rules, sets
	return cfg, nil
}

func bridgeInbound(b profile.Bridge) Inbound {
	return Inbound{Type: "socks", Tag: "bridge-in", Listen: "127.0.0.1", ListenPort: b.Port,
		Users: []User{{Username: b.User, Password: b.Pass}}}
}

// ProbeConfig is a minimal config: a middle segment exposes its bridge, the
// last segment a SOCKS inbound on 127.0.0.1:port without credentials.
func ProbeConfig(seg profile.Segment, port int) (*Config, error) {
	cfg, err := base(seg)
	if err != nil {
		return nil, err
	}
	cfg.Log = Log{Disabled: true}
	if seg.Listen != nil {
		cfg.Inbounds = []Inbound{bridgeInbound(*seg.Listen)}
	} else {
		cfg.Inbounds = []Inbound{{Type: "socks", Tag: "probe", Listen: "127.0.0.1", ListenPort: port}}
	}
	cfg.Route.Rules = []Rule{}
	return cfg, nil
}

// base holds the chain of hops (each dialing through the one before it), a
// direct outbound and the system resolver used for the first server address.
func base(seg profile.Segment) (*Config, error) {
	n := len(seg.Hops)
	if n == 0 {
		return nil, fmt.Errorf("a segment needs at least one hop")
	}
	for _, h := range seg.Hops {
		if err := h.Validate(); err != nil {
			return nil, err
		}
	}
	if err := SupportsSegment(seg.Hops, nil); err != nil {
		return nil, err
	}
	cfg := &Config{
		DNS:   &DNS{Servers: []DNSServer{{Type: "local", Tag: "local"}}, Final: "local"},
		Route: Route{Final: "proxy", DefaultDomainResolver: "local"},
	}
	detour := ""
	if seg.Upstream != nil {
		u := seg.Upstream
		cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "socks", Tag: bridgeTag, Server: "127.0.0.1", ServerPort: u.Port,
			Version: "5", Username: u.User, Password: u.Pass})
		detour = bridgeTag
	}
	for i, h := range seg.Hops {
		tag := hopTag(i, n)
		switch h.Protocol {
		case profile.WireGuard:
			ep := wireGuard(h)
			ep.Tag, ep.Detour = tag, detour
			cfg.Endpoints = append(cfg.Endpoints, ep)
		case profile.OpenVPN:
			cfg.Endpoints = append(cfg.Endpoints, openVPN(h, tag, detour))
		default:
			obs, err := outbounds(h, tag, detour)
			if err != nil {
				return nil, err
			}
			cfg.Outbounds = append(cfg.Outbounds, obs...)
		}
		detour = tag
	}
	cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "direct", Tag: "direct"})
	return cfg, nil
}

func logFor(level string) Log {
	switch level {
	case "none":
		return Log{Disabled: true}
	case "warning":
		return Log{Level: "warn"}
	}
	return Log{Level: level}
}

func muxCapable(p profile.Profile) bool {
	switch p.Protocol {
	case profile.VLESS, profile.VMess, profile.Trojan, profile.Shadowsocks:
	default:
		return false
	}
	return p.Flow == "" && p.Transport.Type != "grpc" && p.Transport.Type != "h2"
}

func tls(sec profile.Security) *TLS {
	if sec.Kind != "tls" && sec.Kind != "reality" {
		return nil
	}
	t := &TLS{Enabled: true, ServerName: sec.SNI, Insecure: sec.Insecure, ALPN: sec.ALPN}
	if sec.Fingerprint != "" {
		t.UTLS = &UTLS{Enabled: true, Fingerprint: sec.Fingerprint}
	}
	if sec.Kind == "reality" {
		t.Insecure = false
		t.Reality = &Reality{Enabled: true, PublicKey: sec.PublicKey, ShortID: sec.ShortID}
		if t.UTLS == nil {
			t.UTLS = &UTLS{Enabled: true, Fingerprint: "chrome"} // reality needs uTLS
		}
	}
	return t
}

func transport(t profile.Transport) *Transport {
	switch t.Type {
	case "ws":
		tr := &Transport{Type: "ws", Path: orDefault(t.Path, "/")}
		if t.Host != "" {
			tr.Headers = map[string]string{"Host": t.Host}
		}
		return tr
	case "grpc":
		return &Transport{Type: "grpc", ServiceName: t.ServiceName}
	case "h2":
		tr := &Transport{Type: "http", Path: orDefault(t.Path, "/")}
		if hs := splitComma(t.Host); len(hs) > 0 {
			tr.Host = hs
		}
		return tr
	case "httpupgrade":
		tr := &Transport{Type: "httpupgrade", Path: orDefault(t.Path, "/")}
		if t.Host != "" {
			tr.Host = t.Host
		}
		return tr
	}
	return nil
}

// outbounds renders one hop under tag, dialing through detour ("" = directly).
func outbounds(p profile.Profile, tag, detour string) ([]Outbound, error) {
	ob := Outbound{Tag: tag, Detour: detour, Server: p.Server, ServerPort: p.Port, TLS: tls(p.Security), Transport: transport(p.Transport)}
	switch p.Protocol {
	case profile.VLESS:
		ob.Type, ob.UUID, ob.Flow = "vless", p.UUID, p.Flow
	case profile.VMess:
		ob.Type, ob.UUID, ob.Security, ob.AlterID = "vmess", p.UUID, orDefault(p.Cipher, "auto"), p.AlterID
	case profile.Trojan:
		ob.Type, ob.Password = "trojan", p.Password
	case profile.Shadowsocks:
		ob.Type, ob.Method, ob.Password = "shadowsocks", p.Cipher, p.Password
	case profile.SOCKS:
		ob.Type, ob.Version, ob.Username, ob.Password = "socks", "5", p.Username, p.Password
	case profile.HTTP:
		ob.Type, ob.Username, ob.Password = "http", p.Username, p.Password
	case profile.Hysteria2:
		ob.Type, ob.Password = "hysteria2", p.Password
		if h := p.Hysteria; h != nil {
			ob.UpMbps, ob.DownMbps = h.UpMbps, h.DownMbps
			if h.Obfs != "" {
				ob.Obfs = Hy2Obfs{Type: h.Obfs, Password: h.ObfsPassword}
			}
		}
	case profile.Hysteria:
		ob.Type, ob.AuthStr = "hysteria", p.Password
		ob.UpMbps, ob.DownMbps = p.Hysteria.UpMbps, p.Hysteria.DownMbps
		if p.Hysteria.Obfs != "" {
			ob.Obfs = p.Hysteria.ObfsPassword
		}
	case profile.TUIC:
		ob.Type, ob.UUID, ob.Password = "tuic", p.UUID, p.Password
		if t := p.TUIC; t != nil {
			ob.Congestion, ob.UDPRelay, ob.ZeroRTT = t.CongestionControl, t.UDPRelayMode, t.ZeroRTT
		}
	case profile.AnyTLS:
		ob.Type, ob.Password = "anytls", p.Password
		if p.AnyTLS != nil && p.AnyTLS.IdleTimeoutSec > 0 {
			ob.IdleTimeout = strconv.Itoa(p.AnyTLS.IdleTimeoutSec) + "s"
		}
	case profile.Naive:
		// NaiveProxy speaks HTTP/2 through Chrome's stack: sing-box accepts only
		// the server name in its TLS block (no ALPN, uTLS or insecure).
		ob.Type, ob.Username, ob.Password = "naive", p.Username, p.Password
		ob.Transport = nil
		ob.TLS = &TLS{Enabled: true, ServerName: p.Security.SNI}
		if p.Naive != nil {
			ob.ExtraHeaders = p.Naive.ExtraHeaders
		}
	case profile.SSH:
		ob.Type, ob.User, ob.Password, ob.TLS = "ssh", p.Username, p.Password, nil
		if o := p.SSH; o != nil {
			ob.PrivateKeyPath, ob.PrivateKey, ob.Passphrase, ob.HostKey = o.PrivateKeyPath, o.PrivateKey, o.Passphrase, o.HostKeys
		}
	case profile.ShadowTLS:
		st := p.ShadowTLS
		shadow := Outbound{Type: "shadowtls", Tag: tag + "-tls", Detour: detour, Server: p.Server, ServerPort: p.Port,
			Version: st.Version, Password: st.Password, TLS: &TLS{Enabled: true, ServerName: st.SNI}}
		if p.Security.Fingerprint != "" {
			shadow.TLS.UTLS = &UTLS{Enabled: true, Fingerprint: p.Security.Fingerprint}
		}
		inner := Outbound{Type: "shadowsocks", Tag: tag, Method: p.Cipher, Password: p.Password, Detour: tag + "-tls"}
		return []Outbound{inner, shadow}, nil
	default:
		return nil, fmt.Errorf("%s is not supported by sing-box", profile.ProtocolName(p.Protocol))
	}
	return []Outbound{ob}, nil
}

func wireGuard(p profile.Profile) Endpoint {
	w := p.WireGuard
	allowed := w.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	peer := Peer{Address: p.Server, Port: p.Port, PublicKey: w.PeerPublicKey, PreSharedKey: w.PreSharedKey,
		AllowedIPs: allowed, Reserved: w.Reserved}
	peer.Keepalive = w.Keepalive
	return Endpoint{Type: "wireguard", Tag: "proxy", Address: w.LocalAddress, PrivateKey: w.PrivateKey, MTU: w.MTU, Peers: []Peer{peer}}
}

// ---- routing ----

type routeList struct {
	target  string // proxy direct block
	entries []string
}

// routeLists mirrors the Xray rule order: block, explicit proxy, then direct.
func routeLists(s models.Settings) []routeList {
	split := func(v string) []string {
		var out []string
		for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
		return out
	}
	var lists []routeList
	blocked := split(s.BlockedSites)
	if s.BlockAds && len(blocked) == 0 {
		blocked = []string{"geosite:category-ads-all"}
	}
	if s.BlockAds || s.RoutingMode == "custom" {
		lists = append(lists, routeList{"block", blocked})
	}
	switch s.RoutingMode {
	case "custom":
		lists = append(lists, routeList{"proxy", split(s.ProxySites)}, routeList{"direct", split(s.DirectSites)})
	case "global":
	default: // bypass-private
		direct := split(s.DirectSites)
		if len(direct) == 0 {
			direct = []string{"geosite:private", "geosite:cn"}
		}
		lists = append(lists, routeList{"direct", append([]string{"geoip:private"}, direct...)})
	}
	return lists
}

func ruleSetName(e string) (string, bool) {
	for _, kind := range []string{"geosite", "geoip"} {
		if v, ok := strings.CutPrefix(e, kind+":"); ok {
			if kind == "geoip" && v == "private" {
				return "", false // ip_is_private
			}
			return kind + "-" + strings.ToLower(v), true
		}
	}
	return "", false
}

func buildRules(s models.Settings, ruleSetPath func(string) string) ([]Rule, []RuleSet, error) {
	rules := []Rule{}
	if s.Sniffing {
		rules = append(rules, Rule{Action: "sniff"})
	}
	sets := map[string]bool{}
	for _, l := range routeLists(s) {
		if len(l.entries) == 0 {
			continue
		}
		r := Rule{Outbound: l.target}
		if l.target == "block" {
			r = Rule{Action: "reject"}
		}
		for _, e := range l.entries {
			if name, ok := ruleSetName(e); ok {
				r.RuleSet = append(r.RuleSet, name)
				sets[name] = true
				continue
			}
			if err := addMatcher(&r, e); err != nil {
				return nil, nil, err
			}
		}
		rules = append(rules, r)
	}
	names := make([]string, 0, len(sets))
	for n := range sets {
		names = append(names, n)
	}
	sort.Strings(names)
	var rs []RuleSet
	for _, n := range names {
		rs = append(rs, RuleSet{Type: "local", Tag: n, Format: "binary", Path: ruleSetPath(n)})
	}
	return rules, rs, nil
}

// addMatcher maps one Xray-style routing entry onto a sing-box rule.
func addMatcher(r *Rule, e string) error {
	switch {
	case e == "geoip:private":
		r.IPIsPrivate = true
	case strings.HasPrefix(e, "domain:"):
		r.DomainSuffix = append(r.DomainSuffix, strings.TrimPrefix(e, "domain:"))
	case strings.HasPrefix(e, "full:"):
		r.Domain = append(r.Domain, strings.TrimPrefix(e, "full:"))
	case strings.HasPrefix(e, "keyword:"):
		r.DomainKeyword = append(r.DomainKeyword, strings.TrimPrefix(e, "keyword:"))
	case strings.HasPrefix(e, "regexp:"):
		r.DomainRegex = append(r.DomainRegex, strings.TrimPrefix(e, "regexp:"))
	case strings.HasPrefix(e, "ext:"):
		return fmt.Errorf("routing entry %q (ext: files) is not supported by sing-box", e)
	default:
		if _, _, err := net.ParseCIDR(e); err == nil {
			r.IPCIDR = append(r.IPCIDR, e)
		} else if ip := net.ParseIP(e); ip != nil {
			bits := "/32"
			if ip.To4() == nil {
				bits = "/128"
			}
			r.IPCIDR = append(r.IPCIDR, e+bits)
		} else {
			r.DomainKeyword = append(r.DomainKeyword, e) // Xray: a plain string is a substring match
		}
	}
	return nil
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
