package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

func rsPath(n string) string { return "/rules/" + n + ".srs" }

func js(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func build(t *testing.T, p profile.Profile, mut func(*models.Settings)) string {
	t.Helper()
	s := models.DefaultSettings()
	if mut != nil {
		mut(&s)
	}
	cfg, err := BuildConfig(profile.Single(p), s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	return js(t, cfg)
}

func want(t *testing.T, name, got string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(got, p) {
			t.Errorf("%s: missing %s\n%s", name, p, got)
		}
	}
}

var tlsSec = profile.Security{Kind: "tls", SNI: "s.example.net"}

func TestOutboundPerProtocol(t *testing.T) {
	cases := []struct {
		name string
		p    profile.Profile
		want []string
	}{
		{"vless reality", profile.Profile{Protocol: profile.VLESS, Server: "a.com", Port: 443, UUID: "id", Flow: "xtls-rprx-vision",
			Security: profile.Security{Kind: "reality", SNI: "w.com", PublicKey: "PK", ShortID: "ab"}},
			[]string{`"type":"vless"`, `"tag":"proxy"`, `"uuid":"id"`, `"flow":"xtls-rprx-vision"`, `"reality":{"enabled":true,"public_key":"PK","short_id":"ab"}`, `"utls":{"enabled":true,"fingerprint":"chrome"}`}},
		{"vmess ws", profile.Profile{Protocol: profile.VMess, Server: "a.com", Port: 443, UUID: "id", Cipher: "auto",
			Transport: profile.Transport{Type: "ws", Path: "/p", Host: "cdn.com"}, Security: tlsSec},
			[]string{`"type":"vmess"`, `"security":"auto"`, `"transport":{"type":"ws","path":"/p","headers":{"Host":"cdn.com"}}`, `"server_name":"s.example.net"`}},
		{"trojan h2", profile.Profile{Protocol: profile.Trojan, Server: "a.com", Port: 443, Password: "pw",
			Transport: profile.Transport{Type: "h2", Path: "/h", Host: "a.com,b.com"}, Security: tlsSec},
			[]string{`"type":"trojan"`, `"transport":{"type":"http","path":"/h","host":["a.com","b.com"]}`}},
		{"ss", profile.Profile{Protocol: profile.Shadowsocks, Server: "a.com", Port: 8388, Cipher: "2022-blake3-aes-128-gcm", Password: "pw"},
			[]string{`"type":"shadowsocks"`, `"method":"2022-blake3-aes-128-gcm"`}},
		{"socks", profile.Profile{Protocol: profile.SOCKS, Server: "a.com", Port: 1080, Username: "u", Password: "p"},
			[]string{`"type":"socks"`, `"version":"5"`, `"username":"u"`}},
		{"hy2 obfs", profile.Profile{Protocol: profile.Hysteria2, Server: "h.com", Port: 443, Password: "pw", Security: profile.Security{Kind: "tls", SNI: "h.com", Insecure: true},
			Hysteria: &profile.HysteriaOpts{UpMbps: 50, DownMbps: 200, Obfs: "salamander", ObfsPassword: "ob"}},
			[]string{`"type":"hysteria2"`, `"up_mbps":50`, `"obfs":{"type":"salamander","password":"ob"}`, `"insecure":true`}},
		{"hysteria", profile.Profile{Protocol: profile.Hysteria, Server: "h.com", Port: 443, Password: "auth", Security: tlsSec,
			Hysteria: &profile.HysteriaOpts{UpMbps: 30, DownMbps: 100, Obfs: "xplus", ObfsPassword: "ob"}},
			[]string{`"type":"hysteria"`, `"auth_str":"auth"`, `"down_mbps":100`, `"obfs":"ob"`}},
		{"tuic", profile.Profile{Protocol: profile.TUIC, Server: "t.com", Port: 443, UUID: "id", Password: "pw", Security: tlsSec,
			TUIC: &profile.TUICOpts{CongestionControl: "bbr", UDPRelayMode: "native", ZeroRTT: true}},
			[]string{`"type":"tuic"`, `"congestion_control":"bbr"`, `"udp_relay_mode":"native"`, `"zero_rtt_handshake":true`}},
		{"anytls", profile.Profile{Protocol: profile.AnyTLS, Server: "a.com", Port: 443, Password: "pw", Security: tlsSec, AnyTLS: &profile.AnyTLSOpts{IdleTimeoutSec: 30}},
			[]string{`"type":"anytls"`, `"idle_session_timeout":"30s"`}},
		{"naive", profile.Profile{Protocol: profile.Naive, Server: "n.com", Port: 443, Username: "u", Password: "p", Transport: profile.Transport{Type: "h2"},
			Security: profile.Security{Kind: "tls", ALPN: []string{"h2"}}, Naive: &profile.NaiveOpts{ExtraHeaders: map[string]string{"X-A": "1"}}},
			[]string{`"type":"naive"`, `"extra_headers":{"X-A":"1"}`, `"tls":{"enabled":true}`}},
		{"ssh", profile.Profile{Protocol: profile.SSH, Server: "s.com", Port: 22, Username: "root", SSH: &profile.SSHOpts{PrivateKeyPath: "/k", HostKeys: []string{"ssh-ed25519 AAA"}}},
			[]string{`"type":"ssh"`, `"user":"root"`, `"private_key_path":"/k"`, `"host_key":["ssh-ed25519 AAA"]`}},
	}
	for _, c := range cases {
		cfg, err := ProbeConfig(profile.Single(c.p), 4321)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := js(t, cfg)
		want(t, c.name, got, c.want...)
		want(t, c.name, got, `"listen_port":4321`, `"final":"proxy"`, `"default_domain_resolver":"local"`)
	}
}

func TestShadowTLSAndWireGuard(t *testing.T) {
	st := profile.Profile{Protocol: profile.ShadowTLS, Server: "st.com", Port: 443, Cipher: "2022-blake3-aes-128-gcm", Password: "inner",
		ShadowTLS: &profile.ShadowTLSOpts{Version: 3, Password: "outer", SNI: "www.example.com"}}
	got := build(t, st, nil)
	want(t, "shadowtls", got, `{"type":"shadowsocks","tag":"proxy","detour":"proxy-tls","method":"2022-blake3-aes-128-gcm","password":"inner"}`,
		`"type":"shadowtls","tag":"proxy-tls","server":"st.com","server_port":443`, `"version":3`, `"server_name":"www.example.com"`)

	wg := profile.Profile{Protocol: profile.WireGuard, Server: "wg.org", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "PRIV", PeerPublicKey: "PUB", LocalAddress: []string{"10.7.0.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}, Keepalive: 25}}
	got = build(t, wg, nil)
	want(t, "wireguard", got, `"endpoints":[{"type":"wireguard","tag":"proxy","address":["10.7.0.2/32"],"private_key":"PRIV","mtu":1420`,
		`"peers":[{"address":"wg.org","port":51820,"public_key":"PUB","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25,"reserved":[1,2,3]}]`)
	if strings.Contains(got, `"type":"wireguard","tag":"proxy","server"`) {
		t.Error("wireguard must be an endpoint, not an outbound")
	}
}

func TestInboundsAndRouting(t *testing.T) {
	vless := profile.Profile{Protocol: profile.VLESS, Server: "a.com", Port: 443, UUID: "id", Security: tlsSec}
	got := build(t, vless, func(s *models.Settings) {
		s.DirectSites = "geosite:private, geosite:IR, domain:example.org, full:a.com, keyword:bank, regexp:^x$, 10.0.0.0/8, 1.2.3.4, plainword"
		s.Inbounds[0].Username, s.Inbounds[0].Password = "u", "p"
		s.Inbounds[0].Listen = "127.0.0.1"
	})
	want(t, "inbounds", got, `{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":10808,"users":[{"username":"u","password":"p"}]}`,
		`{"type":"http","tag":"http-in","listen":"127.0.0.1","listen_port":10809}`)
	want(t, "rules", got, `{"action":"sniff"}`,
		`{"action":"reject","rule_set":["geosite-category-ads-all"]}`,
		`"outbound":"direct","domain":["a.com"],"domain_suffix":["example.org"],"domain_keyword":["bank","plainword"],"domain_regex":["^x$"],"ip_cidr":["10.0.0.0/8","1.2.3.4/32"],"ip_is_private":true,"rule_set":["geosite-private","geosite-ir"]`,
		`{"type":"local","tag":"geosite-ir","format":"binary","path":"/rules/geosite-ir.srs"}`)
	if strings.Contains(got, `"action":"resolve"`) {
		t.Error("no forced resolve: it would leak DNS for proxied domains")
	}

	if names := RequiredRuleSets(models.DefaultSettings()); strings.Join(names, ",") != "geosite-category-ads-all,geosite-cn,geosite-private" {
		t.Errorf("default rule sets: %v", names)
	}
	global := build(t, vless, func(s *models.Settings) { s.RoutingMode = "global"; s.BlockAds = false; s.Sniffing = false })
	if strings.Contains(global, "rule_set") || !strings.Contains(global, `"rules":[]`) {
		t.Errorf("global without ads blocking needs no rules: %s", global)
	}
	if _, err := BuildConfig(profile.Single(vless), func() models.Settings { s := models.DefaultSettings(); s.DirectSites = "ext:my.dat:x"; return s }(), rsPath); err == nil {
		t.Error("ext: entries must be refused, not dropped")
	}
	mux := build(t, vless, func(s *models.Settings) { s.Mux = true; s.MuxConcurrency = 4 })
	want(t, "mux", mux, `"multiplex":{"enabled":true,"max_streams":4}`)
	vision := vless
	vision.Flow = "xtls-rprx-vision"
	if strings.Contains(build(t, vision, func(s *models.Settings) { s.Mux = true }), "multiplex") {
		t.Error("no multiplex with vision")
	}
	if !strings.Contains(build(t, vless, func(s *models.Settings) { s.LogLevel = "warning" }), `"log":{"level":"warn"}`) {
		t.Error("log level mapping")
	}
}

func TestSupports(t *testing.T) {
	official := map[string]bool{TagQUIC: true, TagWireGuard: true, TagUTLS: true}
	cases := []struct {
		p    profile.Profile
		tags map[string]bool
		ok   bool
	}{
		{profile.Profile{Protocol: profile.TUIC}, nil, true},
		{profile.Profile{Protocol: profile.TUIC}, map[string]bool{}, false}, // no with_quic
		{profile.Profile{Protocol: profile.Naive}, official, false},         // no with_naive_outbound
		{profile.Profile{Protocol: profile.Naive}, map[string]bool{TagNaive: true}, true},
		{profile.Profile{Protocol: profile.Naive, Security: profile.Security{Kind: "tls", Insecure: true}}, map[string]bool{TagNaive: true}, false},
		{profile.Profile{Protocol: profile.VLESS, Transport: profile.Transport{Type: "xhttp"}}, nil, false},
		{profile.Profile{Protocol: profile.VLESS, Transport: profile.Transport{Type: "kcp"}}, nil, false},
		{profile.Profile{Protocol: profile.VLESS, Transport: profile.Transport{Type: "tcp", HeaderType: "http"}}, nil, false},
		{profile.Profile{Protocol: profile.VLESS, Flow: "xtls-rprx-direct"}, nil, false},
		{profile.Profile{Protocol: profile.Hysteria2, Security: profile.Security{Kind: "tls", PinSHA256: strings.Repeat("ab", 32)}}, nil, false},
		{profile.Profile{Protocol: profile.Hysteria}, nil, false}, // bandwidth required
		{profile.Profile{Protocol: profile.Hysteria, Hysteria: &profile.HysteriaOpts{UpMbps: 1, DownMbps: 1}}, nil, true},
		{profile.Profile{Protocol: profile.VLESS, Security: profile.Security{Kind: "reality"}}, map[string]bool{TagQUIC: true}, false}, // no uTLS
		{profile.Profile{Protocol: profile.WireGuard}, official, true},
	}
	for i, c := range cases {
		if err := Supports(c.p, c.tags); (err == nil) != c.ok {
			t.Errorf("case %d (%s): %v", i, c.p.Protocol, err)
		}
	}
}

func ovpnProfile() profile.Profile {
	zero := 0
	return profile.Profile{Protocol: profile.OpenVPN, Server: "vpn.example.com", Port: 1194, Transport: profile.Transport{Type: "udp"},
		Username: "alice", Password: "pw",
		OpenVPN: &profile.OpenVPNOpts{
			CA: "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----", Cert: "CERT", Key: "KEY",
			ControlWrap: &profile.OVPNControlWrap{Type: "tls_auth", Key: "WRAPKEY", Direction: "client"},
			Cipher:      "AES-256-CBC", Auth: "SHA256", Compression: "lz4-v2", RenegSec: &zero, PingInterval: 10, PingRestart: 60,
			VerifyName: "server-cn", VerifyNameType: "name", RemoteCertTLS: "server", TLSVersionMin: "1.2", Fragment: 1300, MSSFix: 1200,
		}}
}

func TestOpenVPNEndpoint(t *testing.T) {
	got := build(t, ovpnProfile(), nil)
	want(t, "openvpn", got,
		`"endpoints":[{"type":"openvpn-client","tag":"proxy","server":"vpn.example.com","server_port":1194,"network":"udp","username":"alice","password":"pw"`,
		`"certificate":["-----BEGIN CERTIFICATE-----","CA","-----END CERTIFICATE-----"]`,
		`"client_certificate":["CERT"]`, `"client_key":["KEY"]`, `"server_name":"server-cn"`, `"server_name_type":"name"`,
		`"remote_certificate_tls":"server"`, `"version_min":"1.2"`,
		`"control_wrap":{"type":"tls_auth","key":["WRAPKEY"],"direction":"client"}`,
		`"data_ciphers":["AES-256-GCM","AES-128-GCM","CHACHA20-POLY1305","AES-256-CBC"]`, `"data_ciphers_fallback":"AES-256-CBC"`,
		`"auth":"SHA256"`, `"compression":"lz4-v2"`, `"allow_compression":"asym"`, `"renegotiate_disabled":true`,
		`"ping_interval":"10s"`, `"ping_restart":"60s"`, `"mss_fix":1200`, `"fragment":1300`)
	if strings.Contains(got, `"type":"openvpn-client","tag":"proxy","detour"`) {
		t.Error("a first hop has no detour")
	}

	// several remotes, TCP: servers list, no fragmentation
	p := ovpnProfile()
	p.Transport.Type = "tcp"
	p.OpenVPN.Remotes = []profile.OVPNRemote{{Server: "b.example.com", Port: 443, Network: "udp"}}
	p.OpenVPN.RemoteRandom = true
	got = build(t, p, nil)
	want(t, "remotes", got, `"servers":[{"server":"vpn.example.com","server_port":1194},{"server":"b.example.com","server_port":443,"network":"udp"}]`, `"remote_random":true`, `"network":"tcp"`)
	if strings.Contains(got, `"fragment"`) || strings.Contains(got, `"server":"vpn.example.com","server_port":1194,"network"`) {
		t.Errorf("fragmentation is UDP-only and servers replaces server: %s", got)
	}
	if err := Supports(ovpnProfile(), map[string]bool{TagQUIC: true}); err == nil || !strings.Contains(err.Error(), "OpenVPN") {
		t.Errorf("a build without with_openvpn must refuse OpenVPN: %v", err)
	}
	if err := Supports(ovpnProfile(), map[string]bool{TagOpenVPN: true}); err != nil {
		t.Errorf("%v", err)
	}
}

func chainHops() (ovpn, vless, wg profile.Profile) {
	vless = profile.Profile{Protocol: profile.VLESS, Server: "x.example.com", Port: 443, UUID: "id", Security: tlsSec}
	wg = profile.Profile{Protocol: profile.WireGuard, Server: "wg.org", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "PRIV", PeerPublicKey: "PUB", LocalAddress: []string{"10.7.0.2/32"}}}
	return ovpnProfile(), vless, wg
}

func TestChainUsesDetours(t *testing.T) {
	ovpn, vless, wg := chainHops()
	cfg, err := BuildConfig(profile.Segment{Hops: []profile.Profile{ovpn, vless, wg}}, models.DefaultSettings(), rsPath)
	if err != nil {
		t.Fatal(err)
	}
	// entry: OpenVPN dials directly; VLESS through it; the WireGuard exit through VLESS
	wantDetours(t, "chain", cfg,
		map[string]string{"hop-0": "", "hop-1": "hop-0", "proxy": "hop-1", "direct": ""},
		map[string]string{"hop-0": "openvpn-client", "hop-1": "vless", "proxy": "wireguard"})
	got := js(t, cfg)
	want(t, "chain", got, `"final":"proxy"`, `"address":["10.7.0.2/32"]`)
	if strings.Contains(got, `"tag":"bridge"`) {
		t.Error("no upstream, no bridge outbound")
	}
	// user inbounds and rules are on the segment that exits to the world
	want(t, "inbounds", got, `"tag":"socks-in"`, `{"action":"sniff"}`)

	// a ShadowTLS hop in the middle: its two outbounds keep the chain intact
	st := profile.Profile{Protocol: profile.ShadowTLS, Server: "st.com", Port: 443, Cipher: "2022-blake3-aes-128-gcm", Password: "inner",
		ShadowTLS: &profile.ShadowTLSOpts{Version: 3, Password: "outer", SNI: "www.example.com"}}
	cfg, err = BuildConfig(profile.Segment{Hops: []profile.Profile{vless, st, vless}}, models.DefaultSettings(), rsPath)
	if err != nil {
		t.Fatal(err)
	}
	wantDetours(t, "shadowtls in chain", cfg,
		map[string]string{"hop-0": "", "hop-1-tls": "hop-0", "hop-1": "hop-1-tls", "proxy": "hop-1"},
		map[string]string{"hop-1-tls": "shadowtls", "hop-1": "shadowsocks", "proxy": "vless"})
}

func TestBridgesJoinSegments(t *testing.T) {
	_, vless, wg := chainHops()
	up := &profile.Bridge{Port: 31001, User: "bu", Pass: "bp"}
	// last segment: dials its first hop through the previous segment's bridge
	cfg, err := BuildConfig(profile.Segment{Hops: []profile.Profile{vless, wg}, Upstream: up}, models.DefaultSettings(), rsPath)
	if err != nil {
		t.Fatal(err)
	}
	got := js(t, cfg)
	want(t, "upstream", got, `"server":"127.0.0.1","server_port":31001,"username":"bu","password":"bp","version":"5"`)
	wantDetours(t, "upstream", cfg, map[string]string{"bridge": "", "hop-0": "bridge", "proxy": "hop-0"},
		map[string]string{"bridge": "socks", "hop-0": "vless", "proxy": "wireguard"})

	// middle segment: only the bridge inbound, no user inbounds, no rules
	listen := &profile.Bridge{Port: 31002, User: "lu", Pass: "lp"}
	mid, err := BuildConfig(profile.Segment{Hops: []profile.Profile{vless}, Listen: listen}, models.DefaultSettings(), rsPath)
	if err != nil {
		t.Fatal(err)
	}
	got = js(t, mid)
	want(t, "listen", got, `"inbounds":[{"type":"socks","tag":"bridge-in","listen":"127.0.0.1","listen_port":31002,"users":[{"username":"lu","password":"lp"}]}]`, `"rules":[]`)
	if strings.Contains(got, "socks-in") || strings.Contains(got, "rule_set") {
		t.Errorf("a middle segment serves nobody but the next segment: %s", got)
	}
	// probe configs expose the bridge too, and the plain probe inbound otherwise
	pc, _ := ProbeConfig(profile.Segment{Hops: []profile.Profile{vless}, Listen: listen}, 0)
	want(t, "probe bridge", js(t, pc), `"tag":"bridge-in"`, `"listen_port":31002`)
	pc, _ = ProbeConfig(profile.Segment{Hops: []profile.Profile{vless, wg}, Upstream: up}, 4321)
	want(t, "probe last", js(t, pc), `"tag":"probe"`, `"listen_port":4321`, `"detour":"bridge"`)
	if _, err := BuildConfig(profile.Segment{}, models.DefaultSettings(), rsPath); err == nil {
		t.Error("an empty segment is refused")
	}
}

func TestMuxOnlyOnTheExitHop(t *testing.T) {
	_, vless, _ := chainHops()
	cfg, err := BuildConfig(profile.Segment{Hops: []profile.Profile{vless, vless}}, func() models.Settings {
		s := models.DefaultSettings()
		s.Mux, s.MuxConcurrency = true, 4
		return s
	}(), rsPath)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(js(t, cfg), "multiplex"); n != 1 {
		t.Fatalf("multiplex on %d outbounds, want only the exit hop", n)
	}
}

// detours returns tag -> detour for every outbound and endpoint, plus tag -> type.
func detours(t *testing.T, cfg *Config) (detour, typ map[string]string) {
	t.Helper()
	var m struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(js(t, cfg)), &m); err != nil {
		t.Fatal(err)
	}
	detour, typ = map[string]string{}, map[string]string{}
	for _, o := range append(m.Outbounds, m.Endpoints...) {
		tag, _ := o["tag"].(string)
		d, _ := o["detour"].(string)
		ty, _ := o["type"].(string)
		detour[tag], typ[tag] = d, ty
	}
	return detour, typ
}

func wantDetours(t *testing.T, name string, cfg *Config, wantDetour map[string]string, wantType map[string]string) {
	t.Helper()
	d, ty := detours(t, cfg)
	for tag, w := range wantDetour {
		if got, ok := d[tag]; !ok || got != w {
			t.Errorf("%s: %s dials through %q, want %q (all: %v)", name, tag, got, w, d)
		}
	}
	for tag, w := range wantType {
		if ty[tag] != w {
			t.Errorf("%s: %s is a %q, want %q", name, tag, ty[tag], w)
		}
	}
}
