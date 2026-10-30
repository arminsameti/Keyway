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
	cfg, err := BuildConfig(p, s, rsPath)
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
		cfg, err := ProbeConfig(c.p, 4321)
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
	want(t, "shadowtls", got, `{"type":"shadowsocks","tag":"proxy","detour":"shadowtls-out","method":"2022-blake3-aes-128-gcm","password":"inner"}`,
		`"type":"shadowtls","tag":"shadowtls-out","server":"st.com","server_port":443`, `"version":3`, `"server_name":"www.example.com"`)

	wg := profile.Profile{Protocol: profile.WireGuard, Server: "wg.org", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "PRIV", PeerPublicKey: "PUB", LocalAddress: []string{"10.7.0.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}, Keepalive: 25}}
	got = build(t, wg, nil)
	want(t, "wireguard", got, `"endpoints":[{"type":"wireguard","tag":"proxy","address":["10.7.0.2/32"],"private_key":"PRIV","mtu":1420`,
		`"peers":[{"address":"wg.org","port":51820,"public_key":"PUB","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":"25s","reserved":[1,2,3]}]`)
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
	if _, err := BuildConfig(vless, func() models.Settings { s := models.DefaultSettings(); s.DirectSites = "ext:my.dat:x"; return s }(), rsPath); err == nil {
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
