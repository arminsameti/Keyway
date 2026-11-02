package mihomo

import (
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"keyway/internal/models"
	"keyway/internal/profile"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func tlsSec() profile.Security { return profile.Security{Kind: "tls", SNI: "a.example"} }

func realitySec() profile.Security {
	return profile.Security{Kind: "reality", SNI: "a.example", PublicKey: "pub", ShortID: "ab12", Fingerprint: "chrome"}
}

func vmess(transport string) profile.Profile {
	return profile.Profile{Protocol: profile.VMess, Server: "a.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: transport}}
}

func vless() profile.Profile {
	return profile.Profile{Protocol: profile.VLESS, Server: "b.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"}, Security: tlsSec()}
}

func trojan() profile.Profile {
	return profile.Profile{Protocol: profile.Trojan, Server: "c.example", Port: 443, Password: "pw",
		Transport: profile.Transport{Type: "tcp"}, Security: tlsSec()}
}

func with(p profile.Profile, f func(*profile.Profile)) profile.Profile {
	f(&p)
	return p
}

func TestSupportsAllowed(t *testing.T) {
	cases := map[string]profile.Profile{
		"vmess tcp":     vmess("tcp"),
		"vmess ws tls":  with(vmess("ws"), func(p *profile.Profile) { p.Security = tlsSec() }),
		"vmess grpc":    with(vmess("grpc"), func(p *profile.Profile) { p.Security = tlsSec() }),
		"vmess h2":      with(vmess("h2"), func(p *profile.Profile) { p.Security = tlsSec() }),
		"vmess upgrade": with(vmess("httpupgrade"), func(p *profile.Profile) { p.Security = tlsSec() }),
		"vless tls":     vless(),
		"vless reality": with(vless(), func(p *profile.Profile) { p.Security = realitySec() }),
		"vless vision": with(vless(), func(p *profile.Profile) {
			p.Security = realitySec()
			p.Flow = "xtls-rprx-vision"
		}),
		"vless ws":         with(vless(), func(p *profile.Profile) { p.Transport.Type = "ws" }),
		"vless fp":         with(vless(), func(p *profile.Profile) { p.Security.Fingerprint = "chrome" }),
		"vless pinned":     with(vless(), func(p *profile.Profile) { p.Security.PinSHA256 = strings.Repeat("ab", 32) }),
		"vless insecure":   with(vless(), func(p *profile.Profile) { p.Security.Insecure = true }),
		"trojan":           trojan(),
		"trojan ws":        with(trojan(), func(p *profile.Profile) { p.Transport.Type = "ws" }),
		"shadowsocks":      {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "aes-128-gcm", Password: "p"},
		"shadowsocks 2022": {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "2022-blake3-aes-128-gcm", Password: "p"},
		"socks":            {Protocol: profile.SOCKS, Server: "a.example", Port: 1080},
		"http":             {Protocol: profile.HTTP, Server: "a.example", Port: 8080},
		"hysteria2":        {Protocol: profile.Hysteria2, Server: "a.example", Port: 443, Password: "p"},
		"hysteria2 obfs": {Protocol: profile.Hysteria2, Server: "a.example", Port: 443, Password: "p",
			Hysteria: &profile.HysteriaOpts{Obfs: "salamander", ObfsPassword: "o", UpMbps: 20, DownMbps: 50}},
		"tuic":     {Protocol: profile.TUIC, Server: "a.example", Port: 443, UUID: testUUID, Password: "p"},
		"anytls":   {Protocol: profile.AnyTLS, Server: "a.example", Port: 443, Password: "p", Security: tlsSec()},
		"wg":       wireguard(),
		"empty tp": with(vmess(""), func(p *profile.Profile) {}),
	}
	for name, p := range cases {
		if err := Supports(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func wireguard() profile.Profile {
	return profile.Profile{Protocol: profile.WireGuard, Server: "a.example", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "k", PeerPublicKey: "p", LocalAddress: []string{"10.7.0.2/32"}}}
}

func TestSupportsRejected(t *testing.T) {
	cases := map[string]profile.Profile{
		"vless encryption": with(vless(), func(p *profile.Profile) { p.Encryption = "mlkem768x25519plus" }),
		"vless other flow": with(vless(), func(p *profile.Profile) { p.Flow = "xtls-rprx-vision-udp443" }),
		"trojan no tls":    with(trojan(), func(p *profile.Profile) { p.Security = profile.Security{Kind: "none"} }),
		"reality on vmess": with(vmess("tcp"), func(p *profile.Profile) { p.Security = realitySec() }),
		"reality spiderx":  with(vless(), func(p *profile.Profile) { p.Security = realitySec(); p.Security.SpiderX = "/x" }),
		"kcp":              vmess("kcp"),
		"quic transport":   vmess("quic"),
		"tcp http header":  with(vmess("tcp"), func(p *profile.Profile) { p.Transport.HeaderType = "http" }),
		"grpc multi":       with(vmess("grpc"), func(p *profile.Profile) { p.Transport.Mode = "multi" }),
		"grpc authority":   with(vmess("grpc"), func(p *profile.Profile) { p.Transport.Authority = "x" }),
		"ws early data":    with(vmess("ws"), func(p *profile.Profile) { p.Transport.Path = "/w?ed=2048" }),
		"ss cfb":           {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "aes-128-cfb", Password: "p"},
		"ss xchacha":       {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "xchacha20-ietf-poly1305", Password: "p"},
		"ss over ws":       with(profile.Profile{Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "aes-128-gcm", Password: "p"}, func(p *profile.Profile) { p.Transport.Type = "ws" }),
		"socks over ws":    with(profile.Profile{Protocol: profile.SOCKS, Server: "a.example", Port: 1080}, func(p *profile.Profile) { p.Transport.Type = "ws" }),
		"hysteria v1":      {Protocol: profile.Hysteria, Server: "a.example", Port: 443, Password: "p", Hysteria: &profile.HysteriaOpts{UpMbps: 1, DownMbps: 1}},
		"hysteria2 fp":     {Protocol: profile.Hysteria2, Server: "a.example", Port: 443, Password: "p", Security: profile.Security{Kind: "tls", Fingerprint: "chrome"}},
		"naive":            {Protocol: profile.Naive, Server: "a.example", Port: 443},
		"ssh":              {Protocol: profile.SSH, Server: "a.example", Port: 22},
		"openvpn":          {Protocol: profile.OpenVPN, Server: "a.example", Port: 1194},
		"shadowtls":        {Protocol: profile.ShadowTLS, Server: "a.example", Port: 443},
		"tor":              {Protocol: profile.Tor},
		"custom":           {Protocol: profile.Custom, Custom: &profile.CustomOpts{Engine: "xray", Config: "{}"}},
		"fragment":         with(vless(), func(p *profile.Profile) { p.Overrides = &profile.Overrides{Fragment: &profile.Fragment{}} }),
		// the reserved bytes are for Cloudflare WARP, which no test server here can check
		"wg reserved":    with(wireguard(), func(p *profile.Profile) { p.WireGuard.Reserved = []int{1, 2, 3} }),
		"wg reserved>3":  with(wireguard(), func(p *profile.Profile) { p.WireGuard.Reserved = []int{1, 2, 3, 4} }),
		"wg no v4 or v6": with(wireguard(), func(p *profile.Profile) { p.WireGuard.LocalAddress = []string{"garbage"} }),
	}
	for name, p := range cases {
		if err := Supports(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestSupportsSegmentChainsTCPHopsOnly(t *testing.T) {
	udp := []profile.Profile{{Protocol: profile.Hysteria2, Server: "h.example", Port: 443, Password: "p"}}
	if err := SupportsSegment(udp, false); err != nil {
		t.Fatalf("single hysteria2: %v", err)
	}
	if err := SupportsSegment([]profile.Profile{vmess("tcp"), udp[0]}, false); err == nil {
		t.Error("hysteria2 behind another hop: want an error")
	}
	if err := SupportsSegment(udp, true); err == nil {
		t.Error("hysteria2 behind a bridge: want an error")
	}
	// AnyTLS runs over TCP, but a chain through it was not run against a real server
	anytls := profile.Profile{Protocol: profile.AnyTLS, Server: "t.example", Port: 443, Password: "p", Security: tlsSec()}
	if err := SupportsSegment([]profile.Profile{vmess("tcp"), anytls}, false); err == nil {
		t.Error("anytls in a chain: want an error")
	}
	if err := SupportsSegment([]profile.Profile{anytls}, false); err != nil {
		t.Errorf("single anytls: %v", err)
	}
	if err := SupportsSegment([]profile.Profile{vmess("tcp"), vless()}, true); err != nil {
		t.Errorf("tcp chain behind a bridge: %v", err)
	}
}

// ---- config building ----

func parse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, b)
	}
	return doc
}

func list(t *testing.T, doc map[string]any, key string) []map[string]any {
	t.Helper()
	raw, _ := doc[key].([]any)
	var out []map[string]any
	for _, e := range raw {
		m, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("%s entry %v is not a map", key, e)
		}
		out = append(out, m)
	}
	return out
}

func proxyNamed(t *testing.T, doc map[string]any, name string) map[string]any {
	t.Helper()
	for _, p := range list(t, doc, "proxies") {
		if p["name"] == name {
			return p
		}
	}
	t.Fatalf("no proxy %q in %v", name, doc["proxies"])
	return nil
}

func rules(t *testing.T, doc map[string]any) []string {
	t.Helper()
	var out []string
	for _, r := range doc["rules"].([]any) {
		out = append(out, r.(string))
	}
	return out
}

func build(t *testing.T, seg profile.Segment, s models.Settings) map[string]any {
	t.Helper()
	b, err := BuildConfig(seg, s)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, b)
}

func settings() models.Settings {
	s := models.DefaultSettings()
	s.Inbounds = []models.Inbound{
		{Tag: "socks-in", Protocol: "socks", Port: 10808, Listen: "127.0.0.1", UDP: true, Enabled: true},
		{Tag: "http-in", Protocol: "http", Port: 10809, Listen: "127.0.0.1", Enabled: true},
	}
	return s
}

func TestSingleHopVMessWebSocket(t *testing.T) {
	p := with(vmess("ws"), func(p *profile.Profile) {
		p.Security = tlsSec()
		p.Cipher = "auto"
		p.Transport.Path, p.Transport.Host = "/ray", "cdn.example"
		p.Security.ALPN = []string{"http/1.1"}
	})
	doc := build(t, profile.Single(p), settings())
	px := proxyNamed(t, doc, "proxy")
	want := map[string]any{"type": "vmess", "server": "a.example", "port": 443, "uuid": testUUID, "alterId": 0, "cipher": "auto",
		"network": "ws", "tls": true, "servername": "a.example", "udp": true}
	for k, v := range want {
		if !reflect.DeepEqual(px[k], v) {
			t.Errorf("%s = %#v, want %#v", k, px[k], v)
		}
	}
	ws := px["ws-opts"].(map[string]any)
	if ws["path"] != "/ray" || ws["headers"].(map[string]any)["Host"] != "cdn.example" {
		t.Errorf("ws-opts = %v", ws)
	}
	if _, has := px["dialer-proxy"]; has {
		t.Error("a single hop must not have a dialer-proxy")
	}
	if !reflect.DeepEqual(px["alpn"], []any{"http/1.1"}) {
		t.Errorf("alpn = %v", px["alpn"])
	}
}

func TestVLESSRealityVision(t *testing.T) {
	p := with(vless(), func(p *profile.Profile) { p.Security = realitySec(); p.Flow = "xtls-rprx-vision" })
	px := proxyNamed(t, build(t, profile.Single(p), settings()), "proxy")
	if px["type"] != "vless" || px["flow"] != "xtls-rprx-vision" || px["tls"] != true || px["client-fingerprint"] != "chrome" || px["servername"] != "a.example" {
		t.Errorf("proxy = %v", px)
	}
	ro := px["reality-opts"].(map[string]any)
	// Without this Mihomo strips the post-quantum key share, which current Xray servers (26.10) reject
	// and older ones (25.1, 26.3) accept either way: see integration_test.go
	if ro["public-key"] != "pub" || ro["short-id"] != "ab12" || ro["support-x25519mlkem768"] != true {
		t.Errorf("reality-opts = %v", ro)
	}
}

func TestRealityWithoutFingerprintUsesChrome(t *testing.T) {
	p := with(vless(), func(p *profile.Profile) { p.Security = realitySec(); p.Security.Fingerprint = "" })
	px := proxyNamed(t, build(t, profile.Single(p), settings()), "proxy")
	if px["client-fingerprint"] != "chrome" {
		t.Errorf("client-fingerprint = %v", px["client-fingerprint"])
	}
}

func TestTLSPinAndInsecure(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	px := proxyNamed(t, build(t, profile.Single(with(vless(), func(p *profile.Profile) { p.Security.PinSHA256 = pin })), settings()), "proxy")
	if px["fingerprint"] != pin {
		t.Errorf("fingerprint = %v", px["fingerprint"])
	}
	px = proxyNamed(t, build(t, profile.Single(with(vless(), func(p *profile.Profile) { p.Security.Insecure = true })), settings()), "proxy")
	if px["skip-cert-verify"] != true {
		t.Errorf("skip-cert-verify = %v", px["skip-cert-verify"])
	}
	// colons in the pin are only formatting
	px = proxyNamed(t, build(t, profile.Single(with(vless(), func(p *profile.Profile) {
		p.Security.PinSHA256 = strings.Repeat("AB:", 31) + "AB"
	})), settings()), "proxy")
	if px["fingerprint"] != pin {
		t.Errorf("fingerprint = %v", px["fingerprint"])
	}
}

func TestChainUsesDialerProxy(t *testing.T) {
	seg := profile.Segment{Hops: []profile.Profile{vmess("tcp"), vless(), trojan()}}
	doc := build(t, seg, settings())
	if _, has := proxyNamed(t, doc, "hop-0")["dialer-proxy"]; has {
		t.Error("the entry hop dials directly")
	}
	if got := proxyNamed(t, doc, "hop-1")["dialer-proxy"]; got != "hop-0" {
		t.Errorf("hop-1 dialer-proxy = %v", got)
	}
	if got := proxyNamed(t, doc, "proxy")["dialer-proxy"]; got != "hop-1" {
		t.Errorf("exit dialer-proxy = %v", got)
	}
	if got := proxyNamed(t, doc, "proxy")["type"]; got != "trojan" {
		t.Errorf("the exit is %v", got)
	}
}

func TestUpstreamBridgeIsTheFirstDialer(t *testing.T) {
	seg := profile.Segment{Hops: []profile.Profile{vless()}, Upstream: &profile.Bridge{Port: 4001, User: "u1", Pass: "p1"}}
	doc := build(t, seg, settings())
	br := proxyNamed(t, doc, "bridge")
	if br["type"] != "socks5" || br["server"] != "127.0.0.1" || br["port"] != 4001 || br["username"] != "u1" || br["password"] != "p1" {
		t.Errorf("bridge = %v", br)
	}
	if got := proxyNamed(t, doc, "proxy")["dialer-proxy"]; got != "bridge" {
		t.Errorf("dialer-proxy = %v", got)
	}
}

func TestMiddleSegmentOnlyExposesItsBridge(t *testing.T) {
	seg := profile.Segment{Hops: []profile.Profile{vless()}, Listen: &profile.Bridge{Port: 4002, User: "u2", Pass: "p2"}}
	doc := build(t, seg, settings())
	ls := list(t, doc, "listeners")
	if len(ls) != 1 {
		t.Fatalf("listeners = %v", ls)
	}
	l := ls[0]
	if l["type"] != "socks" || l["listen"] != "127.0.0.1" || l["port"] != 4002 {
		t.Errorf("listener = %v", l)
	}
	users := l["users"].([]any)[0].(map[string]any)
	if users["username"] != "u2" || users["password"] != "p2" {
		t.Errorf("users = %v", users)
	}
	if got := rules(t, doc); !reflect.DeepEqual(got, []string{"MATCH,proxy"}) {
		t.Errorf("rules = %v", got)
	}
	if _, has := doc["external-controller"]; has {
		t.Error("a middle segment must not open a controller")
	}
}

func TestInboundsBecomeListeners(t *testing.T) {
	s := settings()
	s.Inbounds = []models.Inbound{
		{Tag: "socks-in", Protocol: "socks", Port: 10808, Listen: "127.0.0.1", UDP: true, Enabled: true, Username: "me", Password: "pw"},
		{Tag: "http-in", Protocol: "http", Port: 10809, Listen: "127.0.0.1", Enabled: true},
		{Tag: "off", Protocol: "socks", Port: 10810, Listen: "127.0.0.1", Enabled: false},
	}
	ls := list(t, build(t, profile.Single(vless()), s), "listeners")
	if len(ls) != 2 {
		t.Fatalf("listeners = %v", ls)
	}
	if ls[0]["type"] != "socks" || ls[0]["name"] != "socks-in" || ls[0]["port"] != 10808 || ls[0]["udp"] != true || ls[0]["listen"] != "127.0.0.1" {
		t.Errorf("socks listener = %v", ls[0])
	}
	if u := ls[0]["users"].([]any)[0].(map[string]any); u["username"] != "me" || u["password"] != "pw" {
		t.Errorf("users = %v", u)
	}
	if ls[1]["type"] != "http" || ls[1]["port"] != 10809 {
		t.Errorf("http listener = %v", ls[1])
	}
	if _, has := ls[1]["users"]; has {
		t.Error("an open inbound must not have users")
	}
}

func TestAllowLANBindsEverywhere(t *testing.T) {
	s := settings()
	s.AllowLAN = true
	s.Inbounds[0].Username, s.Inbounds[0].Password = "me", "pw"
	s.Inbounds[1].Username, s.Inbounds[1].Password = "me", "pw"
	for _, l := range list(t, build(t, profile.Single(vless()), s), "listeners") {
		if l["listen"] != "0.0.0.0" {
			t.Errorf("listen = %v", l["listen"])
		}
	}
}

func TestGeoDownloadsAreDisabled(t *testing.T) {
	doc := build(t, profile.Single(vless()), settings())
	if doc["geo-auto-update"] != false {
		t.Errorf("geo-auto-update = %v", doc["geo-auto-update"])
	}
	urls := doc["geox-url"].(map[string]any)
	for _, k := range []string{"geoip", "mmdb", "geosite", "asn"} {
		u, _ := urls[k].(string)
		if !strings.HasPrefix(u, "http://127.0.0.1:1/") {
			t.Errorf("geox-url.%s = %q: Mihomo could download it itself", k, u)
		}
	}
}

func TestDefaultRoutingRules(t *testing.T) {
	got := rules(t, build(t, profile.Single(vless()), settings()))
	want := []string{
		"GEOSITE,category-ads-all,REJECT",
		// geoip:private is spelled out: Mihomo's own GEOIP,private is not a list
		"IP-CIDR,0.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR6,::1/128,DIRECT,no-resolve",
		"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
		"IP-CIDR6,fe80::/10,DIRECT,no-resolve",
		"GEOSITE,private,DIRECT",
		"GEOSITE,cn,DIRECT",
	}
	if !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf("rules =\n%s", strings.Join(got, "\n"))
	}
	// Xray's IPIfNonMatch: domains that matched nothing are resolved and the IP
	// rules are tried again, after the domain rules.
	second := got[len(want) : len(got)-1]
	if len(second) != 10 || second[0] != "IP-CIDR,0.0.0.0/8,DIRECT" || second[len(second)-1] != "IP-CIDR6,fe80::/10,DIRECT" {
		t.Fatalf("second pass = %v", second)
	}
	if last := got[len(got)-1]; last != "MATCH,proxy" {
		t.Fatalf("last rule = %q", last)
	}
}

func TestGlobalModeOnlyBlocksAds(t *testing.T) {
	s := settings()
	s.RoutingMode = "global"
	got := rules(t, build(t, profile.Single(vless()), s))
	if !reflect.DeepEqual(got, []string{"GEOSITE,category-ads-all,REJECT", "MATCH,proxy"}) {
		t.Fatalf("rules = %v", got)
	}
	s.BlockAds = false
	got = rules(t, build(t, profile.Single(vless()), s))
	if !reflect.DeepEqual(got, []string{"MATCH,proxy"}) {
		t.Fatalf("rules = %v", got)
	}
}

func TestCustomModeRules(t *testing.T) {
	s := settings()
	s.RoutingMode, s.BlockAds = "custom", false
	s.BlockedSites = "domain:ads.example, full:x.ads.example"
	s.ProxySites = "keyword:openai"
	s.DirectSites = "geosite:cn\n1.2.3.4, 2001:db8::/32"
	got := rules(t, build(t, profile.Single(vless()), s))
	want := []string{
		"DOMAIN-SUFFIX,ads.example,REJECT",
		"DOMAIN,x.ads.example,REJECT",
		"DOMAIN-KEYWORD,openai,proxy",
		"GEOSITE,cn,DIRECT",
		"IP-CIDR,1.2.3.4/32,DIRECT,no-resolve",
		"IP-CIDR6,2001:db8::/32,DIRECT,no-resolve",
		"IP-CIDR,1.2.3.4/32,DIRECT",
		"IP-CIDR6,2001:db8::/32,DIRECT",
		"MATCH,proxy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules =\n%s", strings.Join(got, "\n"))
	}
}

func ruleSet(entries ...string) models.Settings {
	s := settings()
	s.RoutingMode, s.BlockAds = "rules", false
	s.RuleSets = []models.RuleSet{{ID: "a", Name: "a", Rules: []models.RouteRule{{ID: "r", Enabled: true, Entries: entries, Outbound: "direct"}}}}
	s.ActiveRuleSet = "a"
	return s
}

func TestRuleSetEntries(t *testing.T) {
	s := ruleSet("domain:a.example", "regexp:^ad[0-9]+\\.", "geoip:cn", "port:80,443,8000-9000", "bareword", "10.1.0.0/16")
	got := rules(t, build(t, profile.Single(vless()), s))
	want := []string{
		"DOMAIN-SUFFIX,a.example,DIRECT",
		"DOMAIN-REGEX,^ad[0-9]+\\.,DIRECT",
		"GEOIP,cn,DIRECT,no-resolve",
		"DST-PORT,80/443/8000-9000,DIRECT",
		"DOMAIN-KEYWORD,bareword,DIRECT",
		"IP-CIDR,10.1.0.0/16,DIRECT,no-resolve",
		"GEOIP,cn,DIRECT",
		"IP-CIDR,10.1.0.0/16,DIRECT",
		"MATCH,proxy",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules =\n%s", strings.Join(got, "\n"))
	}
}

func TestRuleSetBlockAndProxyTargets(t *testing.T) {
	s := ruleSet("domain:a.example")
	s.RuleSets[0].Rules = append(s.RuleSets[0].Rules,
		models.RouteRule{ID: "b", Enabled: true, Entries: []string{"domain:b.example"}, Outbound: "block"},
		models.RouteRule{ID: "c", Enabled: true, Entries: []string{"domain:c.example"}, Outbound: "proxy"})
	got := rules(t, build(t, profile.Single(vless()), s))
	want := []string{"DOMAIN-SUFFIX,a.example,DIRECT", "DOMAIN-SUFFIX,b.example,REJECT", "DOMAIN-SUFFIX,c.example,proxy", "MATCH,proxy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rules = %v", got)
	}
}

func TestRuleEntriesMihomoCannotHonourAreRefused(t *testing.T) {
	for name, entry := range map[string]string{
		"process":      "process:Telegram",
		"process path": "process-path:/Applications/X.app/Contents/MacOS/X",
		"app":          "app:/Applications/Telegram.app",
		"ext":          "ext:file.dat:tag",
		"comma regexp": "regexp:^a{1,3}\\.",
	} {
		if _, err := BuildConfig(profile.Single(vless()), ruleSet(entry)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestGeoDataNeeded(t *testing.T) {
	// default: geosite:cn, geosite:private and the ad list; geoip:private is spelled out
	if got := GeoData(settings()); !reflect.DeepEqual(got, []string{"GeoSite.dat"}) {
		t.Errorf("default = %v", got)
	}
	if got := GeoData(ruleSet("geoip:cn")); !reflect.DeepEqual(got, []string{"geoip.metadb"}) {
		t.Errorf("geoip:cn = %v", got)
	}
	if got := GeoData(ruleSet("geoip:cn", "geosite:google")); !reflect.DeepEqual(got, []string{"GeoSite.dat", "geoip.metadb"}) {
		t.Errorf("both = %v", got)
	}
	s := settings()
	s.RoutingMode, s.BlockAds = "global", false
	if got := GeoData(s); len(got) != 0 {
		t.Errorf("global = %v", got)
	}
}

func TestStatsController(t *testing.T) {
	seg := profile.Single(vless())
	seg.Stats = &profile.StatsAPI{Port: 9099, Secret: "s3cret"}
	doc := build(t, seg, settings())
	if doc["external-controller"] != "127.0.0.1:9099" || doc["secret"] != "s3cret" {
		t.Errorf("controller = %v secret = %v", doc["external-controller"], doc["secret"])
	}
	if _, has := build(t, profile.Single(vless()), settings())["external-controller"]; has {
		t.Error("no controller without stats")
	}
}

func TestStatsWithoutASecretIsRefused(t *testing.T) {
	seg := profile.Single(vless())
	seg.Stats = &profile.StatsAPI{Port: 9099}
	if _, err := BuildConfig(seg, settings()); err == nil {
		t.Error("an unauthenticated controller was built")
	}
}

func TestTUNIsRefused(t *testing.T) {
	seg := profile.Single(vless())
	seg.TUN = &profile.TUNOptions{Stack: "mixed", MTU: 9000}
	if _, err := BuildConfig(seg, settings()); err == nil {
		t.Error("TUN on Mihomo was built")
	}
}

func TestMuxBecomesSMux(t *testing.T) {
	s := settings()
	s.Mux, s.MuxConcurrency = true, 4
	px := proxyNamed(t, build(t, profile.Single(vmess("tcp")), s), "proxy")
	sm, _ := px["smux"].(map[string]any)
	if sm["enabled"] != true || sm["max-streams"] != 4 || sm["protocol"] != "h2mux" {
		t.Errorf("smux = %v", px["smux"])
	}
	// per-server override turns it off again
	off := false
	p := vmess("tcp")
	p.Overrides = &profile.Overrides{Mux: &off}
	if _, has := proxyNamed(t, build(t, profile.Single(p), s), "proxy")["smux"]; has {
		t.Error("smux despite the server's override")
	}
	// protocols without multiplexing are left alone, as on the other engines
	if _, has := proxyNamed(t, build(t, profile.Single(profile.Profile{Protocol: profile.SOCKS, Server: "s.example", Port: 1080}), s), "proxy")["smux"]; has {
		t.Error("smux on SOCKS")
	}
}

func TestDNSServers(t *testing.T) {
	s := settings()
	s.DNS = []string{"1.1.1.1", "https://dns.google/dns-query", "localhost", "tls://9.9.9.9"}
	d := build(t, profile.Single(vless()), s)["dns"].(map[string]any)
	if d["enable"] != true {
		t.Errorf("dns = %v", d)
	}
	if !reflect.DeepEqual(d["nameserver"], []any{"1.1.1.1", "https://dns.google/dns-query", "system", "tls://9.9.9.9"}) {
		t.Errorf("nameserver = %v", d["nameserver"])
	}
	if !reflect.DeepEqual(d["default-nameserver"], []any{"1.1.1.1"}) {
		t.Errorf("default-nameserver = %v", d["default-nameserver"])
	}
	s.DNS = []string{"quic://x.example"}
	if _, err := BuildConfig(profile.Single(vless()), s); err == nil {
		t.Error("an unknown DNS scheme was passed on")
	}
}

func TestDNSModes(t *testing.T) {
	s := settings()
	s.DNSMode = models.DNSModeSystem
	d := build(t, profile.Single(vless()), s)["dns"].(map[string]any)
	if !reflect.DeepEqual(d["nameserver"], []any{"system"}) {
		t.Errorf("system mode: nameserver = %v", d["nameserver"])
	}
	s.DNSMode = models.DNSModeSecure
	d = build(t, profile.Single(vless()), s)["dns"].(map[string]any)
	if !reflect.DeepEqual(d["nameserver"], []any{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}) {
		t.Errorf("secure mode: nameserver = %v", d["nameserver"])
	}
	s.DNSMode, s.DNS = models.DNSModeCustom, []string{"9.9.9.9"}
	d = build(t, profile.Single(vless()), s)["dns"].(map[string]any)
	if !reflect.DeepEqual(d["nameserver"], []any{"9.9.9.9"}) {
		t.Errorf("custom mode: nameserver = %v", d["nameserver"])
	}
	s.DNSDirect = "223.5.5.5"
	if _, err := BuildConfig(profile.Single(vless()), s); err == nil || !strings.Contains(err.Error(), "direct DNS") {
		t.Errorf("a direct resolver was dropped silently: %v", err)
	}
}

func TestSniffing(t *testing.T) {
	s := settings()
	if sn, _ := build(t, profile.Single(vless()), s)["sniffer"].(map[string]any); sn["enable"] != true {
		t.Errorf("sniffer = %v", sn)
	}
	s.Sniffing = false
	if sn, has := build(t, profile.Single(vless()), s)["sniffer"].(map[string]any); has && sn["enable"] == true {
		t.Errorf("sniffer = %v", sn)
	}
}

func TestProbeConfig(t *testing.T) {
	b, err := ProbeConfig(profile.Single(vless()), 7777)
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(t, b)
	ls := list(t, doc, "listeners")
	if len(ls) != 1 || ls[0]["port"] != 7777 || ls[0]["listen"] != "127.0.0.1" {
		t.Fatalf("listeners = %v", ls)
	}
	if got := rules(t, doc); !reflect.DeepEqual(got, []string{"MATCH,proxy"}) {
		t.Errorf("rules = %v", got)
	}
	if doc["log-level"] != "silent" {
		t.Errorf("log-level = %v", doc["log-level"])
	}
}

func TestBuildRefusesWhatSupportsRefuses(t *testing.T) {
	if _, err := BuildConfig(profile.Single(with(vless(), func(p *profile.Profile) { p.Flow = "other" })), settings()); err == nil {
		t.Error("BuildConfig ran an unsupported server")
	}
	if _, err := ProbeConfig(profile.Single(with(vless(), func(p *profile.Profile) { p.Flow = "other" })), 1); err == nil {
		t.Error("ProbeConfig ran an unsupported server")
	}
}

// Mihomo ignores keys it does not know, so a misspelt one would silently turn a
// setting off. Every key the builder can emit is listed here, checked by hand
// against the field tags of Mihomo v1.19.33 (adapter/outbound, listener/inbound,
// config/config.go).
var knownTop = set("mode", "log-level", "ipv6", "find-process-mode", "geodata-mode", "geo-auto-update", "geox-url",
	"external-controller", "secret", "dns", "sniffer", "listeners", "proxies", "rules", "allow-lan", "profile")
var knownProxy = set("name", "type", "server", "port", "uuid", "alterId", "cipher", "password", "username", "flow", "udp", "network",
	"tls", "servername", "sni", "alpn", "skip-cert-verify", "fingerprint", "client-fingerprint", "reality-opts", "ws-opts", "grpc-opts",
	"h2-opts", "xhttp-opts", "smux", "dialer-proxy", "encryption", "up", "down", "obfs", "obfs-password", "congestion-controller",
	"udp-relay-mode", "reduce-rtt", "idle-session-timeout", "ip", "ipv6", "private-key", "public-key", "pre-shared-key", "allowed-ips",
	"mtu", "persistent-keepalive")

func set(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func TestOnlyKnownKeysAreEmitted(t *testing.T) {
	all := []profile.Profile{vmess("ws"), vless(), with(vless(), func(p *profile.Profile) { p.Security = realitySec(); p.Flow = "xtls-rprx-vision" }),
		trojan(), {Protocol: profile.Shadowsocks, Server: "s.example", Port: 1, Cipher: "aes-128-gcm", Password: "p"},
		{Protocol: profile.SOCKS, Server: "s.example", Port: 1, Username: "u", Password: "p"},
		{Protocol: profile.HTTP, Server: "s.example", Port: 1},
		{Protocol: profile.Hysteria2, Server: "s.example", Port: 1, Password: "p", Hysteria: &profile.HysteriaOpts{Obfs: "salamander", ObfsPassword: "o", UpMbps: 1, DownMbps: 1}},
		{Protocol: profile.TUIC, Server: "s.example", Port: 1, UUID: testUUID, Password: "p", TUIC: &profile.TUICOpts{CongestionControl: "bbr", UDPRelayMode: "native", ZeroRTT: true}},
		{Protocol: profile.AnyTLS, Server: "s.example", Port: 1, Password: "p", Security: tlsSec(), AnyTLS: &profile.AnyTLSOpts{IdleTimeoutSec: 30}},
		wireguard(),
		with(vmess("grpc"), func(p *profile.Profile) { p.Security = tlsSec(); p.Transport.ServiceName = "svc" }),
		with(vmess("h2"), func(p *profile.Profile) {
			p.Security = tlsSec()
			p.Transport.Host = "h.example"
			p.Transport.Path = "/h"
		}),
	}
	s := settings()
	s.Mux = true
	s.Inbounds[0].Username, s.Inbounds[0].Password = "u", "p"
	for _, p := range all {
		seg := profile.Segment{Hops: []profile.Profile{p}, Stats: &profile.StatsAPI{Port: 2, Secret: "s"}}
		if tcpHop(p) {
			seg.Upstream = &profile.Bridge{Port: 1, User: "u", Pass: "p"}
		}
		doc := build(t, seg, s)
		for k := range doc {
			if !knownTop[k] {
				t.Errorf("%s: unknown top-level key %q", p.Protocol, k)
			}
		}
		for _, px := range list(t, doc, "proxies") {
			for k := range px {
				if !knownProxy[k] {
					t.Errorf("%s: unknown proxy key %q", p.Protocol, k)
				}
			}
		}
	}
}
