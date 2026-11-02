package v2ray

import (
	"encoding/json"
	"strings"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func tlsSec() profile.Security { return profile.Security{Kind: "tls", SNI: "a.example"} }

func vmess(transport string) profile.Profile {
	return profile.Profile{Protocol: profile.VMess, Server: "a.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: transport}}
}

func vless() profile.Profile {
	return profile.Profile{Protocol: profile.VLESS, Server: "a.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"}, Security: tlsSec()}
}

func with(p profile.Profile, f func(*profile.Profile)) profile.Profile {
	f(&p)
	return p
}

func TestSupportsAllowed(t *testing.T) {
	cases := map[string]profile.Profile{
		"vmess tcp":      vmess("tcp"),
		"vmess ws":       vmess("ws"),
		"vmess grpc":     vmess("grpc"),
		"vmess h2":       with(vmess("h2"), func(p *profile.Profile) { p.Security = tlsSec() }),
		"vmess kcp":      vmess("kcp"),
		"kcp srtp":       with(vmess("kcp"), func(p *profile.Profile) { p.Transport.HeaderType = "srtp" }),
		"ws plain query": with(vmess("ws"), func(p *profile.Profile) { p.Transport.Path = "/w?a=1" }),
		"vless tls":      vless(),
		"trojan tls":     {Protocol: profile.Trojan, Server: "a.example", Port: 443, Password: "p", Transport: profile.Transport{Type: "tcp"}, Security: tlsSec()},
		"shadowsocks":    {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "aes-128-gcm", Password: "p"},
		"socks":          {Protocol: profile.SOCKS, Server: "a.example", Port: 1080},
		"http":           {Protocol: profile.HTTP, Server: "a.example", Port: 8080},
	}
	for name, p := range cases {
		if err := Supports(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSupportsRejected(t *testing.T) {
	cases := map[string]profile.Profile{
		"reality": with(vless(), func(p *profile.Profile) {
			p.Security = profile.Security{Kind: "reality", SNI: "a.example", PublicKey: "x"}
		}),
		"vision":               with(vless(), func(p *profile.Profile) { p.Flow = "xtls-rprx-vision" }),
		"vless no tls":         with(vless(), func(p *profile.Profile) { p.Server = "10.0.0.1"; p.Security = profile.Security{Kind: "none"} }),
		"vless encryption":     with(vless(), func(p *profile.Profile) { p.Encryption = "mlkem768x25519plus" }),
		"xhttp":                vmess("xhttp"),
		"httpupgrade":          vmess("httpupgrade"),
		"ss 2022":              {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "2022-blake3-aes-128-gcm", Password: "p"},
		"ss 2022 uppercase":    {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "2022-BLAKE3-AES-128-GCM", Password: "p"},
		"wireguard":            {Protocol: profile.WireGuard, Server: "a.example", Port: 51820},
		"hysteria2":            {Protocol: profile.Hysteria2, Server: "a.example", Port: 443, Password: "p"},
		"tuic":                 {Protocol: profile.TUIC, Server: "a.example", Port: 443},
		"custom":               {Protocol: profile.Custom, Custom: &profile.CustomOpts{Engine: "xray", Config: "{}"}},
		"tor":                  {Protocol: profile.Tor},
		"pinned":               with(vless(), func(p *profile.Profile) { p.Security.PinSHA256 = "ab" }),
		"insecure":             with(vless(), func(p *profile.Profile) { p.Security.Insecure = true }),
		"insecure pinned":      with(vless(), func(p *profile.Profile) { p.Security.Insecure = true; p.Security.PinSHA256 = "ab" }),
		"grpc authority":       with(vmess("grpc"), func(p *profile.Profile) { p.Transport.Authority = "x" }),
		"fragment override":    with(vless(), func(p *profile.Profile) { p.Overrides = &profile.Overrides{Fragment: &profile.Fragment{}} }),
		"grpc multi":           with(vmess("grpc"), func(p *profile.Profile) { p.Transport.Mode = "multi" }),
		"ws early data":        with(vmess("ws"), func(p *profile.Profile) { p.Transport.Path = "/w?ed=2048" }),
		"xchacha":              {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "xchacha20-ietf-poly1305", Password: "p"},
		"cfb":                  {Protocol: profile.Shadowsocks, Server: "a.example", Port: 443, Cipher: "aes-128-cfb", Password: "p"},
		"kcp dns header":       with(vmess("kcp"), func(p *profile.Profile) { p.Transport.HeaderType = "dns" }),
		"fingerprint":          with(vless(), func(p *profile.Profile) { p.Security.Fingerprint = "chrome" }),
		"fingerprint override": with(vless(), func(p *profile.Profile) { p.Overrides = &profile.Overrides{Fingerprint: "chrome"} }),
	}
	for name, p := range cases {
		if err := Supports(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestSupportsSegmentKCPNotChained(t *testing.T) {
	kcp := vmess("kcp")
	if err := SupportsSegment([]profile.Profile{kcp}, false); err != nil {
		t.Fatalf("single kcp hop: %v", err)
	}
	if err := SupportsSegment([]profile.Profile{vmess("tcp"), kcp}, false); err == nil {
		t.Error("kcp in a chain: want an error")
	}
	if err := SupportsSegment([]profile.Profile{kcp}, true); err == nil {
		t.Error("kcp through a bridge: want an error")
	}
}

type outbound struct {
	Tag           string `json:"tag"`
	ProxySettings *struct {
		Tag            string `json:"tag"`
		TransportLayer bool   `json:"transportLayer"`
	} `json:"proxySettings"`
}

func outbounds(t *testing.T, b []byte) map[string]outbound {
	t.Helper()
	var cfg struct {
		Outbounds []outbound `json:"outbounds"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	out := map[string]outbound{}
	for _, o := range cfg.Outbounds {
		out[o.Tag] = o
	}
	return out
}

func TestBuildConfigChain(t *testing.T) {
	b, err := BuildConfig(profile.Segment{Hops: []profile.Profile{vmess("tcp"), vless()}}, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "dialerProxy") {
		t.Fatalf("dialerProxy survived:\n%s", b)
	}
	ps := outbounds(t, b)["proxy"].ProxySettings
	if ps == nil || ps.Tag != "hop-0" || !ps.TransportLayer {
		t.Fatalf("exit proxySettings = %+v", ps)
	}
}

func TestBuildConfigUpstream(t *testing.T) {
	seg := profile.Segment{Hops: []profile.Profile{vmess("tcp")}, Upstream: &profile.Bridge{Port: 2000, User: "u", Pass: "p"}}
	b, err := BuildConfig(seg, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	ps := outbounds(t, b)["proxy"].ProxySettings
	if ps == nil || ps.Tag != "bridge" || !ps.TransportLayer {
		t.Fatalf("proxySettings = %+v", ps)
	}
}

func TestBuildConfigGRPC(t *testing.T) {
	if _, err := BuildConfig(profile.Single(vmess("grpc")), models.DefaultSettings()); err != nil {
		t.Fatal(err)
	}
}

func TestProbeConfigChain(t *testing.T) {
	b, err := ProbeConfig(profile.Segment{Hops: []profile.Profile{vmess("tcp"), vless()}}, 2001)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "dialerProxy") || outbounds(t, b)["proxy"].ProxySettings == nil {
		t.Fatalf("probe config not adapted:\n%s", b)
	}
}

func TestBuildConfigRejectsUnsupportedHop(t *testing.T) {
	seg := profile.Segment{Hops: []profile.Profile{with(vless(), func(p *profile.Profile) { p.Flow = "xtls-rprx-vision" })}}
	if _, err := BuildConfig(seg, models.DefaultSettings()); err == nil {
		t.Fatal("want an error")
	}
}

func TestRefuseXrayKeys(t *testing.T) {
	for _, key := range []string{"dialerProxy", "realitySettings", "xhttpSettings", "httpupgradeSettings", "flow", "pinnedPeerCertSha256", "fragment", "fingerprint", "multiMode", "authority"} {
		err := refuseXrayKeys([]byte(`{"outbounds":[{"a":{"` + key + `":"x"}}]}`))
		if err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("%s: err = %v", key, err)
		}
	}
	if err := refuseXrayKeys([]byte(`{"outbounds":[{"tag":"proxy","multiMode":false,"authority":""}]}`)); err != nil {
		t.Errorf("clean config: %v", err)
	}
}
