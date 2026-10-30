package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"xray-friendly/internal/profile"
)

func outboundJSON(t *testing.T, p profile.Profile) string {
	t.Helper()
	ob, err := FromProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ob)
	return string(b)
}

func TestOutboundPerProtocol(t *testing.T) {
	tls := profile.Security{Kind: "tls", SNI: "s.com"}
	cases := []struct {
		name string
		p    profile.Profile
		want []string
	}{
		{"vmess ws", profile.Profile{Protocol: profile.VMess, Server: "a.com", Port: 443, UUID: "id", Cipher: "auto",
			Transport: profile.Transport{Type: "ws", Path: "/p", Host: "cdn.com"}, Security: tls},
			[]string{`"protocol":"vmess"`, `"alterId":0`, `"security":"auto"`, `"network":"ws"`, `"Host":"cdn.com"`, `"serverName":"s.com"`}},
		{"vless reality", profile.Profile{Protocol: profile.VLESS, Server: "a.com", Port: 443, UUID: "id", Flow: "xtls-rprx-vision",
			Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "reality", SNI: "w.com", PublicKey: "PK", ShortID: "ab"}},
			[]string{`"encryption":"none"`, `"flow":"xtls-rprx-vision"`, `"security":"reality"`, `"publicKey":"PK"`, `"fingerprint":"chrome"`}},
		{"trojan grpc", profile.Profile{Protocol: profile.Trojan, Server: "a.com", Port: 443, Password: "pw",
			Transport: profile.Transport{Type: "grpc", ServiceName: "svc", Mode: "multi"}, Security: tls},
			[]string{`"password":"pw"`, `"serviceName":"svc"`, `"multiMode":true`}},
		{"shadowsocks", profile.Profile{Protocol: profile.Shadowsocks, Server: "a.com", Port: 8388, Cipher: "2022-blake3-aes-128-gcm", Password: "pw"},
			[]string{`"method":"2022-blake3-aes-128-gcm"`}},
		{"socks auth", profile.Profile{Protocol: profile.SOCKS, Server: "a.com", Port: 1080, Username: "u", Password: "p"},
			[]string{`"protocol":"socks"`, `"user":"u"`, `"pass":"p"`}},
		{"https proxy", profile.Profile{Protocol: profile.HTTP, Server: "a.com", Port: 443, Username: "u", Password: "p", Security: tls},
			[]string{`"protocol":"http"`, `"security":"tls"`}},
		{"kcp header", profile.Profile{Protocol: profile.VLESS, Server: "a.com", Port: 443, UUID: "id",
			Transport: profile.Transport{Type: "kcp", HeaderType: "wechat-video", Seed: "s"}},
			[]string{`"network":"kcp"`, `"type":"wechat-video"`, `"seed":"s"`}},
		{"tcp http header", profile.Profile{Protocol: profile.VLESS, Server: "a.com", Port: 80, UUID: "id",
			Transport: profile.Transport{Type: "tcp", HeaderType: "http", Path: "/", Host: "a.com,b.com"}},
			[]string{`"type":"http"`, `"Host":["a.com","b.com"]`}},
	}
	for _, c := range cases {
		got := outboundJSON(t, c.p)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: missing %s in %s", c.name, w, got)
			}
		}
	}
	if s := outboundJSON(t, profile.Profile{Protocol: profile.HTTP, Server: "a.com", Port: 8080}); strings.Contains(s, "streamSettings") {
		t.Errorf("plain http proxy must have no stream settings: %s", s)
	}
}

func TestHysteria2PinWinsOverInsecure(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	hy := profile.Profile{Protocol: profile.Hysteria2, Server: "h.com", Port: 443, Password: "pw",
		Security: profile.Security{Kind: "tls", SNI: "h.com", Insecure: true, PinSHA256: pin}}
	got := outboundJSON(t, hy)
	for _, w := range []string{`"protocol":"hysteria"`, `"version":2`, `"auth":"pw"`, `"network":"hysteria"`, `"alpn":["h3"]`, `"pinnedPeerCertSha256":"` + pin} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %s", w, got)
		}
	}
	if strings.Contains(got, "allowInsecure") {
		t.Errorf("allowInsecure must not be emitted next to a pin: %s", got)
	}
	hy.Security.PinSHA256 = ""
	if _, err := FromProfile(hy); err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Errorf("unpinned insecure TLS goes to sing-box: %v", err)
	}
}

func TestWireGuardOutbound(t *testing.T) {
	wg := profile.Profile{Protocol: profile.WireGuard, Server: "wg.example.org", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "PRIV", PeerPublicKey: "PUB", PreSharedKey: "PSK",
			LocalAddress: []string{"10.7.0.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}, Keepalive: 25}}
	got := outboundJSON(t, wg)
	for _, w := range []string{`"protocol":"wireguard"`, `"secretKey":"PRIV"`, `"address":["10.7.0.2/32"]`, `"publicKey":"PUB"`,
		`"preSharedKey":"PSK"`, `"endpoint":"wg.example.org:51820"`, `"keepAlive":25`, `"mtu":1420`, `"reserved":[1,2,3]`,
		`"allowedIPs":["0.0.0.0/0","::/0"]`} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %s", w, got)
		}
	}
	if strings.Contains(got, "streamSettings") {
		t.Errorf("wireguard has no stream settings: %s", got)
	}
}

func TestUnsupportedOnXray(t *testing.T) {
	for _, p := range []profile.Profile{
		{Protocol: profile.Hysteria2, Hysteria: &profile.HysteriaOpts{Obfs: "salamander", ObfsPassword: "x"}},
		{Protocol: profile.Hysteria2, Hysteria: &profile.HysteriaOpts{UpMbps: 50}},
		{Protocol: profile.Hysteria}, {Protocol: profile.AnyTLS}, {Protocol: profile.Naive}, {Protocol: profile.SSH}, {Protocol: profile.ShadowTLS},
	} {
		if err := Supports(p); err == nil || !strings.Contains(err.Error(), "sing-box") {
			t.Errorf("%s %+v: %v", p.Protocol, p.Hysteria, err)
		}
	}
	if _, err := FromProfile(profile.Profile{Protocol: profile.VLESS, Server: "a.com", Port: 1, UUID: "u", Transport: profile.Transport{Type: "quic"}}); err == nil {
		t.Error("quic transport must be rejected")
	}
	if Supports(profile.Profile{Protocol: profile.TUIC}) == nil {
		t.Error("TUIC is sing-box only")
	}
}
