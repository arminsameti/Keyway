package xray

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

func realKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// realityKey is a Reality public key: 32 bytes, URL-safe base64 without padding.
func realityKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func xrayTest(t *testing.T, bin string, cfg *Config, name string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(mustJSON(t, cfg)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "run", "-test", "-c", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%s: Xray rejected the config: %s", name, strings.TrimSpace(string(out)))
	}
}

// Set XRAY_BIN to an Xray binary (make test-engines does).
func TestRealEngineXrayAcceptsEveryConfig(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("set XRAY_BIN to run against a real Xray")
	}
	s := models.DefaultSettings()
	s.RoutingMode, s.BlockAds = "global", false
	id := "11111111-1111-1111-1111-111111111111"
	tls := profile.Security{Kind: "tls", SNI: "s.example.net"}
	hops := map[string]profile.Profile{
		"vless-reality": {Protocol: profile.VLESS, Server: "a.example.com", Port: 443, UUID: id, Flow: "xtls-rprx-vision", Transport: profile.Transport{Type: "tcp"},
			Security: profile.Security{Kind: "reality", SNI: "w.example.com", PublicKey: realityKey(), ShortID: "ab"}},
		"vless-xhttp": {Protocol: profile.VLESS, Server: "a.example.com", Port: 443, UUID: id, Transport: profile.Transport{Type: "xhttp", Path: "/x"}, Security: tls},
		"vmess-ws":    {Protocol: profile.VMess, Server: "a.example.com", Port: 443, UUID: id, Cipher: "auto", Transport: profile.Transport{Type: "ws", Path: "/p"}, Security: tls},
		"trojan-grpc": {Protocol: profile.Trojan, Server: "a.example.com", Port: 443, Password: "pw", Transport: profile.Transport{Type: "grpc", ServiceName: "svc"}, Security: tls},
		"ss":          {Protocol: profile.Shadowsocks, Server: "a.example.com", Port: 8388, Cipher: "aes-128-gcm", Password: "pw"},
		"socks":       {Protocol: profile.SOCKS, Server: "a.example.com", Port: 1080, Username: "u", Password: "p"},
		"http":        {Protocol: profile.HTTP, Server: "a.example.com", Port: 8080, Username: "u", Password: "p"},
		"hy2": {Protocol: profile.Hysteria2, Server: "a.example.com", Port: 443, Password: "pw",
			Security: profile.Security{Kind: "tls", SNI: "h.example.com", PinSHA256: strings.Repeat("ab", 32)}},
		"wireguard": {Protocol: profile.WireGuard, Server: "a.example.com", Port: 51820,
			WireGuard: &profile.WireGuardOpts{PrivateKey: realKey(), PeerPublicKey: realKey(), LocalAddress: []string{"10.7.0.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}, Keepalive: 25}},
	}
	for name, p := range hops {
		cfg, err := BuildConfig(profile.Single(p), s)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		xrayTest(t, bin, cfg, name)
		pc, err := ProbeConfig(profile.Single(p), 4321)
		if err != nil {
			t.Errorf("%s probe: %v", name, err)
			continue
		}
		xrayTest(t, bin, pc, name+" (probe)")
	}

	// chains of TCP hops, with the dialerProxy on each
	tcp := []string{"vless-reality", "vless-xhttp", "vmess-ws", "trojan-grpc", "ss", "socks", "http"}
	for _, a := range tcp {
		for _, b := range tcp {
			cfg, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops[a], hops["trojan-grpc"], hops[b]}}, s)
			if err != nil {
				t.Errorf("chain %s -> trojan -> %s: %v", a, b, err)
				continue
			}
			xrayTest(t, bin, cfg, "chain "+a+" -> trojan-grpc -> "+b)
		}
	}
	// bridges
	up := &profile.Bridge{Port: 31001, User: "bu", Pass: "bp"}
	listen := &profile.Bridge{Port: 31002, User: "lu", Pass: "lp"}
	last, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["vless-xhttp"], hops["vmess-ws"]}, Upstream: up}, s)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, bin, last, "last segment behind a bridge")
	withStats, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["vless-xhttp"]}, Stats: &profile.StatsAPI{Port: 31003, Secret: "s"}}, s)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, bin, withStats, "stats API")
	rs := s
	rs.RoutingMode = "rules"
	rs.RuleSets = []models.RuleSet{{ID: "r", Name: "r", Rules: []models.RouteRule{
		{ID: "1", Enabled: true, Outbound: "direct", Entries: []string{"domain:a.example", "full:b.example", "keyword:ads", "regexp:^x[0-9]+$", "10.0.0.0/8", "1.2.3.4", "port:80,443,8000-9000"}},
		{ID: "2", Enabled: true, Outbound: "block", Entries: []string{"domain:bad.example"}}}}}
	rs.ActiveRuleSet = "r"
	custom, err := BuildConfig(profile.Single(hops["vless-xhttp"]), rs)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, bin, custom, "rules mode")
	yes := true
	ov := hops["trojan-grpc"]
	ov.Transport = profile.Transport{Type: "tcp"}
	ov.Overrides = &profile.Overrides{Mux: &yes, MuxConcurrency: 4, Fragment: &profile.Fragment{Length: "50-100"}}
	withOv, err := BuildConfig(profile.Single(ov), s)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, bin, withOv, "fragment and mux overrides")
	custom1 := profile.Profile{Protocol: profile.Custom, Custom: &profile.CustomOpts{Engine: "xray", Config: `{"outbounds":[
		{"tag":"front","protocol":"trojan","settings":{"servers":[{"address":"a.example.com","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}}]}`}}
	cc, err := BuildConfig(profile.Segment{Hops: []profile.Profile{custom1}, Stats: &profile.StatsAPI{Port: 31004}}, s)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, bin, cc, "custom config")
	mid, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["vless-reality"]}, Listen: listen}, s)
	if err != nil {
		t.Fatal(err)
	}
	xrayTest(t, bin, mid, "middle segment")
}
