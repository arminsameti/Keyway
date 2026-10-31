package singbox

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// testPKI returns a CA, a client certificate and its key as PEM, plus an
// OpenVPN static key, so OpenVPN profiles carry material sing-box can parse.
func testPKI(t *testing.T) (ca, cert, key, staticKey string) {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now().Add(-time.Hour)
	caKey := gen()
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now, NotAfter: now.AddDate(1, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	cliKey := gen()
	cliT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "client"}, NotBefore: now, NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	cliDER, err := x509.CreateCertificate(rand.Reader, cliT, caCert, &cliKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(cliKey)
	raw := make([]byte, 256)
	_, _ = rand.Read(raw)
	h := hex.EncodeToString(raw)
	sk := "-----BEGIN OpenVPN Static key V1-----\n"
	for i := 0; i < len(h); i += 32 {
		sk += h[i:i+32] + "\n"
	}
	sk += "-----END OpenVPN Static key V1-----"
	enc := func(typ string, der []byte) string {
		return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})))
	}
	return enc("CERTIFICATE", caDER), enc("CERTIFICATE", cliDER), enc("PRIVATE KEY", kb), sk
}

// realityKey is a Reality public key: 32 bytes, URL-safe base64 without padding.
func realityKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func wgKey() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// realHops is one valid profile per protocol sing-box can run.
func realHops(t *testing.T) map[string]profile.Profile {
	ca, cert, key, sk := testPKI(t)
	tlsSec := profile.Security{Kind: "tls", SNI: "s.example.net"}
	id := "11111111-1111-1111-1111-111111111111"
	return map[string]profile.Profile{
		"vless-reality": {Protocol: profile.VLESS, Server: "a.example.com", Port: 443, UUID: id, Flow: "xtls-rprx-vision",
			Security: profile.Security{Kind: "reality", SNI: "w.example.com", PublicKey: realityKey(), ShortID: "ab"}},
		"vmess-ws":    {Protocol: profile.VMess, Server: "a.example.com", Port: 443, UUID: id, Cipher: "auto", Transport: profile.Transport{Type: "ws", Path: "/p", Host: "h.example.com"}, Security: tlsSec},
		"trojan-grpc": {Protocol: profile.Trojan, Server: "a.example.com", Port: 443, Password: "pw", Transport: profile.Transport{Type: "grpc", ServiceName: "svc"}, Security: tlsSec},
		"ss":          {Protocol: profile.Shadowsocks, Server: "a.example.com", Port: 8388, Cipher: "aes-128-gcm", Password: "pw"},
		"socks":       {Protocol: profile.SOCKS, Server: "a.example.com", Port: 1080, Username: "u", Password: "p"},
		"http":        {Protocol: profile.HTTP, Server: "a.example.com", Port: 8080, Username: "u", Password: "p"},
		"hy2":         {Protocol: profile.Hysteria2, Server: "a.example.com", Port: 443, Password: "pw", Security: tlsSec, Hysteria: &profile.HysteriaOpts{UpMbps: 50, DownMbps: 100, Obfs: "salamander", ObfsPassword: "ob"}},
		"hysteria":    {Protocol: profile.Hysteria, Server: "a.example.com", Port: 443, Password: "auth", Security: tlsSec, Hysteria: &profile.HysteriaOpts{UpMbps: 50, DownMbps: 100}},
		"tuic":        {Protocol: profile.TUIC, Server: "a.example.com", Port: 443, UUID: id, Password: "pw", Security: tlsSec, TUIC: &profile.TUICOpts{CongestionControl: "bbr", UDPRelayMode: "native", ZeroRTT: true}},
		"anytls":      {Protocol: profile.AnyTLS, Server: "a.example.com", Port: 443, Password: "pw", Security: tlsSec, AnyTLS: &profile.AnyTLSOpts{IdleTimeoutSec: 30}},
		"naive":       {Protocol: profile.Naive, Server: "a.example.com", Port: 443, Username: "u", Password: "p", Security: profile.Security{Kind: "tls", SNI: "a.example.com"}},
		"ssh":         {Protocol: profile.SSH, Server: "a.example.com", Port: 22, Username: "root", Password: "pw"},
		"shadowtls": {Protocol: profile.ShadowTLS, Server: "a.example.com", Port: 443, Cipher: "aes-128-gcm", Password: "inner",
			ShadowTLS: &profile.ShadowTLSOpts{Version: 3, Password: "outer", SNI: "www.example.com"}},
		"wireguard": {Protocol: profile.WireGuard, Server: "a.example.com", Port: 51820,
			WireGuard: &profile.WireGuardOpts{PrivateKey: wgKey(), PeerPublicKey: wgKey(), PreSharedKey: wgKey(), LocalAddress: []string{"10.7.0.2/32"}, MTU: 1420, Reserved: []int{1, 2, 3}, Keepalive: 25}},
		"openvpn": {Protocol: profile.OpenVPN, Server: "a.example.com", Port: 1194, Transport: profile.Transport{Type: "udp"}, Username: "u", Password: "p",
			OpenVPN: &profile.OpenVPNOpts{CA: ca, Cert: cert, Key: key, Cipher: "AES-256-CBC", Auth: "SHA256", Compression: "lz4-v2", PingInterval: 10, PingRestart: 60,
				ControlWrap: &profile.OVPNControlWrap{Type: "tls_crypt", Key: sk}, VerifyName: "server", VerifyNameType: "name",
				Remotes: []profile.OVPNRemote{{Server: "b.example.com", Port: 443, Network: "tcp"}}}},
	}
}

func singBoxCheck(t *testing.T, bin string, cfg any, name string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(js(t, cfg)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", path)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("%s: sing-box rejected the config: %s", name, strings.TrimSpace(string(out)))
	}
}

// Set SINGBOX_BIN to a sing-box binary (make test-engines does). Unit tests
// only compare JSON text; this one asks the real engine.
func TestRealEngineSingBoxAcceptsEveryConfig(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("set SINGBOX_BIN to run against a real sing-box")
	}
	s := models.DefaultSettings()
	s.RoutingMode, s.BlockAds = "global", false // no rule-set files needed
	hops := realHops(t)

	for name, p := range hops {
		cfg, err := BuildConfig(profile.Single(p), s, rsPath)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		singBoxCheck(t, bin, cfg, name)
		pc, err := ProbeConfig(profile.Single(p), 4321)
		if err != nil {
			t.Errorf("%s probe: %v", name, err)
			continue
		}
		singBoxCheck(t, bin, pc, name+" (probe)")
	}

	// every protocol as the exit of a chain behind an OpenVPN entry, and as a middle hop
	entry := hops["openvpn"]
	for name, p := range hops {
		if name == "openvpn" {
			continue
		}
		seg := profile.Segment{Hops: []profile.Profile{entry, hops["vless-reality"], p}}
		if p.UDPBased() && !profile.RelaysUDP(hops["vless-reality"]) {
			continue
		}
		cfg, err := BuildConfig(seg, s, rsPath)
		if err != nil {
			t.Errorf("chain ending in %s: %v", name, err)
			continue
		}
		singBoxCheck(t, bin, cfg, "chain openvpn -> vless -> "+name)
	}

	// bridges: a middle segment, and a last segment that dials through one
	up := &profile.Bridge{Port: 31001, User: "bu", Pass: "bp"}
	listen := &profile.Bridge{Port: 31002, User: "lu", Pass: "lp"}
	mid, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["openvpn"], hops["trojan-grpc"]}, Listen: listen}, s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, mid, "middle segment")
	withStats, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["wireguard"]}, Stats: &profile.StatsAPI{Port: 31003, Secret: "s"}}, s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, withStats, "stats API")
	rs := s
	rs.RoutingMode = "rules"
	rs.RuleSets = []models.RuleSet{{ID: "r", Name: "r", Rules: []models.RouteRule{
		{ID: "1", Enabled: true, Outbound: "direct", Entries: []string{"domain:a.example", "full:b.example", "keyword:ads", "regexp:^x[0-9]+$", "10.0.0.0/8", "1.2.3.4", "geoip:private", "port:80,443,8000-9000", "process:Slack", "process-path:/Applications/Slack.app/Contents/MacOS/Slack"}},
		{ID: "2", Enabled: true, Outbound: "block", Entries: []string{"domain:bad.example"}}}}}
	rs.ActiveRuleSet = "r"
	custom, err := BuildConfig(profile.Single(hops["wireguard"]), rs, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, custom, "rules mode")
	yes := true
	ov := hops["trojan-grpc"]
	ov.Transport = profile.Transport{Type: "tcp"}
	ov.Overrides = &profile.Overrides{Mux: &yes, MuxConcurrency: 4, Fragment: &profile.Fragment{}}
	withOv, err := BuildConfig(profile.Single(ov), s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, withOv, "fragment and mux overrides")
	custom1 := profile.Profile{Protocol: profile.Custom, Custom: &profile.CustomOpts{Engine: "sing-box", Config: `{"outbounds":[
		{"type":"trojan","tag":"t","server":"a.example.com","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"a.example.com"}}]}`}}
	cc, err := BuildConfig(profile.Segment{Hops: []profile.Profile{custom1}, Stats: &profile.StatsAPI{Port: 31004}}, s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, cc, "custom config")
	appRules := rs
	appRules.RuleSets = []models.RuleSet{{ID: "r", Name: "r", Rules: []models.RouteRule{
		{ID: "1", Enabled: true, Outbound: "direct", Entries: []string{"app:/Applications/Some App.app"}}}}}
	tun, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["wireguard"]}, TUN: &profile.TUNOptions{Stack: "mixed", MTU: 9000, Strict: true, ExcludePaths: []string{"/tmp/xray"}}}, appRules, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, tun, "tun and app rules")
	relay, err := BuildConfig(profile.Segment{Upstream: up, TUN: &profile.TUNOptions{Stack: "gvisor", MTU: 1500}}, s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, relay, "relay with tun")
	last, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hops["wireguard"]}, Upstream: up}, s, rsPath)
	if err != nil {
		t.Fatal(err)
	}
	singBoxCheck(t, bin, last, "last segment behind a bridge")
}
