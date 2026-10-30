package link

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func vmessLink(t *testing.T, m map[string]any) string {
	t.Helper()
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func mustParse(t *testing.T, raw string) Result {
	t.Helper()
	r, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%.30s…): %v", raw, err)
	}
	return r
}

func TestVMessWS(t *testing.T) {
	raw := vmessLink(t, map[string]any{"ps": "ws node", "add": "ex.com", "port": "443", "id": "uuid-1", "aid": 0,
		"net": "ws", "host": "cdn.ex.com", "path": "/p", "tls": "tls", "sni": "sni.ex.com"})
	r := mustParse(t, raw)
	if r.Node.Name != "ws node" || r.Node.Protocol != "vmess" || r.Node.Port != 443 {
		t.Fatalf("node: %+v", r.Node)
	}
	pr := r.Profile
	if pr.Transport.Type != "ws" || pr.Security.Kind != "tls" || pr.Transport.Path != "/p" || pr.Transport.Host != "cdn.ex.com" || pr.Security.SNI != "sni.ex.com" {
		t.Fatalf("profile: %+v", pr)
	}
	if pr.UUID != "uuid-1" || pr.Cipher != "auto" {
		t.Fatalf("auth: %+v", pr)
	}
}

func TestVMessRejectsGarbage(t *testing.T) {
	if _, err := Parse("vmess://!!!"); err == nil {
		t.Fatal("bad base64 must fail")
	}
	if _, err := Parse(vmessLink(t, map[string]any{"add": "", "port": 1, "id": "x"})); err == nil {
		t.Fatal("missing address must fail")
	}
	if _, err := Parse(vmessLink(t, map[string]any{"add": "a.com", "port": 70000, "id": "x"})); err == nil {
		t.Fatal("bad port must fail")
	}
}

func TestVLESSReality(t *testing.T) {
	raw := "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision&type=tcp#My%20Reality"
	r := mustParse(t, raw)
	if r.Node.Name != "My Reality" {
		t.Fatalf("name = %q", r.Node.Name)
	}
	sec := r.Profile.Security
	if sec.Kind != "reality" || sec.PublicKey != "PUBKEY" || sec.ShortID != "ab12" || sec.SNI != "www.example.com" || sec.Fingerprint != "chrome" {
		t.Fatalf("reality: %+v", sec)
	}
	if r.Profile.Flow != "xtls-rprx-vision" || r.Profile.DisplaySecurity() != "Reality · Vision" || r.Profile.DisplayTransport() != "Reality" {
		t.Fatalf("flow/display: %+v", r.Profile)
	}
	// reality implied by pbk even without security=
	r2 := mustParse(t, "vless://u@h.com:443?pbk=K&sni=a.com")
	if r2.Profile.Security.Kind != "reality" {
		t.Fatal("pbk should imply reality")
	}
	if _, err := Parse("vless://u@h.com:443?security=reality"); err == nil {
		t.Fatal("reality without pbk must fail")
	}
}

func TestVLESSTransports(t *testing.T) {
	for _, tc := range []struct{ q, network string }{
		{"type=grpc&serviceName=svc&mode=multi", "grpc"}, {"type=ws&path=/x", "ws"}, {"type=xhttp&path=/x&host=h", "xhttp"},
		{"type=splithttp&path=/x", "xhttp"}, {"type=httpupgrade&path=/u", "httpupgrade"}, {"type=h2&host=a.com,b.com", "h2"},
		{"type=kcp&headerType=wechat-video&seed=s", "kcp"}, {"type=tcp&headerType=http&host=h.com&path=/", "tcp"},
	} {
		r := mustParse(t, "vless://u@h.com:443?security=tls&"+tc.q)
		if r.Profile.Transport.Type != tc.network {
			t.Errorf("%s -> %s", tc.q, r.Profile.Transport.Type)
		}
	}
	if _, err := Parse("vless://u@h.com:443?type=quic"); err == nil {
		t.Fatal("unknown transport must fail, not silently produce a broken config")
	}
}

func TestTrojanDefaultsToTLS(t *testing.T) {
	r := mustParse(t, "trojan://pa%24s@t.com:443?sni=t.com#T")
	if r.Profile.Security.Kind != "tls" {
		t.Fatal("trojan should default to tls")
	}
	if r.Profile.Password != "pa$s" {
		t.Fatalf("password = %q", r.Profile.Password)
	}
	if mustParse(t, "trojan://p@t.com:443?security=none").Profile.Security.Kind != "none" {
		t.Fatal("explicit security=none must be honoured")
	}
}

func TestShadowsocksForms(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pass:word"))
	sip002 := "ss://" + userinfo + "@1.2.3.4:8388#SIP002"
	legacy := "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:secret@5.6.7.8:9999")) + "#Legacy"
	plain := "ss://aes-128-gcm:plainpw@9.9.9.9:1234#Plain"
	v6 := "ss://" + userinfo + "@[2001:db8::1]:8388#V6"

	cases := []struct {
		raw, host, method, pw string
		port                  int
	}{
		{sip002, "1.2.3.4", "aes-256-gcm", "pass:word", 8388},
		{legacy, "5.6.7.8", "chacha20-ietf-poly1305", "secret", 9999},
		{plain, "9.9.9.9", "aes-128-gcm", "plainpw", 1234},
		{v6, "2001:db8::1", "aes-256-gcm", "pass:word", 8388},
	}
	for _, c := range cases {
		r := mustParse(t, c.raw)
		s := r.Profile
		if s.Server != c.host || s.Cipher != c.method || s.Password != c.pw || s.Port != c.port {
			t.Errorf("%.20s: got %+v", c.raw, s)
		}
	}
	if _, err := Parse("ss://" + userinfo + "@1.2.3.4:8388?plugin=obfs-local"); err == nil {
		t.Fatal("plugins must be rejected explicitly")
	}
	bad := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:pw")) + "@1.2.3.4:1"
	if _, err := Parse(bad); err == nil {
		t.Fatal("unsupported cipher must be rejected")
	}
}

func TestSocksAndHysteria(t *testing.T) {
	r := mustParse(t, "socks5://user:pw@10.0.0.1:1081#S")
	s := r.Profile
	if s.Port != 1081 || s.Username != "user" || s.Password != "pw" {
		t.Fatalf("socks: %+v", s)
	}
	h := mustParse(t, "hy2://secret@h.com:8443?sni=h.com&insecure=1#H")
	if h.Node.Protocol != "hysteria2" || h.Profile.Protocol != "hysteria2" || h.Profile.Password != "secret" || !h.Profile.Security.Insecure {
		t.Fatalf("hysteria: %+v", h.Profile)
	}
	if !h.Profile.UDPBased() || h.Profile.DisplayTransport() != "QUIC" {
		t.Fatalf("hysteria display: %+v", h.Profile)
	}
	for _, bad := range []string{"hy2://s@h.com:1?obfs=salamander", "hy2://s@h.com:1?obfs=xor&obfs-password=p", "hy2://s@h.com:1?pinSHA256=AA", "hy2://s@h.com:1?pinSHA256=" + strings.Repeat("zz", 32)} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s must be rejected, not silently degraded", bad)
		}
	}
}

func TestHTTPURLIsNotANode(t *testing.T) {
	if _, err := Parse("https://sub.example.com/token"); err == nil {
		t.Fatal("an https URL must not parse as a proxy node")
	}
}

func readyCount(items []Item) int {
	n := 0
	for _, it := range items {
		if it.Kind == KindReady {
			n++
		}
	}
	return n
}

func TestBase64SubscriptionBody(t *testing.T) {
	links := "vless://u@a.com:443?security=tls#A\ntrojan://p@b.com:443#B\r\nhttps://ignored\n"
	body := base64.StdEncoding.EncodeToString([]byte(links))
	if n := readyCount(Classify(body)); n != 2 {
		t.Fatalf("std: %d", n)
	}
	// URL-safe, unpadded, line-wrapped variants
	wrapped := base64.RawURLEncoding.EncodeToString([]byte(links))
	wrapped = wrapped[:20] + "\n" + wrapped[20:]
	if n := readyCount(Classify(wrapped)); n != 2 {
		t.Fatalf("wrapped variant: %d", n)
	}
	// plain text still works
	if n := readyCount(Classify(links)); n != 2 {
		t.Fatalf("plain: %d", n)
	}
	if DetectFormat(body) != FormatBase64 || DetectFormat(links) != FormatLinks {
		t.Fatal("format detection")
	}
}

func TestImportErrorsDoNotLeakCredentials(t *testing.T) {
	items := Classify("vless://SECRET-UUID@host:99999?security=tls")
	if len(items) != 1 || items[0].Kind != KindSkipped || strings.Contains(items[0].Reason, "SECRET-UUID") {
		t.Fatalf("items = %+v", items)
	}
}

func TestNodeIDIgnoresFragment(t *testing.T) {
	a := NodeID("vless://u@h.com:443?security=tls#Old%20name")
	b := NodeID("vless://u@h.com:443?security=tls#New%20name")
	c := NodeID("vless://u@h.com:444?security=tls#Old%20name")
	if a != b || a == c || len(a) != 16 {
		t.Fatalf("a=%s b=%s c=%s", a, b, c)
	}
}

func TestEveryParsedProfileValidates(t *testing.T) {
	for _, raw := range []string{
		"vless://u@h.com:443?security=tls&type=ws&path=/w&host=h.com#x",
		"trojan://p@t.com:443#T", "socks5://10.0.0.1:1080", "hy2://s@h.com:443#H",
		"ss://aes-128-gcm:pw@9.9.9.9:1234#P",
	} {
		if err := mustParse(t, raw).Profile.Validate(); err != nil {
			t.Errorf("%.12s: %v", raw, err)
		}
	}
}

func TestHysteriaPinMapsToPinnedPeerCert(t *testing.T) {
	const colon = "1E:CE:E9:0A:DD:D6:46:A8:05:C8:70:29:FF:14:AA:23:C1:BC:D5:66:54:A8:90:8E:EE:20:71:47:D3:F5:AB:7B"
	for _, pin := range []string{colon, strings.ReplaceAll(strings.ToLower(colon), ":", "")} {
		// insecure=1 alongside a pin is common in share links; the pin wins,
		// because cores that verify pins no longer accept allowInsecure.
		h := mustParse(t, "hy2://s@h.com:443?sni=h.com&insecure=1&pinSHA256="+pin+"#H")
		sec := h.Profile.Security
		if sec.PinSHA256 != pin || sec.Insecure {
			t.Errorf("pin %s: got %+v", pin, sec)
		}
	}
}
