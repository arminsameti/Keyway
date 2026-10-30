package link

import (
	"strings"
	"testing"
)

const (
	pemCA   = "-----BEGIN CERTIFICATE-----\nMIIBCA\n-----END CERTIFICATE-----"
	pemCert = "-----BEGIN CERTIFICATE-----\nMIIBCERT\n-----END CERTIFICATE-----"
	pemKey  = "-----BEGIN PRIVATE KEY-----\nMIIBKEY\n-----END PRIVATE KEY-----"
	crypt   = "-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----"
)

func ovpn(extra, blocks string) string {
	return "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\n" +
		"remote-cert-tls server\ncipher AES-256-CBC\nauth SHA256\nverb 3\n" + extra + "\n" + blocks
}

func blocks(parts ...string) string {
	all := map[string]string{"ca": pemCA, "cert": pemCert, "key": pemKey, "tls-crypt": crypt}
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("<" + p + ">\n" + all[p] + "\n</" + p + ">\n")
	}
	return b.String()
}

func TestOVPNInlineProfile(t *testing.T) {
	text := ovpn("keepalive 10 60\nreneg-sec 0\ncompress lz4-v2\nverify-x509-name server-cn name\ntls-version-min 1.2\n", blocks("ca", "cert", "key", "tls-crypt"))
	if !LooksLikeOVPN(text) || DetectFormat(text) != FormatOVPN {
		t.Fatal("must be detected as an OpenVPN profile")
	}
	r, err := ParseOVPN(text, "")
	if err != nil {
		t.Fatal(err)
	}
	p, o := r.Profile, r.Profile.OpenVPN
	if p.Protocol != "openvpn" || p.Server != "vpn.example.com" || p.Port != 1194 || p.Transport.Type != "udp" || r.Node.Name != "OpenVPN vpn.example.com" {
		t.Fatalf("basics: %+v / %+v", p, r.Node)
	}
	if o.CA != pemCA || o.Cert != pemCert || o.Key != pemKey || o.Cipher != "AES-256-CBC" || o.Auth != "SHA256" {
		t.Fatalf("material/ciphers: %+v", o)
	}
	if o.ControlWrap == nil || o.ControlWrap.Type != "tls_crypt" || o.ControlWrap.Key != crypt {
		t.Fatalf("wrap: %+v", o.ControlWrap)
	}
	if o.PingInterval != 10 || o.PingRestart != 60 || o.RenegSec == nil || *o.RenegSec != 0 || o.Compression != "lz4-v2" ||
		o.VerifyName != "server-cn" || o.VerifyNameType != "name" || o.RemoteCertTLS != "server" || o.TLSVersionMin != "1.2" {
		t.Fatalf("options: %+v", o)
	}
	// stored as a profile (no share-link format), and it round-trips
	if r.Node.RawLink != "" || len(r.Node.Profile) == 0 {
		t.Fatalf("node: %+v", r.Node)
	}
	back, err := NodeProfile(r.Node.RawLink, r.Node.Profile)
	if err != nil || back.OpenVPN.CA != pemCA {
		t.Fatalf("stored profile: %v", err)
	}
	if got := mustClassify(t, text); got != KindReady {
		t.Fatalf("classify: %s", got)
	}
}

func mustClassify(t *testing.T, text string) string {
	t.Helper()
	items := Classify(text)
	if len(items) != 1 {
		t.Fatalf("items: %+v", items)
	}
	return items[0].Kind
}

func TestOVPNRemotesAndProtocols(t *testing.T) {
	text := "client\ndev tun\nproto tcp-client\nremote a.example.com 443\nremote b.example.com 1194 udp\nremote c.example.com\nremote-random\n" +
		blocks("ca") + "<auth-user-pass>\nalice\ns3cret\n</auth-user-pass>\n"
	r, err := ParseOVPN(text, "Work")
	if err != nil {
		t.Fatal(err)
	}
	p, o := r.Profile, r.Profile.OpenVPN
	if p.Transport.Type != "tcp" || p.Server != "a.example.com" || p.Port != 443 || r.Node.Name != "Work" {
		t.Fatalf("%+v", p)
	}
	if len(o.Remotes) != 2 || o.Remotes[0].Network != "udp" || o.Remotes[0].Port != 1194 || o.Remotes[1].Server != "c.example.com" || o.Remotes[1].Port != 1194 || !o.RemoteRandom {
		t.Fatalf("remotes: %+v", o.Remotes)
	}
	if p.Username != "alice" || p.Password != "s3cret" || o.NeedsCredential {
		t.Fatalf("inline credentials: %q %q needs=%v", p.Username, p.Password, o.NeedsCredential)
	}
	// <connection> blocks
	c := "client\ndev tun\n<connection>\nremote one.example.com 1194 udp\n</connection>\n<connection>\nremote two.example.com 443 tcp\n</connection>\n" + blocks("ca", "cert", "key")
	r, err = ParseOVPN(c, "")
	if err != nil || r.Profile.Server != "one.example.com" || len(r.Profile.OpenVPN.Remotes) != 1 || r.Profile.OpenVPN.Remotes[0].Network != "tcp" {
		t.Fatalf("connection blocks: %v %+v", err, r.Profile)
	}
}

func TestOVPNTLSAuthDirectionAndCredentialsPrompt(t *testing.T) {
	bl := "<tls-auth>\n" + crypt + "\n</tls-auth>\n" + blocks("ca", "cert", "key")
	r, err := ParseOVPN("client\ndev tun\nremote v.example.com 1194\nkey-direction 1\n"+bl, "")
	if err != nil || r.Profile.OpenVPN.ControlWrap.Type != "tls_auth" || r.Profile.OpenVPN.ControlWrap.Direction != "client" {
		t.Fatalf("tls-auth: %v %+v", err, r.Profile.OpenVPN.ControlWrap)
	}
	// auth-user-pass with no stored credentials: the form can still be filled, the import is refused
	text := ovpn("auth-user-pass\n", blocks("ca"))
	p, _, err := ParseOVPNProfile(text)
	if err != nil || !p.OpenVPN.NeedsCredential {
		t.Fatalf("raw parse must succeed and flag the missing credentials: %v", err)
	}
	items := Classify(text)
	if items[0].Kind != KindSkipped || !strings.Contains(items[0].Reason, "username and password") {
		t.Fatalf("import must be refused with a reason: %+v", items[0])
	}
}

func TestOVPNRefusals(t *testing.T) {
	ok := blocks("ca", "cert", "key")
	cases := map[string]struct{ text, want string }{
		"tap":         {ovpn("", ok) + "dev tap\n", "TAP"},
		"static key":  {ovpn("secret static.key\n", ok), "static-key"},
		"http proxy":  {ovpn("http-proxy proxy.example.com 8080\n", ok), "proxy"},
		"plugin":      {ovpn("plugin foo.so\n", ok), "plugin"},
		"pkcs12":      {ovpn("pkcs12 client.p12\n", ok), "PKCS#12"},
		"server conf": {ovpn("server 10.8.0.0 255.255.255.0\n", ok), "server configuration"},
		"file ca":     {ovpn("ca ca.crt\n", blocks("cert", "key")), "ca.crt"},
		"file crypt":  {ovpn("tls-crypt ta.key\n", ok), "tls-crypt"},
		"enc key":     {ovpn("", "<ca>\n"+pemCA+"\n</ca>\n<cert>\n"+pemCert+"\n</cert>\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nxx\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n"), "passphrase"},
		"no remote":   {"client\ndev tun\nremote-cert-tls server\n" + ok, "no remote"},
		"open block":  {ovpn("", "<ca>\n"+pemCA+"\n"), "not closed"},
		"bad port":    {"client\ndev tun\nremote v.example.com 99999\n" + ok, "port"},
	}
	for name, c := range cases {
		if _, _, err := ParseOVPNProfile(c.text); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
	// the refusal reaches the import preview as a skipped item with its reason
	items := Classify(ovpn("secret static.key\n", ok))
	if items[0].Kind != KindSkipped || !strings.HasPrefix(items[0].Reason, "OpenVPN: ") {
		t.Fatalf("classify: %+v", items[0])
	}
	// share links and other formats are not mistaken for OpenVPN
	for _, text := range []string{"vless://u@h.com:443#x", "proxies:\n  - {name: a}", "remote host\n"} {
		if LooksLikeOVPN(text) {
			t.Errorf("%q is not an OpenVPN profile", text)
		}
	}
}

func TestOVPNArgs(t *testing.T) {
	got := ovpnArgs(`remote "my server.example.com" 1194 udp # comment`)
	if len(got) != 4 || got[1] != "my server.example.com" || got[3] != "udp" {
		t.Fatalf("%q", got)
	}
}
