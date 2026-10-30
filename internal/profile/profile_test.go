package profile

import (
	"strings"
	"testing"
)

func TestSplitCountry(t *testing.T) {
	cases := []struct{ in, cc, name string }{
		{"🇩🇪 Frankfurt 01", "DE", "Frankfurt 01"},
		{"🇬🇧-London", "GB", "London"},
		{"🇩🇪", "DE", "DE"},
		{"DE Frankfurt", "DE", "DE Frankfurt"},
		{"[NL] Amsterdam", "NL", "[NL] Amsterdam"},
		{"UK-London", "GB", "UK-London"},
		{"OK test node", "", "OK test node"},
		{"Home server", "", "Home server"},
		{"de lowercase", "", "de lowercase"},
	}
	for _, c := range cases {
		cc, name := SplitCountry(c.in)
		if cc != c.cc || name != c.name {
			t.Errorf("%q -> %q %q, want %q %q", c.in, cc, name, c.cc, c.name)
		}
	}
}

func TestDisplay(t *testing.T) {
	cases := []struct {
		p              Profile
		transport, sec string
	}{
		{Profile{Protocol: VLESS, Flow: "xtls-rprx-vision", Transport: Transport{Type: "tcp"}, Security: Security{Kind: "reality"}}, "Reality", "Reality · Vision"},
		{Profile{Protocol: VLESS, Transport: Transport{Type: "xhttp"}, Security: Security{Kind: "tls"}}, "XHTTP", "TLS"},
		{Profile{Protocol: VMess, Transport: Transport{Type: "ws"}, Security: Security{Kind: "tls"}}, "WebSocket", "TLS"},
		{Profile{Protocol: Shadowsocks, Cipher: "2022-blake3-aes-128-gcm"}, "TCP", "2022-blake3"},
		{Profile{Protocol: Hysteria2, Security: Security{Kind: "tls"}}, "QUIC", "TLS"},
		{Profile{Protocol: WireGuard}, "UDP", "Curve25519 keys"},
		{Profile{Protocol: SOCKS}, "TCP", "None"},
	}
	for _, c := range cases {
		if got := c.p.DisplayTransport(); got != c.transport {
			t.Errorf("%s transport = %q, want %q", c.p.Protocol, got, c.transport)
		}
		if got := c.p.DisplaySecurity(); got != c.sec {
			t.Errorf("%s security = %q, want %q", c.p.Protocol, got, c.sec)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := Profile{Protocol: Trojan, Server: "a.com", Port: 443, Password: "p", Security: Security{Kind: "tls"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := []Profile{
		{Protocol: Trojan, Server: "", Port: 443, Password: "p"},
		{Protocol: Trojan, Server: "a.com", Port: 0, Password: "p"},
		{Protocol: VLESS, Server: "a.com", Port: 1},
		{Protocol: Shadowsocks, Server: "a.com", Port: 1, Password: "p"},
		{Protocol: "ssr", Server: "a.com", Port: 1},
		{Protocol: SOCKS, Server: "a.com", Port: 1, Transport: Transport{Type: "carrier-pigeon"}},
		{Protocol: VLESS, Server: "a.com", Port: 1, UUID: "u", Security: Security{Kind: "reality"}},
		{Protocol: Hysteria2, Server: "a.com", Port: 1, Password: "p", Security: Security{Kind: "tls", PinSHA256: "AA"}},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("case %d must fail: %+v", i, p)
		}
	}
}

func TestOpenVPNValidateAndDisplay(t *testing.T) {
	ok := Profile{Protocol: OpenVPN, Server: "vpn.example.com", Port: 1194, Transport: Transport{Type: "udp"},
		OpenVPN: &OpenVPNOpts{CA: "CA", Cert: "C", Key: "K", ControlWrap: &OVPNControlWrap{Type: "tls_crypt", Key: "k"}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if ok.DisplayTransport() != "UDP" || ok.DisplaySecurity() != "TLS · tls-crypt" || !ok.UDPBased() {
		t.Fatalf("display: %s / %s / udp=%v", ok.DisplayTransport(), ok.DisplaySecurity(), ok.UDPBased())
	}
	tcp := ok
	tcp.Transport.Type = "tcp"
	if tcp.UDPBased() || tcp.DisplayTransport() != "TCP" {
		t.Fatal("openvpn over TCP is not UDP-based")
	}
	pw := Profile{Protocol: OpenVPN, Server: "v", Port: 443, Username: "u", Password: "p", OpenVPN: &OpenVPNOpts{CA: "CA"}}
	if err := pw.Validate(); err != nil {
		t.Fatalf("username/password without a client certificate: %v", err)
	}
	for name, p := range map[string]Profile{
		"no settings":  {Protocol: OpenVPN, Server: "v", Port: 1},
		"no ca":        {Protocol: OpenVPN, Server: "v", Port: 1, Username: "u", Password: "p", OpenVPN: &OpenVPNOpts{}},
		"cert no key":  {Protocol: OpenVPN, Server: "v", Port: 1, OpenVPN: &OpenVPNOpts{CA: "c", Cert: "x"}},
		"no auth":      {Protocol: OpenVPN, Server: "v", Port: 1, OpenVPN: &OpenVPNOpts{CA: "c"}},
		"needs creds":  {Protocol: OpenVPN, Server: "v", Port: 1, OpenVPN: &OpenVPNOpts{CA: "c", Cert: "x", Key: "k", NeedsCredential: true}},
		"bad wrap":     {Protocol: OpenVPN, Server: "v", Port: 1, OpenVPN: &OpenVPNOpts{CA: "c", Cert: "x", Key: "k", ControlWrap: &OVPNControlWrap{Type: "x", Key: "k"}}},
		"bad fallback": {Protocol: OpenVPN, Server: "v", Port: 1, OpenVPN: &OpenVPNOpts{CA: "c", Cert: "x", Key: "k", Remotes: []OVPNRemote{{Server: "", Port: 1}}}},
	} {
		if p.Validate() == nil {
			t.Errorf("%s must fail", name)
		}
	}
}

func TestCheckChain(t *testing.T) {
	vless := Profile{Protocol: VLESS, Server: "a.com", Port: 443, UUID: "u"}
	ssh := Profile{Protocol: SSH, Server: "s.com", Port: 22, Username: "root", Password: "p"}
	wg := Profile{Protocol: WireGuard, Server: "w.com", Port: 51820,
		WireGuard: &WireGuardOpts{PrivateKey: "k", PeerPublicKey: "p", LocalAddress: []string{"10.0.0.2/32"}}}
	ovpn := Profile{Protocol: OpenVPN, Server: "o.com", Port: 1194, Transport: Transport{Type: "udp"},
		OpenVPN: &OpenVPNOpts{CA: "c", Cert: "x", Key: "k"}}
	trojan := Profile{Protocol: Trojan, Server: "t.com", Port: 443, Password: "p"}

	if err := CheckChain([]Profile{ovpn, vless, wg}, []string{"Office", "Frankfurt", "Home WG"}); err != nil {
		t.Fatalf("openvpn -> vless -> wireguard must be allowed: %v", err)
	}
	if err := CheckChain([]Profile{ssh, trojan, vless}, nil); err != nil {
		t.Fatalf("TCP hops after a TCP-only hop are fine: %v", err)
	}
	err := CheckChain([]Profile{vless, ssh, wg}, []string{"A", "Jump box", "Home WG"})
	if err == nil || !strings.Contains(err.Error(), "Jump box") || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("wireguard after ssh must name the culprits: %v", err)
	}
	if CheckChain([]Profile{vless}, nil) == nil {
		t.Fatal("one server is not a chain")
	}
	long := make([]Profile, MaxChainHops+1)
	for i := range long {
		long[i] = vless
	}
	if CheckChain(long, nil) == nil {
		t.Fatal("too many hops")
	}
	if CheckChain([]Profile{vless, {Protocol: VLESS}}, nil) == nil {
		t.Fatal("an invalid hop must be reported")
	}
}
