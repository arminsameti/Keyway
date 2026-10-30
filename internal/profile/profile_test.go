package profile

import "testing"

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
