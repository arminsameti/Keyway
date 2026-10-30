package link

import (
	"reflect"
	"strings"
	"testing"

	"xray-friendly/internal/profile"
)

const (
	wgPriv = "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA="
	wgPub  = "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5cHViMDA="
)

func TestWireGuardLink(t *testing.T) {
	raw := "wireguard://" + strings.ReplaceAll(wgPriv, "=", "%3D") + "@wg.example.org:51820?publickey=" +
		strings.ReplaceAll(wgPub, "=", "%3D") + "&address=10.7.0.2/32,fd00::2/128&mtu=1420&reserved=1,2,3&keepalive=25#Home%20WG"
	r := mustParse(t, raw)
	w := r.Profile.WireGuard
	if r.Node.Protocol != "wireguard" || r.Node.Name != "Home WG" || w.PrivateKey != wgPriv || w.PeerPublicKey != wgPub ||
		len(w.LocalAddress) != 2 || w.MTU != 1420 || !reflect.DeepEqual(w.Reserved, []int{1, 2, 3}) || w.Keepalive != 25 {
		t.Fatalf("%+v %+v", r.Node, w)
	}
	if !r.Profile.UDPBased() || r.Profile.DisplayTransport() != "UDP" {
		t.Fatal("wireguard is UDP")
	}
	// alternative spellings and the wg:// scheme
	alt := mustParse(t, "wg://k@1.2.3.4:51820?public_key=P&ip=10.0.0.2/32")
	if alt.Profile.WireGuard.PeerPublicKey != "P" || alt.Profile.WireGuard.LocalAddress[0] != "10.0.0.2/32" {
		t.Fatalf("alt: %+v", alt.Profile.WireGuard)
	}
	for _, bad := range []string{
		"wireguard://k@h:1?address=10.0.0.2/32",                // no peer key
		"wireguard://k@h:1?publickey=P",                        // no address
		"wireguard://k@h:1?publickey=P&address=a&reserved=1,2", // reserved too short
		"wireguard://k@h:1?publickey=P&address=a&mtu=big",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s must fail", bad)
		}
	}
}

func TestWireGuardConf(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + wgPriv + `
Address = 10.7.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1380

[Peer]
PublicKey = ` + wgPub + `
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrMDA=
Endpoint = wg.example.org:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	if !LooksLikeWireGuardConf(conf) {
		t.Fatal("detect")
	}
	r, err := ParseWireGuardConf(conf, "")
	if err != nil {
		t.Fatal(err)
	}
	w := r.Profile.WireGuard
	if r.Node.Name != "WireGuard wg.example.org" || r.Node.Port != 51820 || w.MTU != 1380 || len(w.AllowedIPs) != 2 || w.PreSharedKey == "" {
		t.Fatalf("%+v %+v", r.Node, w)
	}
	if r.Node.RawLink == "" || !strings.HasPrefix(r.Node.RawLink, "wireguard://") {
		t.Fatalf("a .conf becomes a canonical link: %q", r.Node.RawLink)
	}
	if _, err := ParseWireGuardConf("[Interface]\nPrivateKey = x\n", ""); err == nil {
		t.Fatal("missing peer must fail")
	}
	if _, err := ParseWireGuardConf(strings.Replace(conf, "Endpoint = wg.example.org:51820", "Endpoint = nope", 1), ""); err == nil {
		t.Fatal("bad endpoint must fail")
	}
}

func TestTUIC(t *testing.T) {
	r := mustParse(t, "tuic://11111111-1111-1111-1111-111111111111:pw@sgp.example.net:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=sgp.example.net&reduce_rtt=1#Singapore")
	p := r.Profile
	if p.UUID == "" || p.Password != "pw" || p.TUIC.CongestionControl != "bbr" || !p.TUIC.ZeroRTT || p.Security.SNI != "sgp.example.net" {
		t.Fatalf("%+v %+v", p, p.TUIC)
	}
	if p.DisplaySecurity() != "TLS · BBR" || p.DisplayTransport() != "QUIC" {
		t.Fatalf("display: %s / %s", p.DisplaySecurity(), p.DisplayTransport())
	}
	for _, bad := range []string{"tuic://u:p@h:1?version=4", "tuic://u:p@h:1?congestion_control=reno9", "tuic://u@h:1", "tuic://u:p@h:1?udp_relay_mode=x"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s must fail", bad)
		}
	}
}

func TestHysteria1(t *testing.T) {
	r := mustParse(t, "hysteria://hy.example.net:443?protocol=udp&auth=secret&peer=hy.example.net&upmbps=50&downmbps=200&obfs=xplus&obfsParam=ob#Hy1")
	h := r.Profile.Hysteria
	if r.Profile.Protocol != "hysteria" || r.Profile.Password != "secret" || h.UpMbps != 50 || h.DownMbps != 200 || h.Obfs != "xplus" || h.ObfsPassword != "ob" {
		t.Fatalf("%+v %+v", r.Profile, h)
	}
	if r.Profile.Security.ALPN[0] != "hysteria" {
		t.Fatalf("default alpn: %v", r.Profile.Security.ALPN)
	}
	if _, err := Parse("hysteria://h:1?protocol=faketcp&auth=a"); err == nil {
		t.Error("faketcp mode must be rejected")
	}
	if _, err := Parse("hysteria://h:1"); err == nil {
		t.Error("missing auth must be rejected")
	}
}

func TestHysteria2Obfs(t *testing.T) {
	r := mustParse(t, "hy2://pw@h.com:443?obfs=salamander&obfs-password=ob&sni=h.com#O")
	if h := r.Profile.Hysteria; h == nil || h.Obfs != "salamander" || h.ObfsPassword != "ob" {
		t.Fatalf("%+v", r.Profile.Hysteria)
	}
	if _, err := Parse("hy2://pw@h.com:443?obfs=salamander"); err == nil {
		t.Error("obfs without password must fail")
	}
}

func TestAnyTLSAndNaive(t *testing.T) {
	a := mustParse(t, "anytls://pw@a.example.net:443/?sni=a.example.net&idle_session_timeout=30#A")
	if a.Profile.Password != "pw" || a.Profile.Security.SNI != "a.example.net" || a.Profile.AnyTLS.IdleTimeoutSec != 30 {
		t.Fatalf("anytls: %+v", a.Profile)
	}
	n := mustParse(t, "naive+https://user:pa%24s@n.example.net:443?extra-headers=X-A%3A%201%7CX-B%3A%202#N")
	if n.Profile.Protocol != "naive" || n.Profile.Username != "user" || n.Profile.Password != "pa$s" ||
		n.Profile.Naive.ExtraHeaders["X-B"] != "2" || n.Profile.DisplayTransport() != "HTTP/2" {
		t.Fatalf("naive: %+v %+v", n.Profile, n.Profile.Naive)
	}
	if _, err := Parse("naive+quic://u:p@n.example.net:443"); err == nil || !strings.Contains(err.Error(), "QUIC") {
		t.Fatalf("naive+quic: %v", err)
	}
	if _, err := Parse("naive+https://n.example.net:443"); err == nil {
		t.Error("naive without credentials must fail")
	}
}

func TestNewProtocolsRoundTrip(t *testing.T) {
	for _, raw := range []string{
		"wireguard://" + strings.ReplaceAll(wgPriv, "=", "%3D") + "@wg.example.org:51820?publickey=" + strings.ReplaceAll(wgPub, "=", "%3D") +
			"&address=10.7.0.2/32&mtu=1420&reserved=1,2,3&presharedkey=psk&allowedips=0.0.0.0/0&keepalive=25#WG",
		"tuic://u:p@h.com:443?congestion_control=cubic&udp_relay_mode=quic&sni=h.com&reduce_rtt=1#T",
		"tuic://u:p@h.com:443?alpn=h3,spdy/3.1&insecure=1",
		"hysteria://h.com:443?auth=a&upmbps=50&downmbps=200&obfs=xplus&obfsParam=o&peer=h.com#H1",
		"hy2://pw@h.com:443?obfs=salamander&obfs-password=ob#O",
		"hy2://pw@h.com:443?upmbps=50&downmbps=200#B",
		"anytls://pw@a.com:443?sni=a.com&idle_session_timeout=30#A",
		"naive+https://u:p@n.com:443?extra-headers=X-A%3A%201#N",
	} {
		first := mustParse(t, raw)
		enc, ok := Encode(first.Profile, first.Node.Name)
		if !ok {
			t.Fatalf("%.20s: no encoding", raw)
		}
		second := mustParse(t, enc)
		if !reflect.DeepEqual(first.Profile, second.Profile) {
			t.Errorf("%.30s\n first: %+v\nsecond: %+v\n   via: %s", raw, first.Profile, second.Profile, enc)
		}
	}
}

func TestNoLinkProtocolsStoreProfile(t *testing.T) {
	for _, p := range []profile.Profile{
		{Protocol: profile.SSH, Server: "s.com", Port: 22, Username: "root", SSH: &profile.SSHOpts{PrivateKeyPath: "~/.ssh/id_ed25519"}},
		{Protocol: profile.ShadowTLS, Server: "s.com", Port: 443, Cipher: "2022-blake3-aes-128-gcm", Password: "inner",
			ShadowTLS: &profile.ShadowTLSOpts{Version: 3, Password: "outer", SNI: "www.example.com"}},
	} {
		res, err := ProfileNode(p, "")
		if err != nil || res.Node.RawLink != "" || len(res.Node.Profile) == 0 {
			t.Errorf("%s: %+v %v", p.Protocol, res.Node, err)
		}
	}
}

func TestProfileNodeKeepsWhatALinkCannotCarry(t *testing.T) {
	// a TUIC server with an option the tuic:// format has no parameter for
	p := mustParse(t, "tuic://u:p@h.com:443?sni=h.com#T").Profile
	p.Security.Fingerprint = "chrome"
	res, err := ProfileNode(p, "T")
	if err != nil || res.Node.RawLink != "" || len(res.Node.Profile) == 0 {
		t.Fatalf("lossy link must not be used: %+v %v", res.Node, err)
	}
	back, _ := NodeProfile("", res.Node.Profile)
	if back.Security.Fingerprint != "chrome" {
		t.Fatal("profile lost the fingerprint")
	}
}
