package link

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"xray-friendly/internal/profile"
)

func TestEncodeRoundTrips(t *testing.T) {
	ss := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("2022-blake3-aes-128-gcm:p@ss:word")) + "@[2001:db8::1]:8388#SS"
	for _, raw := range []string{
		"vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEY&sid=ab12&spx=%2F&flow=xtls-rprx-vision&type=tcp#Reality",
		"vless://u@h.com:443?security=tls&type=xhttp&path=/x&host=h&mode=auto&alpn=h2,http/1.1&allowInsecure=1#X",
		"vless://u@h.com:443?security=none&type=kcp&headerType=wechat-video&seed=s",
		"trojan://pa%3As@t.com:443?type=grpc&serviceName=svc&mode=multi&sni=t.com#Tr%20G",
		"trojan://p@t.com:80?security=none&type=tcp&headerType=http&host=a.com,b.com&path=/p",
		vmessLink(t, map[string]any{"ps": "ws", "add": "ex.com", "port": "443", "id": "uuid-1", "aid": "2",
			"net": "ws", "host": "cdn.ex.com", "path": "/p", "tls": "tls", "sni": "sni.ex.com", "scy": "aes-128-gcm"}),
		vmessLink(t, map[string]any{"ps": "g", "add": "ex.com", "port": 443, "id": "u", "net": "grpc", "path": "svc", "type": "multi", "tls": "tls"}),
		ss,
		"socks5://user:pw@10.0.0.1:1081#S",
		"socks5://10.0.0.1:1080",
		"hy2://s%3Acret@h.com:8443?sni=h.com&pinSHA256=" + strings.Repeat("ab", 32) + "#H",
		"hysteria2://s@h.com:443?insecure=1",
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
		if second.Node.Name != first.Node.Name {
			t.Errorf("name %q -> %q", first.Node.Name, second.Node.Name)
		}
	}
}

func TestProfileNode(t *testing.T) {
	// a link-capable protocol becomes an ordinary link node
	res, err := ProfileNode(profile.Profile{Protocol: profile.Trojan, Server: "t.com", Port: 443, Password: "pw",
		Security: profile.Security{Kind: "tls", SNI: "t.com"}}, "Manual")
	if err != nil || res.Node.RawLink == "" || res.Node.Profile != nil || res.Node.Name != "Manual" {
		t.Fatalf("trojan: %+v %v", res.Node, err)
	}
	// HTTP has no share-link format: the profile is stored
	hp := profile.Profile{Protocol: profile.HTTP, Server: "p.com", Port: 8080, Username: "u", Password: "p"}
	res, err = ProfileNode(hp, "")
	if err != nil || res.Node.RawLink != "" || len(res.Node.Profile) == 0 || res.Node.ID == "" {
		t.Fatalf("http: %+v %v", res.Node, err)
	}
	back, err := NodeProfile(res.Node.RawLink, res.Node.Profile)
	if err != nil || !reflect.DeepEqual(back, hp) {
		t.Fatalf("stored profile: %+v %v", back, err)
	}
	if _, err := ProfileNode(profile.Profile{Protocol: profile.VLESS, Server: "h.com", Port: 443}, "x"); err == nil {
		t.Fatal("invalid profile must be refused")
	}
}
