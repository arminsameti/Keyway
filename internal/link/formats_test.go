package link

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// byName indexes ready items by node name and skipped items by label.
func byName(items []Item) (ready map[string]Item, skipped map[string]string) {
	ready, skipped = map[string]Item{}, map[string]string{}
	for _, it := range items {
		if it.Kind == KindReady {
			ready[it.Result.Node.Name] = it
		} else {
			skipped[it.Label] = it.Reason
		}
	}
	return ready, skipped
}

func TestClashFixture(t *testing.T) {
	text := fixture(t, "clash.yaml")
	if DetectFormat(text) != FormatClash {
		t.Fatalf("format = %s", DetectFormat(text))
	}
	ready, skipped := byName(Classify(text))
	wantProto := map[string]string{
		"🇩🇪 SS 2022": "shadowsocks", "VMess WS": "vmess", "VLESS Reality": "vless", "Trojan gRPC": "trojan",
		"Trojan HTTP obfs": "trojan", "SOCKS": "socks", "HTTPS proxy": "http", "Hy2": "hysteria2", "Hy1": "hysteria",
		"TUIC": "tuic", "WG": "wireguard", "AnyTLS": "anytls", "ShadowTLS": "shadowtls", "SSH": "ssh",
	}
	for name, proto := range wantProto {
		it, ok := ready[name]
		if !ok {
			t.Errorf("%s not ready (skipped: %q)", name, skipped[name])
			continue
		}
		if it.Result.Profile.Protocol != proto {
			t.Errorf("%s: protocol %s, want %s", name, it.Result.Profile.Protocol, proto)
		}
		if err := it.Result.Profile.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(ready) != len(wantProto) {
		t.Errorf("ready = %d, want %d", len(ready), len(wantProto))
	}

	vm := ready["VMess WS"].Result.Profile
	if vm.Transport.Type != "ws" || vm.Transport.Path != "/ws" || vm.Transport.Host != "cdn.example.net" || vm.Security.SNI != "cdn.example.net" {
		t.Errorf("vmess: %+v", vm)
	}
	vl := ready["VLESS Reality"].Result.Profile
	if vl.Security.Kind != "reality" || vl.Security.PublicKey != "PUBKEY" || vl.Flow != "xtls-rprx-vision" {
		t.Errorf("vless: %+v", vl)
	}
	if h := ready["Trojan HTTP obfs"].Result.Profile; h.Transport.Type != "tcp" || h.Transport.HeaderType != "http" || h.Security.Kind != "none" {
		t.Errorf("clash network: http is TCP header obfuscation: %+v", h)
	}
	hy := ready["Hy2"].Result.Profile.Hysteria
	if hy.Obfs != "salamander" || hy.UpMbps != 50 || hy.DownMbps != 200 {
		t.Errorf("hy2: %+v", hy)
	}
	wg := ready["WG"].Result.Profile.WireGuard
	if !reflect.DeepEqual(wg.LocalAddress, []string{"10.7.0.2/32", "fd00::2/128"}) || !reflect.DeepEqual(wg.Reserved, []int{1, 2, 3}) {
		t.Errorf("wg: %+v", wg)
	}
	st := ready["ShadowTLS"].Result
	if st.Profile.ShadowTLS.SNI != "www.example.com" || st.Profile.Password != "inner" || st.Node.RawLink != "" {
		t.Errorf("shadowtls: %+v", st.Profile)
	}
	if ready["SSH"].Result.Profile.SSH.PrivateKeyPath != "~/.ssh/id_ed25519" {
		t.Errorf("ssh key path")
	}

	for label, want := range map[string]string{
		"Legacy SSR (ssr)": "ShadowsocksR is retired", "Snell (snell)": "not supported", "Obfs plugin (ss)": "plugin",
		"Broken (vmess)": "missing user id", "TUIC v4 (tuic)": "TUIC v4",
	} {
		if !strings.Contains(skipped[label], want) {
			t.Errorf("%s: reason %q, want %q", label, skipped[label], want)
		}
	}
}

func TestSingBoxFixture(t *testing.T) {
	text := fixture(t, "singbox.json")
	if DetectFormat(text) != FormatSingBox {
		t.Fatalf("format = %s", DetectFormat(text))
	}
	ready, skipped := byName(Classify(text))
	wantProto := map[string]string{
		"VLESS Reality": "vless", "VMess gRPC": "vmess", "Trojan WS": "trojan", "SS": "shadowsocks", "SOCKS": "socks",
		"HTTP": "http", "Hy2": "hysteria2", "Hy1": "hysteria", "TUIC": "tuic", "AnyTLS": "anytls", "Naive": "naive",
		"SSH": "ssh", "ShadowTLS": "shadowtls", "WG": "wireguard",
	}
	for name, proto := range wantProto {
		it, ok := ready[name]
		if !ok {
			t.Errorf("%s not ready (skipped: %q)", name, skipped[name])
			continue
		}
		if it.Result.Profile.Protocol != proto {
			t.Errorf("%s: protocol %s, want %s", name, it.Result.Profile.Protocol, proto)
		}
	}
	if len(ready) != len(wantProto) {
		t.Errorf("ready = %d, want %d: %v", len(ready), len(wantProto), skipped)
	}
	if _, ok := skipped["direct (direct)"]; ok {
		t.Error("routing outbounds must be ignored silently")
	}
	if _, ok := skipped["stls (shadowtls)"]; ok {
		t.Error("a shadowtls outbound used as detour is folded into its shadowsocks outbound")
	}
	for label, want := range map[string]string{"Tor (tor)": "not supported", "QUIC transport (trojan)": "transport"} {
		if !strings.Contains(strings.ToLower(skipped[label]), want) {
			t.Errorf("%s: reason %q, want %q", label, skipped[label], want)
		}
	}
	st := ready["ShadowTLS"].Result.Profile
	if st.Server != "st.example.net" || st.Port != 443 || st.ShadowTLS.Version != 3 || st.ShadowTLS.Password != "outer" || st.Cipher != "2022-blake3-aes-128-gcm" {
		t.Errorf("shadowtls: %+v %+v", st, st.ShadowTLS)
	}
	wg := ready["WG"].Result.Profile
	if wg.Server != "wg.example.org" || wg.Port != 51820 || wg.WireGuard.Keepalive != 25 || wg.WireGuard.MTU != 1408 {
		t.Errorf("wg endpoint: %+v %+v", wg, wg.WireGuard)
	}
	if tr := ready["Trojan WS"].Result.Profile; !tr.Security.Insecure || tr.Transport.Host != "cdn.example.net" {
		t.Errorf("trojan: %+v", tr)
	}
	if at := ready["AnyTLS"].Result.Profile; at.AnyTLS.IdleTimeoutSec != 30 {
		t.Errorf("anytls idle: %+v", at.AnyTLS)
	}
}

func TestBrokenConfigsAreReportedNotPanics(t *testing.T) {
	for _, text := range []string{"{\"outbounds\": [", "proxies:\n  - [unclosed", "proxies: 7"} {
		items := Classify(text)
		if len(items) == 0 {
			continue // "proxies: 7" decodes to an empty list
		}
		if items[0].Kind != KindSkipped || items[0].Reason == "" {
			t.Errorf("%q: %+v", text, items)
		}
	}
}
