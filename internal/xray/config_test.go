package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

func vlessOutbound(flow string) profile.Profile {
	return profile.Profile{
		Protocol: profile.VLESS, Server: "h.com", Port: 443, UUID: "u", Encryption: "none", Flow: flow,
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "tls", SNI: "h.com"},
	}
}

func build(t *testing.T, ob profile.Profile, mut func(*models.Settings)) *Config {
	t.Helper()
	s := models.DefaultSettings()
	if mut != nil {
		mut(&s)
	}
	cfg, err := BuildConfig(profile.Single(ob), s)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func ruleFor(cfg *Config, tag string) *Rule {
	for i := range cfg.Routing.Rules {
		if cfg.Routing.Rules[i].OutboundTag == tag {
			return &cfg.Routing.Rules[i]
		}
	}
	return nil
}

func TestBypassPrivateUsesDirectSitesSetting(t *testing.T) {
	cfg := build(t, vlessOutbound(""), func(s *models.Settings) { s.DirectSites = "geosite:ir, example.org" })
	var domains []string
	for _, r := range cfg.Routing.Rules {
		if r.OutboundTag == "direct" {
			domains = append(domains, r.Domain...)
		}
	}
	joined := strings.Join(domains, ",")
	if !strings.Contains(joined, "geosite:ir") || !strings.Contains(joined, "example.org") || strings.Contains(joined, "geosite:cn") {
		t.Fatalf("DirectSites ignored: %v", cfg.Routing.Rules)
	}
}

func TestBlockAdsHonouredInEveryMode(t *testing.T) {
	for _, mode := range []string{"global", "bypass-private", "custom"} {
		cfg := build(t, vlessOutbound(""), func(s *models.Settings) { s.RoutingMode = mode; s.BlockAds = true })
		if ruleFor(cfg, "block") == nil {
			t.Errorf("%s: blockAds ignored", mode)
		}
		cfg = build(t, vlessOutbound(""), func(s *models.Settings) { s.RoutingMode = mode; s.BlockAds = false })
		if mode != "custom" && ruleFor(cfg, "block") != nil {
			t.Errorf("%s: block rule present although blockAds=false", mode)
		}
	}
}

func TestCustomRoutingOrderAndLists(t *testing.T) {
	cfg := build(t, vlessOutbound(""), func(s *models.Settings) {
		s.RoutingMode, s.ProxySites, s.DirectSites, s.BlockedSites, s.BlockAds = "custom", "a.com", "b.com", "c.com", false
	})
	var tags []string
	for _, r := range cfg.Routing.Rules {
		tags = append(tags, r.OutboundTag)
	}
	if strings.Join(tags, ",") != "block,proxy,direct" {
		t.Fatalf("order = %v", tags)
	}
}

func TestMuxGating(t *testing.T) {
	withMux := func(s *models.Settings) { s.Mux = true; s.MuxConcurrency = 4 }
	if m := build(t, vlessOutbound(""), withMux).Outbounds[0].Mux; m == nil || m.Concurrency != 4 {
		t.Fatalf("mux should be on for plain vless: %+v", m)
	}
	if build(t, vlessOutbound("xtls-rprx-vision"), withMux).Outbounds[0].Mux != nil {
		t.Fatal("mux must be off with vision flow")
	}
	grpc := vlessOutbound("")
	grpc.Transport.Type = "grpc"
	if build(t, grpc, withMux).Outbounds[0].Mux != nil {
		t.Fatal("mux must be off for grpc")
	}
	hy := profile.Profile{Protocol: profile.Hysteria2, Server: "h.com", Port: 443, Password: "p", Security: profile.Security{Kind: "tls"}}
	if build(t, hy, withMux).Outbounds[0].Mux != nil {
		t.Fatal("mux must be off for hysteria")
	}
}

func TestInboundShapes(t *testing.T) {
	cfg := build(t, vlessOutbound(""), func(s *models.Settings) {
		s.Inbounds[0].Username, s.Inbounds[0].Password = "u", "p"
	})
	b, _ := json.Marshal(cfg.Inbounds)
	var ins []map[string]any
	_ = json.Unmarshal(b, &ins)
	if len(ins) != 3 {
		t.Fatalf("inbounds: %d", len(ins))
	}
	socks := ins[0]["settings"].(map[string]any)
	if socks["auth"] != "password" || socks["udp"] != true || socks["accounts"] == nil {
		t.Fatalf("socks settings: %v", socks)
	}
	http := ins[1]["settings"].(map[string]any)
	if _, has := http["udp"]; has {
		t.Fatal("http inbound must not carry a udp option")
	}
	if ins[2]["settings"].(map[string]any)["auth"] != "noauth" {
		t.Fatal("unauthenticated socks should be noauth")
	}
	sniff := ins[0]["sniffing"].(map[string]any)
	if sniff["enabled"] != true {
		t.Fatalf("sniffing: %v", sniff)
	}
}

func TestAllowLANBindsAllInterfaces(t *testing.T) {
	cfg := build(t, vlessOutbound(""), func(s *models.Settings) {
		s.AllowLAN = true
		for i := range s.Inbounds {
			s.Inbounds[i].Username, s.Inbounds[i].Password = "u", "p"
		}
	})
	for _, in := range cfg.Inbounds {
		if in.Listen != "0.0.0.0" {
			t.Fatalf("listen = %s", in.Listen)
		}
	}
}

func TestBuildConfigRefusesInvalidSettings(t *testing.T) {
	s := models.DefaultSettings()
	s.AllowLAN = true // no credentials: would be an open proxy
	if _, err := BuildConfig(profile.Single(vlessOutbound("")), s); err == nil {
		t.Fatal("open proxy config must be refused")
	}
}

func TestUsesGeoData(t *testing.T) {
	if !build(t, vlessOutbound(""), nil).UsesGeoData() {
		t.Fatal("default config uses geosite")
	}
	cfg := build(t, vlessOutbound(""), func(s *models.Settings) {
		s.RoutingMode, s.BlockAds = "global", false
	})
	if cfg.UsesGeoData() {
		t.Fatal("global without block rules needs no geo data")
	}
}

func TestProbeConfigShape(t *testing.T) {
	cfg, err := ProbeConfig(profile.Single(vlessOutbound("")), 4321)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(cfg)
	s := string(b)
	if !strings.Contains(s, `"port":4321`) || !strings.Contains(s, `"tag":"proxy"`) || !strings.Contains(s, `127.0.0.1`) {
		t.Fatalf("probe config: %s", s)
	}
}

func TestSplitList(t *testing.T) {
	got := SplitList(" a, b\n\nc ,, ")
	if strings.Join(got, "|") != "a|b|c" {
		t.Fatalf("%v", got)
	}
}

func tcpHops() (a, b, c profile.Profile) {
	a = profile.Profile{Protocol: profile.VLESS, Server: "a.example.com", Port: 443, UUID: "ua", Security: profile.Security{Kind: "tls", SNI: "a.example.com"}}
	b = profile.Profile{Protocol: profile.Trojan, Server: "b.example.com", Port: 443, Password: "pb", Security: profile.Security{Kind: "tls"}}
	c = profile.Profile{Protocol: profile.Shadowsocks, Server: "c.example.com", Port: 8388, Cipher: "aes-128-gcm", Password: "pc"}
	return
}

func outboundByTag(t *testing.T, cfg *Config, tag string) Outbound {
	t.Helper()
	for _, o := range cfg.Outbounds {
		if o.Tag == tag {
			return o
		}
	}
	t.Fatalf("no outbound %q in %v", tag, cfg.Outbounds)
	return Outbound{}
}

func dialerOf(o Outbound) string {
	if o.StreamSettings != nil && o.StreamSettings.Sockopt != nil {
		return o.StreamSettings.Sockopt.DialerProxy
	}
	return ""
}

func TestChainUsesDialerProxy(t *testing.T) {
	a, b, c := tcpHops()
	cfg, err := BuildConfig(profile.Segment{Hops: []profile.Profile{a, b, c}}, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	// the exit hop is first (the default route), every hop dials through the one before it
	if cfg.Outbounds[0].Tag != "proxy" || cfg.Outbounds[0].Protocol != "shadowsocks" {
		t.Fatalf("exit must be the first outbound: %+v", cfg.Outbounds[0])
	}
	for tag, want := range map[string]string{"hop-0": "", "hop-1": "hop-0", "proxy": "hop-1", "direct": ""} {
		if got := dialerOf(outboundByTag(t, cfg, tag)); got != want {
			t.Errorf("%s dials through %q, want %q", tag, got, want)
		}
	}
	if ss := outboundByTag(t, cfg, "proxy"); ss.StreamSettings == nil || ss.StreamSettings.Network != "tcp" {
		t.Errorf("a protocol without stream settings still needs them to carry the dialer: %+v", ss.StreamSettings)
	}
	if len(cfg.Inbounds) == 0 || cfg.Inbounds[0].Tag != "socks-in" {
		t.Errorf("user inbounds belong on the exit segment: %+v", cfg.Inbounds)
	}
}

func TestSegmentBridges(t *testing.T) {
	a, b, _ := tcpHops()
	up := &profile.Bridge{Port: 31001, User: "bu", Pass: "bp"}
	cfg, err := BuildConfig(profile.Segment{Hops: []profile.Profile{a, b}, Upstream: up}, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if got := dialerOf(outboundByTag(t, cfg, "hop-0")); got != "bridge" {
		t.Errorf("the first hop must dial through the bridge, got %q", got)
	}
	br := outboundByTag(t, cfg, "bridge")
	s := mustJSON(t, br)
	for _, w := range []string{`"protocol":"socks"`, `"address":"127.0.0.1"`, `"port":31001`, `"user":"bu"`, `"pass":"bp"`} {
		if !strings.Contains(s, w) {
			t.Errorf("bridge outbound missing %s: %s", w, s)
		}
	}

	listen := &profile.Bridge{Port: 31002, User: "lu", Pass: "lp"}
	mid, err := BuildConfig(profile.Segment{Hops: []profile.Profile{a}, Listen: listen}, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	if len(mid.Inbounds) != 1 || mid.Inbounds[0].Tag != "bridge-in" || mid.Inbounds[0].Port != 31002 || mid.Inbounds[0].Listen != "127.0.0.1" {
		t.Fatalf("a middle segment serves only its bridge: %+v", mid.Inbounds)
	}
	if in := mustJSON(t, mid.Inbounds[0]); !strings.Contains(in, `"auth":"password"`) || !strings.Contains(in, `"user":"lu"`) {
		t.Errorf("the bridge must require its credentials: %s", in)
	}
	if len(mid.Routing.Rules) != 0 {
		t.Error("a middle segment has no routing rules")
	}
	pc, err := ProbeConfig(profile.Segment{Hops: []profile.Profile{a, b}, Upstream: up}, 4321)
	if err != nil || pc.Inbounds[0].Tag != "probe" || pc.Inbounds[0].Port != 4321 {
		t.Fatalf("probe: %v %+v", err, pc)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestXrayChainsOnlyTCPProtocols(t *testing.T) {
	a, _, _ := tcpHops()
	hy := profile.Profile{Protocol: profile.Hysteria2, Server: "h.com", Port: 443, Password: "p", Security: profile.Security{Kind: "tls"}}
	wg := profile.Profile{Protocol: profile.WireGuard, Server: "w.com", Port: 1, WireGuard: &profile.WireGuardOpts{PrivateKey: "k", PeerPublicKey: "p", LocalAddress: []string{"10.0.0.2/32"}}}
	kcp := a
	kcp.Transport.Type = "kcp"
	xh := a
	xh.Transport = profile.Transport{Type: "xhttp", Path: "/x"}

	ok := [][]profile.Profile{{a}, {a, a}, {xh, a}, {hy}, {wg}}
	for i, hops := range ok {
		if err := SupportsSegment(hops, false); err != nil {
			t.Errorf("case %d must work: %v", i, err)
		}
	}
	if err := SupportsSegment([]profile.Profile{xh}, true); err != nil {
		t.Errorf("an xhttp hop can follow another segment: %v", err)
	}
	for i, c := range []struct {
		hops []profile.Profile
		up   bool
	}{{[]profile.Profile{a, hy}, false}, {[]profile.Profile{wg, a}, false}, {[]profile.Profile{kcp, a}, false}, {[]profile.Profile{hy}, true}, {[]profile.Profile{wg}, true}} {
		if err := SupportsSegment(c.hops, c.up); err == nil || !strings.Contains(err.Error(), "TCP") {
			t.Errorf("case %d must be refused with the reason: %v", i, err)
		}
	}
	if _, err := BuildConfig(profile.Segment{}, models.DefaultSettings()); err == nil {
		t.Error("an empty segment is refused")
	}
}
