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
	cfg, err := BuildConfig(ob, s)
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
	if _, err := BuildConfig(vlessOutbound(""), s); err == nil {
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
	cfg, err := ProbeConfig(vlessOutbound(""), 4321)
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
