package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func dnsConfig(t *testing.T, seg profile.Segment, edit func(*models.Settings)) *Config {
	t.Helper()
	s := models.DefaultSettings()
	edit(&s)
	cfg, err := BuildConfig(seg, s)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func dnsJSON(t *testing.T, cfg *Config) string {
	t.Helper()
	b, err := json.Marshal(cfg.DNS)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSystemDNS(t *testing.T) {
	cfg := dnsConfig(t, profile.Single(goldenProfile()), func(s *models.Settings) { s.DNSMode = "system" })
	if got := dnsJSON(t, cfg); got != `{"servers":["localhost"]}` {
		t.Errorf("dns = %s", got)
	}
	base := dnsConfig(t, profile.Single(goldenProfile()), func(*models.Settings) {})
	if len(cfg.Routing.Rules) != len(base.Routing.Rules) {
		t.Errorf("system DNS must not add routing rules, got %d", len(cfg.Routing.Rules))
	}
}

func TestSecureDNSGoesThroughTheProxy(t *testing.T) {
	cfg := dnsConfig(t, profile.Single(goldenProfile()), func(s *models.Settings) { s.DNSMode = "secure" })
	want := `{"servers":["https://1.1.1.1/dns-query","https://8.8.8.8/dns-query"],"tag":"dns-in"}`
	if got := dnsJSON(t, cfg); got != want {
		t.Errorf("dns = %s", got)
	}
	r := cfg.Routing.Rules[0]
	if len(r.InboundTag) != 1 || r.InboundTag[0] != DNSTag || r.OutboundTag != "proxy" || r.Domain != nil || r.IP != nil {
		t.Errorf("the DNS queries must be pinned to the proxy by the first rule: %+v", r)
	}
}

func TestCustomDNSKeepsTheStatsRuleFirst(t *testing.T) {
	seg := profile.Single(goldenProfile())
	seg.Stats = &profile.StatsAPI{Port: 20000}
	cfg := dnsConfig(t, seg, func(s *models.Settings) {
		s.DNSMode, s.DNS = "custom", []string{"https://dns.google/dns-query", "9.9.9.9"}
	})
	if got := dnsJSON(t, cfg); got != `{"servers":["https://dns.google/dns-query","9.9.9.9"],"tag":"dns-in"}` {
		t.Errorf("dns = %s", got)
	}
	if cfg.Routing.Rules[0].InboundTag[0] != StatsTag || cfg.Routing.Rules[1].InboundTag[0] != DNSTag {
		t.Errorf("rules = %+v", cfg.Routing.Rules)
	}
}

func TestDirectResolverServesTheBypassedDomains(t *testing.T) {
	cfg := dnsConfig(t, profile.Single(goldenProfile()), func(s *models.Settings) {
		s.DNSMode, s.DNSDirect = "secure", "https://223.5.5.5/dns-query"
	})
	want := `{"servers":[{"address":"https://223.5.5.5/dns-query","domains":["geosite:private","geosite:cn"],"skipFallback":true},` +
		`"https://1.1.1.1/dns-query","https://8.8.8.8/dns-query"],"tag":"dns-in"}`
	if got := dnsJSON(t, cfg); got != want {
		t.Errorf("dns = %s", got)
	}
	first, second := cfg.Routing.Rules[0], cfg.Routing.Rules[1]
	if first.InboundTag[0] != DNSTag || first.OutboundTag != "direct" || len(first.IP) != 1 || first.IP[0] != "223.5.5.5" {
		t.Errorf("the direct resolver must be reached directly: %+v", first)
	}
	if second.InboundTag[0] != DNSTag || second.OutboundTag != "proxy" {
		t.Errorf("everything else goes through the proxy: %+v", second)
	}
}

func TestDirectResolverFollowsTheRoutingRules(t *testing.T) {
	cfg := dnsConfig(t, profile.Single(goldenProfile()), func(s *models.Settings) {
		s.RoutingMode, s.DirectSites = "custom", "domain:a.example, full:b.example, 10.0.0.0/8"
		s.DNSMode, s.DNSDirect = "custom", "223.5.5.5"
	})
	srv, ok := cfg.DNS.Servers[0].(DNSServer)
	if !ok || strings.Join(srv.Domains, " ") != "domain:a.example full:b.example" {
		t.Errorf("only domain matchers of the direct rules belong to the direct resolver: %+v", cfg.DNS.Servers[0])
	}
	cfg = dnsConfig(t, profile.Single(goldenProfile()), func(s *models.Settings) {
		s.RoutingMode, s.DNSMode, s.DNSDirect = "global", "custom", "223.5.5.5"
	})
	if got := dnsJSON(t, cfg); strings.Contains(got, "223.5.5.5") {
		t.Errorf("nothing is bypassed in global mode, so there is nothing for a direct resolver to do: %s", got)
	}
}

func TestMiddleSegmentKeepsTheDefaultDNS(t *testing.T) {
	seg := profile.Single(goldenProfile())
	seg.Listen = &profile.Bridge{Port: 20001, User: "u", Pass: "p"}
	cfg := dnsConfig(t, seg, func(s *models.Settings) { s.DNSMode = "secure" })
	if got := dnsJSON(t, cfg); got != `{"servers":["1.1.1.1","8.8.8.8","localhost"]}` || len(cfg.Routing.Rules) != 0 {
		t.Errorf("a middle segment serves nobody's lookups: dns %s, rules %+v", got, cfg.Routing.Rules)
	}
}

func TestDNSOverTLSNeedsAnotherEngine(t *testing.T) {
	// Xray reads tls://1.1.1.1 as a plain UDP server named "tls://1.1.1.1" and says nothing.
	s := models.DefaultSettings()
	s.DNSMode, s.DNS = "custom", []string{"1.1.1.1", "tls://9.9.9.9"}
	plan, err := s.DNSPlan()
	if err != nil {
		t.Fatal(err)
	}
	if err := SupportsDNS(plan); err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Errorf("SupportsDNS = %v", err)
	}
	if _, err := BuildConfig(profile.Single(goldenProfile()), s); err == nil {
		t.Error("BuildConfig must refuse DNS over TLS")
	}
	s.DNSMode, s.DNS, s.DNSDirect = "secure", nil, "tls://223.5.5.5"
	if _, err := BuildConfig(profile.Single(goldenProfile()), s); err == nil {
		t.Error("BuildConfig must refuse a DNS over TLS direct resolver")
	}
	s.DNSMode, s.DNS, s.DNSDirect = "custom", []string{"https://dns.google/dns-query", "9.9.9.9"}, "223.5.5.5"
	plan, _ = s.DNSPlan()
	if err := SupportsDNS(plan); err != nil {
		t.Error(err)
	}
}
