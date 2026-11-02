package singbox

import (
	"encoding/json"
	"strings"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func dnsBuild(t *testing.T, seg profile.Segment, edit func(*models.Settings)) *Config {
	t.Helper()
	s := models.DefaultSettings()
	edit(&s)
	cfg, err := BuildConfig(seg, s, ruleSetPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func dnsOf(t *testing.T, cfg *Config) string {
	t.Helper()
	b, err := json.Marshal(cfg.DNS)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const localServer = `{"type":"local","tag":"local"}`

func TestSystemDNSIsTheDefault(t *testing.T) {
	seg := profile.Single(goldenProfile())
	base := dnsOf(t, dnsBuild(t, seg, func(*models.Settings) {}))
	if got := dnsOf(t, dnsBuild(t, seg, func(s *models.Settings) { s.DNSMode = "system" })); got != base {
		t.Errorf("dns = %s, want %s", got, base)
	}
}

func TestSecureDNSAsksTheFirstServerThroughTheProxy(t *testing.T) {
	cfg := dnsBuild(t, profile.Single(goldenProfile()), func(s *models.Settings) { s.DNSMode = "secure" })
	want := `{"servers":[` + localServer + `,{"type":"https","tag":"dns-0","server":"1.1.1.1","path":"/dns-query","detour":"proxy"}],"final":"dns-0"}`
	if got := dnsOf(t, cfg); got != want {
		t.Errorf("dns = %s", got)
	}
	if cfg.Route.DefaultDomainResolver != "local" {
		t.Errorf("the server's own host name must still resolve without the proxy, got %q", cfg.Route.DefaultDomainResolver)
	}
}

func TestCustomDNSKinds(t *testing.T) {
	for in, want := range map[string]string{
		"9.9.9.9":                        `{"type":"udp","tag":"dns-0","server":"9.9.9.9","detour":"proxy"}`,
		"tls://dns.google:853":           `{"type":"tls","tag":"dns-0","server":"dns.google","server_port":853,"detour":"proxy"}`,
		"tls://9.9.9.9":                  `{"type":"tls","tag":"dns-0","server":"9.9.9.9","detour":"proxy"}`,
		"https://dns.example:8443/q":     `{"type":"https","tag":"dns-0","server":"dns.example","server_port":8443,"path":"/q","detour":"proxy"}`,
		"https://[2606:4700:4700::1111]": `{"type":"https","tag":"dns-0","server":"2606:4700:4700::1111","path":"/dns-query","detour":"proxy"}`,
	} {
		cfg := dnsBuild(t, profile.Single(goldenProfile()), func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{in} })
		w := `{"servers":[` + localServer + `,` + want + `],"final":"dns-0"}`
		if got := dnsOf(t, cfg); got != w {
			t.Errorf("%s:\n got %s\nwant %s", in, got, w)
		}
	}
	cfg := dnsBuild(t, profile.Single(goldenProfile()), func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"localhost", "9.9.9.9"} })
	if got := dnsOf(t, cfg); got != `{"servers":[`+localServer+`],"final":"local"}` {
		t.Errorf("localhost first: %s", got)
	}
}

func TestDirectResolverAnswersForBypassedDomains(t *testing.T) {
	cfg := dnsBuild(t, profile.Single(goldenProfile()), func(s *models.Settings) {
		s.DNSMode, s.DNSDirect = "secure", "tls://223.5.5.5"
	})
	want := `{"servers":[` + localServer + `,{"type":"https","tag":"dns-0","server":"1.1.1.1","path":"/dns-query","detour":"proxy"},` +
		`{"type":"tls","tag":"dns-direct","server":"223.5.5.5"}],` +
		`"rules":[{"rule_set":["geosite-private","geosite-cn"],"action":"route","server":"dns-direct"}],"final":"dns-0"}`
	if got := dnsOf(t, cfg); got != want {
		t.Errorf("dns = %s", got)
	}

	cfg = dnsBuild(t, profile.Single(goldenProfile()), func(s *models.Settings) {
		s.RoutingMode, s.DirectSites = "custom", "domain:a.example, full:b.example, keyword:c, 10.0.0.0/8, geoip:cn"
		s.DNSMode, s.DNSDirect = "custom", "223.5.5.5"
	})
	got := dnsOf(t, cfg)
	for _, part := range []string{`"domain_suffix":["a.example"]`, `"domain":["b.example"]`, `"domain_keyword":["c"]`, `"server":"dns-direct"`} {
		if !strings.Contains(got, part) {
			t.Errorf("dns lacks %s: %s", part, got)
		}
	}
	if strings.Contains(got, "10.0.0.0") || strings.Contains(got, "geoip") {
		t.Errorf("IP matchers cannot select a DNS server: %s", got)
	}

	cfg = dnsBuild(t, profile.Single(goldenProfile()), func(s *models.Settings) {
		s.RoutingMode, s.DNSMode, s.DNSDirect = "global", "custom", "223.5.5.5"
	})
	if got := dnsOf(t, cfg); strings.Contains(got, "dns-direct") {
		t.Errorf("nothing is bypassed in global mode: %s", got)
	}
}

func TestFakeIPOnlyWithTUN(t *testing.T) {
	tun := profile.Single(goldenProfile())
	tun.TUN = &profile.TUNOptions{Stack: "mixed", MTU: 9000}
	edit := func(s *models.Settings) { s.TUN.Enabled, s.FakeIP = true, true }
	cfg := dnsBuild(t, tun, edit)
	want := `{"servers":[` + localServer + `,{"type":"fakeip","tag":"fakeip","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}],` +
		`"rules":[{"query_type":["A","AAAA"],"action":"route","server":"fakeip"}],"final":"local"}`
	if got := dnsOf(t, cfg); got != want {
		t.Errorf("dns = %s", got)
	}

	plain := dnsBuild(t, profile.Single(goldenProfile()), edit) // no TUN in this process
	if got := dnsOf(t, plain); strings.Contains(got, "fakeip") {
		t.Errorf("FakeIP without the tunnel would hand out addresses nothing translates back: %s", got)
	}

	cfg = dnsBuild(t, tun, func(s *models.Settings) { edit(s); s.DNSMode, s.DNSDirect = "secure", "223.5.5.5" })
	got := dnsOf(t, cfg)
	direct, fake := strings.Index(got, `"server":"dns-direct"}`), strings.Index(got, `"server":"fakeip"}`)
	if direct < 0 || fake < 0 || direct > fake || !strings.Contains(got, `"final":"dns-0"`) {
		t.Errorf("the direct resolver's rule must come before the FakeIP rule, and real lookups use the chosen server: %s", got)
	}
}

func TestMiddleSegmentAndProbeKeepTheDefaultDNS(t *testing.T) {
	middle := profile.Single(goldenProfile())
	middle.Listen = &profile.Bridge{Port: 20001, User: "u", Pass: "p"}
	cfg := dnsBuild(t, middle, func(s *models.Settings) { s.DNSMode = "secure" })
	if got := dnsOf(t, cfg); got != `{"servers":[`+localServer+`],"final":"local"}` {
		t.Errorf("middle segment: %s", got)
	}
}
