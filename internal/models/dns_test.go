package models

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDNSServer(t *testing.T) {
	ok := map[string]DNSServer{
		"1.1.1.1":                         {Kind: DNSPlain, Host: "1.1.1.1"},
		" 2606:4700:4700::1111 ":          {Kind: DNSPlain, Host: "2606:4700:4700::1111"},
		"LocalHost":                       {Kind: DNSLocal, Host: "localhost"},
		"https://dns.google/dns-query":    {Kind: DNSHTTPS, Host: "dns.google", Path: "/dns-query"},
		"https://1.1.1.1":                 {Kind: DNSHTTPS, Host: "1.1.1.1", Path: "/dns-query"},
		"https://dns.example:8443/q":      {Kind: DNSHTTPS, Host: "dns.example", Port: 8443, Path: "/q"},
		"https://[2606:4700:4700::1111]/": {Kind: DNSHTTPS, Host: "2606:4700:4700::1111", Path: "/"},
		"tls://1.1.1.1":                   {Kind: DNSTLS, Host: "1.1.1.1"},
		"tls://dns.google:853":            {Kind: DNSTLS, Host: "dns.google", Port: 853},
	}
	for in, want := range ok {
		got, err := ParseDNSServer(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		want.Raw = strings.TrimSpace(in)
		if got != want {
			t.Errorf("%q: got %+v, want %+v", in, got, want)
		}
	}
	bad := []string{
		"", "   ", "dns.google", "1.1.1.1:53", "http://1.1.1.1/dns-query", "quic://1.1.1.1", "tcp://1.1.1.1", "https://",
		"https://user@dns.google/dns-query", "https://dns.google/dns-query?x=1", "https://dns.google/#f", "tls://dns.google/path",
		"https://bad_host/dns-query", "https://dns.google:0/dns-query", "https://dns.google:70000/dns-query",
		"https://dns.google/dns query", "1.1.1.1 8.8.8.8", "https://" + strings.Repeat("a", 64) + ".example/", strings.Repeat("a", 600),
		"https://-bad.example/", "tls://", "999.1.1.1",
	}
	for _, in := range bad {
		if _, err := ParseDNSServer(in); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
}

func TestDNSServerString(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1":                         "1.1.1.1",
		"localhost":                       "localhost",
		"https://dns.google":              "https://dns.google/dns-query",
		"https://dns.example:8443/q":      "https://dns.example:8443/q",
		"https://[2606:4700:4700::1111]/": "https://[2606:4700:4700::1111]/",
		"tls://dns.google:853":            "tls://dns.google:853",
	} {
		d, err := ParseDNSServer(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := d.String(); got != want {
			t.Errorf("%q: String() = %q, want %q", in, got, want)
		}
	}
}

func dnsValid(t *testing.T, s Settings) error {
	t.Helper()
	s.Normalize()
	return s.Validate()
}

func TestDNSSettingsValidate(t *testing.T) {
	with := func(f func(*Settings)) Settings {
		s := DefaultSettings()
		f(&s)
		return s
	}
	good := map[string]Settings{
		"defaults":   DefaultSettings(),
		"unset mode": with(func(s *Settings) { s.DNSMode = "" }),
		"system":     with(func(s *Settings) { s.DNSMode = "system" }),
		"secure":     with(func(s *Settings) { s.DNSMode = "secure" }),
		"custom": with(func(s *Settings) {
			s.DNSMode, s.DNS = "custom", []string{"1.1.1.1", "https://dns.google/dns-query", "tls://9.9.9.9"}
		}),
		"direct ip":          with(func(s *Settings) { s.DNSMode, s.DNSDirect = "secure", "223.5.5.5" }),
		"direct doh ip":      with(func(s *Settings) { s.DNSMode, s.DNSDirect = "secure", "https://223.5.5.5/dns-query" }),
		"direct dot ip":      with(func(s *Settings) { s.DNSMode, s.DNSDirect = "custom", "tls://223.5.5.5"; s.DNS = []string{"1.1.1.1"} }),
		"legacy odd entry":   with(func(s *Settings) { s.DNS = []string{"https+local://1.1.1.1/dns-query", "8.8.8.8:53"} }),
		"fakeip without tun": with(func(s *Settings) { s.FakeIP = true }),
	}
	for name, s := range good {
		if err := dnsValid(t, s); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]Settings{
		"unknown mode":     with(func(s *Settings) { s.DNSMode = "magic" }),
		"custom empty":     with(func(s *Settings) { s.DNSMode, s.DNS = "custom", nil }),
		"custom bad entry": with(func(s *Settings) { s.DNSMode, s.DNS = "custom", []string{"1.1.1.1", "dns.google"} }),
		"custom http":      with(func(s *Settings) { s.DNSMode, s.DNS = "custom", []string{"http://1.1.1.1/dns-query"} }),
		"too many": with(func(s *Settings) {
			s.DNS = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "9.9.9.10", "4.2.2.1", "4.2.2.2", "4.2.2.3"}
		}),
		"whitespace":         with(func(s *Settings) { s.DNS = []string{"1.1.1.1 8.8.8.8"} }),
		"direct hostname":    with(func(s *Settings) { s.DNSMode, s.DNSDirect = "secure", "dns.alidns.com" }),
		"direct doh host":    with(func(s *Settings) { s.DNSMode, s.DNSDirect = "secure", "https://dns.alidns.com/dns-query" }),
		"direct localhost":   with(func(s *Settings) { s.DNSMode, s.DNSDirect = "secure", "localhost" }),
		"direct garbage":     with(func(s *Settings) { s.DNSDirect = "not a server" }),
		"direct unused mode": with(func(s *Settings) { s.DNSMode, s.DNSDirect = "system", "tcp://1.1.1.1" }),
	}
	for name, s := range bad {
		err := dnsValid(t, s)
		var ve *ValidationError
		if err == nil || !errors.As(err, &ve) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
}

func TestDNSNormalize(t *testing.T) {
	s := DefaultSettings()
	s.DNSMode, s.DNSDirect = "", "  223.5.5.5 "
	s.Normalize()
	if s.DNSMode != "default" || s.DNSDirect != "223.5.5.5" {
		t.Errorf("got mode %q direct %q", s.DNSMode, s.DNSDirect)
	}
	s.DNSMode = " Secure "
	s.Normalize()
	if s.DNSMode != "secure" {
		t.Errorf("mode = %q", s.DNSMode)
	}
	if DefaultSettings().DNSMode != "default" {
		t.Error("the default mode must be default")
	}
}

func TestDNSPlan(t *testing.T) {
	plan := func(f func(*Settings)) DNSPlan {
		t.Helper()
		s := DefaultSettings()
		f(&s)
		p, err := s.DNSPlan()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if p := plan(func(*Settings) {}); !p.IsDefault() || len(p.Servers) != 0 {
		t.Errorf("defaults: %+v", p)
	}
	if p := plan(func(s *Settings) { s.DNSMode = "" }); !p.IsDefault() {
		t.Errorf("unset mode must be the default: %+v", p)
	}
	if p := plan(func(s *Settings) { s.DNSMode = "system" }); p.IsDefault() || len(p.Servers) != 1 || p.Servers[0].Kind != DNSLocal {
		t.Errorf("system: %+v", p)
	}
	p := plan(func(s *Settings) { s.DNSMode = "secure"; s.DNS = []string{"9.9.9.9"} })
	if len(p.Servers) != 2 || p.Servers[0].Kind != DNSHTTPS || p.Servers[0].Host != "1.1.1.1" {
		t.Errorf("secure must ignore the custom list and use the built-in DoH servers: %+v", p)
	}
	p = plan(func(s *Settings) {
		s.DNSMode = "custom"
		s.DNS = []string{"tls://9.9.9.9", "localhost"}
		s.DNSDirect = "223.5.5.5"
	})
	if len(p.Servers) != 2 || p.Servers[0].Kind != DNSTLS || p.Direct == nil || p.Direct.Host != "223.5.5.5" {
		t.Errorf("custom: %+v", p)
	}
	if p := plan(func(s *Settings) { s.DNSMode = "system"; s.DNSDirect = "223.5.5.5" }); p.Direct != nil {
		t.Errorf("a direct resolver only applies to secure and custom DNS: %+v", p.Direct)
	}
	if p := plan(func(s *Settings) { s.FakeIP = true }); p.FakeIP || !p.IsDefault() {
		t.Errorf("FakeIP needs TUN: %+v", p)
	}
	if p := plan(func(s *Settings) { s.FakeIP, s.TUN.Enabled = true, true }); !p.FakeIP || p.IsDefault() {
		t.Errorf("FakeIP with TUN: %+v", p)
	}
	s := DefaultSettings()
	s.DNSMode, s.DNS = "custom", []string{"nonsense"}
	if _, err := s.DNSPlan(); err == nil {
		t.Error("an unparsable custom server must be an error, never skipped")
	}
}

func TestEffectiveDNS(t *testing.T) {
	s := DefaultSettings()
	for engine, want := range map[string]string{
		"xray":     "Default: 1.1.1.1, 8.8.8.8, localhost",
		"v2ray":    "Default: 1.1.1.1, 8.8.8.8, localhost",
		"sing-box": "Default: the system resolver",
	} {
		if got := s.EffectiveDNS(engine); got != want {
			t.Errorf("%s: %q, want %q", engine, got, want)
		}
	}
	s.DNSMode = "system"
	if got := s.EffectiveDNS("xray"); got != "System: the system resolver" {
		t.Error(got)
	}
	s.DNSMode, s.DNSDirect = "secure", "223.5.5.5"
	got := s.EffectiveDNS("sing-box")
	for _, part := range []string{"Secure DNS", "https://1.1.1.1/dns-query", "through the proxy", "bypassed domains", "223.5.5.5"} {
		if !strings.Contains(got, part) {
			t.Errorf("%q lacks %q", got, part)
		}
	}
	if got := s.EffectiveDNS("v2ray"); !strings.Contains(got, "routing rules") || strings.Contains(got, "through the proxy") {
		t.Errorf("v2ray cannot pin the proxy: %q", got)
	}
	s.DNSMode, s.DNSDirect, s.DNS = "custom", "", []string{"tls://9.9.9.9", "8.8.8.8"}
	got = s.EffectiveDNS("sing-box")
	if !strings.Contains(got, "tls://9.9.9.9") || !strings.Contains(got, "only the first") || strings.Contains(got, "8.8.8.8,") {
		t.Errorf("sing-box has no failover; it must say which server it uses: %q", got)
	}
	if got := s.EffectiveDNS("xray"); strings.Contains(got, "only the first") {
		t.Errorf("Xray asks them all: %q", got)
	}
	s.DNS = []string{"tls://9.9.9.9"}
	s.TUN.Enabled, s.FakeIP = true, true
	if got := s.EffectiveDNS("sing-box"); !strings.Contains(got, "tls://9.9.9.9") || !strings.Contains(got, "FakeIP") {
		t.Error(got)
	}
}
