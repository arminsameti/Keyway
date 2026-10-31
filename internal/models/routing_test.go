package models

import (
	"strings"
	"testing"
)

func TestEntryKind(t *testing.T) {
	for entry, want := range map[string]string{
		"domain:a.com": KindDomain, "full:a.com": KindDomain, "keyword:ads": KindDomain, "geosite:cn": KindDomain, "plainword": KindDomain,
		"geoip:cn": KindIP, "10.0.0.0/8": KindIP, "1.2.3.4": KindIP, "::1": KindIP,
		"port:80,443,8000-9000": KindPort, "process:Slack": KindProcess, "process-path:/Applications/My App.app/x": KindProcess,
	} {
		if got, err := EntryKind(entry); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", entry, got, err, want)
		}
	}
	for _, bad := range []string{"", "domain:", "geoip:", "port:0", "port:99999", "port:9-3", "port:a", "nope:thing", "two words", "process:"} {
		if _, err := EntryKind(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestRuleSetValidation(t *testing.T) {
	s := DefaultSettings()
	s.RoutingMode = "rules"
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "choose a rule set") {
		t.Errorf("rules mode without a set: %v", err)
	}
	s.RuleSets = []RuleSet{{ID: "a", Name: "x", Rules: []RouteRule{{ID: "1", Enabled: true, Outbound: "direct", Entries: []string{"domain:a.com"}}}}}
	s.ActiveRuleSet = "a"
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	s.RuleSets[0].Rules[0].Outbound = "somewhere"
	s.RuleSets[0].Rules[0].Entries = []string{"port:x"}
	err := s.Validate()
	if err == nil || !strings.Contains(err.Error(), "outbound must be") || !strings.Contains(err.Error(), "bad port") {
		t.Errorf("every problem should be reported: %v", err)
	}
	if n := len(s.Clone().RuleSets[0].Rules[0].Entries); n != 1 {
		t.Error("clone lost entries")
	}
	c := s.Clone()
	c.RuleSets[0].Rules[0].Entries[0] = "changed"
	if s.RuleSets[0].Rules[0].Entries[0] == "changed" {
		t.Error("Clone must be deep")
	}
}

func TestMatchRoute(t *testing.T) {
	rules := []RouteRule{
		{ID: "a", Enabled: true, Outbound: "block", Entries: []string{"keyword:ads"}},
		{ID: "b", Enabled: true, Outbound: "direct", Entries: []string{"geosite:cn", "domain:example.com", "192.168.0.0/16", "port:22"}},
		{ID: "off", Enabled: false, Outbound: "block", Entries: []string{"domain:other.com"}},
	}
	for _, c := range []struct {
		host string
		port int
		want string
		rule string
	}{
		{"ads.tracker.net", 443, "block", "a"},
		{"www.example.com", 443, "direct", "b"},
		{"badexample.com", 443, "proxy", ""}, // domain: is a suffix at a dot boundary
		{"192.168.4.5", 80, "direct", "b"},
		{"git.example.org", 22, "direct", "b"},
		{"other.com", 443, "proxy", ""}, // disabled rule
	} {
		m := MatchRoute(rules, c.host, c.port)
		if m.Outbound != c.want || m.RuleID != c.rule {
			t.Errorf("%s:%d -> %+v, want %s via %q", c.host, c.port, m, c.want, c.rule)
		}
	}
	if m := MatchRoute(rules, "unlisted.org", 443); len(m.Unknown) != 1 || m.Unknown[0] != "geosite:cn" {
		t.Errorf("geosite entries must be reported as unknown: %+v", m)
	}
}

func TestParseRulesClashAndXray(t *testing.T) {
	rules, skipped, err := ParseRules("rules:\n  - DOMAIN-SUFFIX,google.com,PROXY\n  - DOMAIN-KEYWORD,ads,REJECT\nGEOIP,CN,DIRECT\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nMATCH,PROXY\nDST-PORT,22,DIRECT\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].Outbound != "proxy" || rules[1].Outbound != "block" || len(rules[2].Entries) != 3 {
		t.Fatalf("rules = %+v", rules)
	}
	if rules[2].Entries[0] != "geoip:cn" || rules[2].Entries[2] != "port:22" || len(skipped) != 1 || skipped[0] != "MATCH,PROXY" {
		t.Errorf("entries %v, skipped %v", rules[2].Entries, skipped)
	}
	x, _, err := ParseRules(`{"rules":[{"type":"field","domain":["geosite:cn"],"outboundTag":"direct"},{"type":"field","ip":["geoip:private"],"port":"80,443","outboundTag":"direct"},{"domain":["x.com"],"outboundTag":"weird"}]}`)
	if err != nil || len(x) != 1 || len(x[0].Entries) != 3 {
		t.Fatalf("xray import = %+v, %v", x, err)
	}
	if _, _, err := ParseRules("   "); err == nil {
		t.Error("empty input must fail")
	}
	if _, _, err := ParseRules("{broken"); err == nil {
		t.Error("broken JSON must fail")
	}
}
