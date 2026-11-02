package xray

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got with testdata/<name>.json. The files pin the generated
// configuration of settings that never touched the DNS controls: a change here
// means every existing user's config changed.
func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(got) {
		t.Errorf("%s changed.\nwant:\n%s\ngot:\n%s", path, want, got)
	}
}

func goldenProfile() profile.Profile {
	return profile.Profile{Protocol: profile.VLESS, Server: "a.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "tls", SNI: "a.example"}}
}

func TestGoldenDefaultConfigs(t *testing.T) {
	custom := models.DefaultSettings()
	custom.RoutingMode, custom.ProxySites, custom.DirectSites = "custom", "domain:a.example", "geosite:cn, domain:b.example"
	global := models.DefaultSettings()
	global.RoutingMode, global.DNS = "global", []string{"9.9.9.9", "https://dns.google/dns-query"}
	rules := models.DefaultSettings()
	rules.RoutingMode = "rules"
	rules.RuleSets = []models.RuleSet{{ID: "r", Name: "r", Rules: []models.RouteRule{
		{ID: "1", Enabled: true, Entries: []string{"domain:c.example", "1.2.3.4"}, Outbound: "direct"}}}}
	rules.ActiveRuleSet = "r"
	legacyEmpty := models.DefaultSettings()
	legacyEmpty.DNS = nil // a store from before the DNS list existed

	one := profile.Single(goldenProfile())
	stats := one
	stats.Stats = &profile.StatsAPI{Port: 20000}
	middle := one
	middle.Listen = &profile.Bridge{Port: 20001, User: "u", Pass: "p"}

	cases := []struct {
		name string
		seg  profile.Segment
		s    models.Settings
	}{
		{"default", one, models.DefaultSettings()},
		{"default-stats", stats, models.DefaultSettings()},
		{"default-middle", middle, models.DefaultSettings()},
		{"routing-custom", one, custom},
		{"routing-global-own-dns", one, global},
		{"routing-rules", one, rules},
		{"dns-list-empty", one, legacyEmpty},
	}
	for _, c := range cases {
		cfg, err := BuildConfig(c.seg, c.s)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "xray-"+c.name, append(b, '\n'))
	}
}
