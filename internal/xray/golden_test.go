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

func TestGoldenFilters(t *testing.T) {
	seg := profile.Single(goldenProfile())
	seg.Block = &profile.BlockFiles{SingBoxPath: "/data/filters/active/keyway-block.json"}
	cfg, err := BuildConfig(seg, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "xray-routing-filters", append(b, '\n'))
}

func TestFiltersAddToExistingBlockRule(t *testing.T) {
	seg := profile.Single(goldenProfile())
	seg.Block = &profile.BlockFiles{}
	s := models.DefaultSettings()
	s.BlockedSites = "domain:ads.example"
	cfg, err := BuildConfig(seg, s)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Routing.Rules[0]
	if got.OutboundTag != "block" || len(got.Domain) != 2 || got.Domain[0] != "domain:ads.example" || got.Domain[1] != "ext:keyway-block.dat:block" {
		t.Errorf("block rule = %+v", got)
	}
	// Block ads off: no filter reference even if a Block is passed
	s.BlockAds = false
	cfg, err = BuildConfig(seg, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range cfg.Routing.Rules {
		for _, d := range r.Domain {
			if d == "ext:keyway-block.dat:block" {
				t.Errorf("filter referenced with Block ads off: %+v", r)
			}
		}
	}
}

func TestNoFiltersUnchanged(t *testing.T) {
	seg := profile.Single(goldenProfile()) // Block == nil
	cfg, err := BuildConfig(seg, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	golden(t, "xray-default", append(b, '\n'))
}
