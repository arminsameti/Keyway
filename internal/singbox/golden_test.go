package singbox

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

func ruleSetPath(name string) string { return "/rules/" + name + ".srs" }

func TestGoldenDefaultConfigs(t *testing.T) {
	custom := models.DefaultSettings()
	custom.RoutingMode, custom.ProxySites, custom.DirectSites = "custom", "domain:a.example", "geosite:cn, domain:b.example"
	global := models.DefaultSettings()
	global.RoutingMode, global.DNS = "global", []string{"9.9.9.9", "https://dns.google/dns-query"}
	tun := models.DefaultSettings()
	tun.TUN.Enabled = true

	one := profile.Single(goldenProfile())
	stats := one
	stats.Stats = &profile.StatsAPI{Port: 20000, Secret: "s"}
	middle := one
	middle.Listen = &profile.Bridge{Port: 20001, User: "u", Pass: "p"}
	tunSeg := one
	tunSeg.TUN = &profile.TUNOptions{Stack: "mixed", MTU: 9000, ExcludePaths: []string{"/engines/xray"}}
	relay := profile.Segment{Upstream: &profile.Bridge{Port: 20002, User: "u", Pass: "p"}}

	cases := []struct {
		name string
		seg  profile.Segment
		s    models.Settings
	}{
		{"default", one, models.DefaultSettings()},
		{"default-stats", stats, models.DefaultSettings()},
		{"default-middle", middle, models.DefaultSettings()},
		{"default-relay", relay, models.DefaultSettings()},
		{"routing-custom", one, custom},
		{"routing-global-own-dns", one, global},
		{"tun", tunSeg, tun},
	}
	for _, c := range cases {
		cfg, err := BuildConfig(c.seg, c.s, ruleSetPath)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		b, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "singbox-"+c.name, append(b, '\n'))
	}
	probe, err := ProbeConfig(one, 20003)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.MarshalIndent(probe, "", "  ")
	golden(t, "singbox-probe", append(b, '\n'))
}
