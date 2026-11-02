package xray

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

// TestRealXrayAcceptsTheDNSConfigs runs "xray -test" over a config of every DNS
// mode. It needs a binary and the geo data next to it (or in KEYWAY_XRAY_ASSETS):
//
//	KEYWAY_XRAY_BIN=$(which xray) go test ./internal/xray -run Real
func TestRealXrayAcceptsTheDNSConfigs(t *testing.T) {
	bin := os.Getenv("KEYWAY_XRAY_BIN")
	if bin == "" {
		t.Skip("KEYWAY_XRAY_BIN is not set")
	}
	assets := os.Getenv("KEYWAY_XRAY_ASSETS")
	if assets == "" {
		assets = filepath.Dir(bin)
	}
	cases := map[string]func(*models.Settings){
		"default": func(*models.Settings) {},
		"system":  func(s *models.Settings) { s.DNSMode = "system" },
		"secure":  func(s *models.Settings) { s.DNSMode = "secure" },
		"custom": func(s *models.Settings) {
			s.DNSMode, s.DNS = "custom", []string{"https://dns.google/dns-query", "9.9.9.9", "localhost"}
		},
		"direct": func(s *models.Settings) { s.DNSMode, s.DNSDirect = "secure", "https://223.5.5.5/dns-query" },
		"direct custom routing": func(s *models.Settings) {
			s.RoutingMode, s.DirectSites = "custom", "domain:a.example, geosite:cn"
			s.DNSMode, s.DNSDirect = "custom", "223.5.5.5"
		},
	}
	for name, edit := range cases {
		s := models.DefaultSettings()
		edit(&s)
		seg := profile.Single(goldenProfile())
		seg.Stats = &profile.StatsAPI{Port: 20000}
		cfg, err := BuildConfig(seg, s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := json.Marshal(cfg)
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := Test(context.Background(), bin, path, assets); err != nil {
			t.Errorf("%s: %v\n%s", name, err, b)
		}
	}
}
