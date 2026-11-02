package singbox

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

// TestRealSingBoxChecksTheDNSConfigs runs "sing-box check" over a config of
// every DNS mode:
//
//	KEYWAY_SINGBOX_BIN=/path/to/sing-box go test ./internal/singbox -run Real
func TestRealSingBoxChecksTheDNSConfigs(t *testing.T) {
	bin := os.Getenv("KEYWAY_SINGBOX_BIN")
	if bin == "" {
		t.Skip("KEYWAY_SINGBOX_BIN is not set")
	}
	dir := t.TempDir()
	// the rule sets the routing refers to, compiled from tiny sources
	for _, name := range []string{"geosite-private", "geosite-cn", "geosite-category-ads-all"} {
		src := filepath.Join(dir, name+".json")
		if err := os.WriteFile(src, []byte(`{"version":3,"rules":[{"domain_suffix":["example"]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "rule-set", "compile", "--output", filepath.Join(dir, name+".srs"), src).CombinedOutput(); err != nil {
			t.Fatalf("compile %s: %v\n%s", name, err, out)
		}
	}
	path := func(name string) string { return filepath.Join(dir, name+".srs") }

	cases := map[string]func(*models.Settings){
		"default": func(*models.Settings) {},
		"system":  func(s *models.Settings) { s.DNSMode = "system" },
		"secure":  func(s *models.Settings) { s.DNSMode = "secure" },
		"custom": func(s *models.Settings) {
			s.DNSMode, s.DNS = "custom", []string{"tls://dns.google:853", "9.9.9.9"}
		},
		"custom doh": func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"https://dns.google/dns-query"} },
		"direct":     func(s *models.Settings) { s.DNSMode, s.DNSDirect = "secure", "https://223.5.5.5/dns-query" },
		"direct custom routing": func(s *models.Settings) {
			s.RoutingMode, s.DirectSites = "custom", "domain:a.example, geosite:cn, keyword:x"
			s.DNSMode, s.DNSDirect = "custom", "tls://223.5.5.5"
			s.DNS = []string{"1.1.1.1"}
		},
		"fakeip": func(s *models.Settings) { s.TUN.Enabled, s.FakeIP = true, true },
		"fakeip secure": func(s *models.Settings) {
			s.TUN.Enabled, s.FakeIP, s.DNSMode, s.DNSDirect = true, true, "secure", "223.5.5.5"
		},
	}
	for name, edit := range cases {
		s := models.DefaultSettings()
		edit(&s)
		seg := profile.Single(goldenProfile())
		if s.TUN.Enabled {
			seg.TUN = &profile.TUNOptions{Stack: "mixed", MTU: 9000}
		}
		cfg, err := BuildConfig(seg, s, path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		file := filepath.Join(dir, "config.json")
		if err := os.WriteFile(file, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bin, "check", "-c", file).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s\n%s", name, err, out, b)
		}
	}
}
