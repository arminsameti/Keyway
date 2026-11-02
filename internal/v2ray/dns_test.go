package v2ray

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func dnsPlan(t *testing.T, edit func(*models.Settings)) (models.Settings, models.DNSPlan) {
	t.Helper()
	s := models.DefaultSettings()
	edit(&s)
	p, err := s.DNSPlan()
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestSupportsDNS(t *testing.T) {
	allowed := map[string]func(*models.Settings){
		"default": func(*models.Settings) {},
		"system":  func(s *models.Settings) { s.DNSMode = "system" },
		"secure":  func(s *models.Settings) { s.DNSMode = "secure" },
		"custom": func(s *models.Settings) {
			s.DNSMode, s.DNS = "custom", []string{"9.9.9.9", "https://8.8.8.8/dns-query", "localhost"}
		},
	}
	for name, edit := range allowed {
		s, p := dnsPlan(t, edit)
		if err := SupportsDNS(p); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := BuildConfig(profile.Single(vless()), s); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// "v2ray test" passes all of these. v2ray-core reads tls://1.1.1.1 as a UDP server
	// named "tls://1.1.1.1", cannot look up a DoH server's own host name, and ignores
	// the "tag" and domain-specific resolvers that Keyway uses to steer its queries.
	refused := map[string]func(*models.Settings){
		"dot":         func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"tls://1.1.1.1"} },
		"doh by name": func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"https://dns.google/dns-query"} },
		"direct":      func(s *models.Settings) { s.DNSMode, s.DNSDirect = "secure", "223.5.5.5" },
	}
	for name, edit := range refused {
		s, p := dnsPlan(t, edit)
		if err := SupportsDNS(p); err == nil || !strings.Contains(err.Error(), "Xray core or sing-box") {
			t.Errorf("%s: SupportsDNS = %v", name, err)
		}
		if _, err := BuildConfig(profile.Single(vless()), s); err == nil {
			t.Errorf("%s: BuildConfig must refuse", name)
		}
	}
}

func TestSecureDNSDropsWhatV2RayWouldIgnore(t *testing.T) {
	s, _ := dnsPlan(t, func(s *models.Settings) { s.DNSMode = "secure" })
	b, err := BuildConfig(profile.Single(vless()), s)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{`"https://1.1.1.1/dns-query"`, `"https://8.8.8.8/dns-query"`} {
		if !bytes.Contains(b, []byte(part)) {
			t.Errorf("config lacks %s", part)
		}
	}
	for _, part := range []string{"dns-in", "inboundTag", "skipFallback"} {
		if bytes.Contains(b, []byte(part)) {
			t.Errorf("v2ray-core ignores %q, so it must not be written:\n%s", part, b)
		}
	}
}

func TestSecureDNSInGlobalModeLeavesEmptyRules(t *testing.T) {
	s, _ := dnsPlan(t, func(s *models.Settings) { s.DNSMode, s.RoutingMode, s.BlockAds = "secure", "global", false })
	b, err := BuildConfig(profile.Single(vless()), s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte(`"rules": []`)) {
		t.Errorf("routing rules must stay an empty list, not null:\n%s", b)
	}
}

func TestRefuseXrayKeysCatchesDNSObjects(t *testing.T) {
	doc := `{"dns":{"servers":[{"address":"1.1.1.1","domains":["geosite:cn"],"skipFallback":true}]}}`
	if err := refuseXrayKeys([]byte(doc)); err == nil {
		t.Error("a DNS server object with skipFallback is Xray-only")
	}
}

// TestRealV2RayReadsTheDNSServers starts v2ray-core with each mode and reads the
// resolvers it says it created from its log. "v2ray test" would not do: it passes
// a bogus scheme, which "run" then turns into a UDP server of that name.
//
//	KEYWAY_V2RAY_BIN=/path/to/v2ray go test ./internal/v2ray -run Real
func TestRealV2RayReadsTheDNSServers(t *testing.T) {
	bin := os.Getenv("KEYWAY_V2RAY_BIN")
	if bin == "" {
		t.Skip("KEYWAY_V2RAY_BIN is not set")
	}
	cases := []struct {
		name string
		edit func(*models.Settings)
		want []string
	}{
		{"system", func(s *models.Settings) { s.DNSMode = "system" }, []string{"created localhost client"}},
		{"secure", func(s *models.Settings) { s.DNSMode = "secure" },
			[]string{"created Remote DOH client for https://1.1.1.1/dns-query", "created Remote DOH client for https://8.8.8.8/dns-query"}},
		{"custom", func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"9.9.9.9", "localhost"} },
			[]string{"created UDP client initialized for 9.9.9.9:53", "created localhost client"}},
	}
	for _, c := range cases {
		s := models.DefaultSettings()
		c.edit(&s)
		s.LogLevel = "info"
		s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: freePort(t), Listen: "127.0.0.1", Enabled: true}}
		b, err := BuildConfig(profile.Single(vless()), s)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.json")
		if err := os.WriteFile(cfg, b, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "run", "-c", cfg)
		cmd.Env = append(os.Environ(), "V2RAY_LOCATION_ASSET="+filepath.Dir(bin))
		var log bytes.Buffer
		cmd.Stdout, cmd.Stderr = &log, &log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(1500 * time.Millisecond)
		cmd.Process.Kill()
		cmd.Wait()
		for _, w := range c.want {
			if !strings.Contains(log.String(), w) {
				t.Errorf("%s: log lacks %q:\n%s", c.name, w, log.String())
			}
		}
	}
}
