package service

import (
	"testing"

	"keyway/internal/engine"
	"keyway/internal/models"
	"keyway/internal/profile"
)

func dnsService() *Service {
	return &Service{engines: []EngineSlot{{Engine: engine.Xray{}}, {Engine: &engine.SingBox{}}, {Engine: engine.V2Ray{}}}}
}

func vmessProfile() profile.Profile {
	return profile.Profile{Protocol: profile.VMess, Server: "a.example", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Transport: profile.Transport{Type: "tcp"}}
}

func TestPreviewDNS(t *testing.T) {
	st := models.DefaultSettings()
	st.DNSMode = "secure"
	last := profile.Single(vmessProfile())
	middle := last
	middle.Listen = &profile.Bridge{Port: 20001, User: "u", Pass: "p"}

	if got := previewDNS(st, engine.NameSingBox, last); got != st.EffectiveDNS("sing-box") || got == "" {
		t.Errorf("last segment: %q", got)
	}
	if got := previewDNS(st, engine.NameV2Ray, last); got != st.EffectiveDNS("v2ray") {
		t.Errorf("v2ray: %q", got)
	}
	if got := previewDNS(st, engine.NameXray, middle); got != "" {
		t.Errorf("a middle segment answers nobody's lookups: %q", got)
	}
	if got := previewDNS(st, engine.NameTor, last); got != "" {
		t.Errorf("Tor does no DNS of its own: %q", got)
	}
}

func TestEngineListFollowsTheDNSSettings(t *testing.T) {
	s := dnsService()
	everything := func(string) bool { return true }
	run := func(pref string) string {
		t.Helper()
		e, err := runsOn(vmessProfile(), nil, pref, s.engineList(), everything)
		if err != nil {
			t.Fatal(err)
		}
		return e.Name()
	}
	if got := run(engine.NameV2Ray); got != engine.NameV2Ray {
		t.Fatalf("before any DNS setting: %s", got)
	}

	st := models.DefaultSettings()
	st.DNSMode, st.DNS = "custom", []string{"tls://9.9.9.9"}
	s.setDNS(st)
	if got := run(engine.NameV2Ray); got != engine.NameSingBox {
		t.Errorf("DNS over TLS: %s", got)
	}

	st.DNSMode, st.DNS, st.DNSDirect = "secure", nil, "223.5.5.5"
	s.setDNS(st)
	if got := run(engine.NameV2Ray); got != engine.NameXray {
		t.Errorf("a direct resolver: %s", got)
	}

	s.setDNS(models.DefaultSettings())
	if got := run(engine.NameV2Ray); got != engine.NameV2Ray {
		t.Errorf("back to the default: %s", got)
	}
}
