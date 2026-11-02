package engine

import (
	"strings"
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func planFor(t *testing.T, edit func(*models.Settings)) models.DNSPlan {
	t.Helper()
	s := models.DefaultSettings()
	edit(&s)
	p, err := s.DNSPlan()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestForDNSMovesAServerToTheEngineThatCanHonourIt(t *testing.T) {
	dot := planFor(t, func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"tls://9.9.9.9"} })
	engines := ForDNS(allEngines(), dot)
	for _, pref := range []string{NameXray, NameV2Ray} {
		steps, err := PlanSegments([]profile.Profile{vmessHop()}, pref, engines, everyInstalled, "")
		if err != nil {
			t.Fatal(err)
		}
		if steps[0].Engine.Name() != NameSingBox {
			t.Errorf("preferring %s with DNS over TLS: engine = %s", pref, steps[0].Engine.Name())
		}
	}
	if e, err := Select(vmessHop(), NameXray, engines, everyInstalled); err != nil || e.Name() != NameSingBox {
		t.Errorf("Select = %v, %v", e, err)
	}

	direct := planFor(t, func(s *models.Settings) { s.DNSMode, s.DNSDirect = "secure", "223.5.5.5" })
	steps, err := PlanSegments([]profile.Profile{vmessHop()}, NameV2Ray, ForDNS(allEngines(), direct), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Engine.Name() != NameXray {
		t.Errorf("a direct resolver leaves v2ray-core for Xray core, got %s", steps[0].Engine.Name())
	}
}

func TestForDNSKeepsEveryEngineWhenNothingIsInTheWay(t *testing.T) {
	for _, edit := range []func(*models.Settings){
		func(*models.Settings) {},
		func(s *models.Settings) { s.DNSMode = "system" },
		func(s *models.Settings) { s.DNSMode = "secure" },
	} {
		steps, err := PlanSegments([]profile.Profile{vmessHop()}, NameV2Ray, ForDNS(allEngines(), planFor(t, edit)), everyInstalled, "")
		if err != nil || steps[0].Engine.Name() != NameV2Ray {
			t.Errorf("steps %v, err %v", steps, err)
		}
	}
}

func TestForDNSSaysWhyWhenNoEngineIsLeft(t *testing.T) {
	// Reality needs Xray, DNS over TLS rules Xray out, and sing-box has no xhttp.
	dot := planFor(t, func(s *models.Settings) { s.DNSMode, s.DNS = "custom", []string{"tls://9.9.9.9"} })
	hop := realityHop()
	hop.Transport.Type = "xhttp"
	_, err := PlanSegments([]profile.Profile{hop}, NameXray, ForDNS(allEngines(), dot), everyInstalled, "")
	if err == nil || !strings.Contains(err.Error(), "DNS over TLS") {
		t.Errorf("err = %v", err)
	}
}

func TestForDNSKeepsTheOptionalInterfaces(t *testing.T) {
	// sing-box downloads rule sets and sets its build tags; wrapping it would hide both.
	engines := ForDNS(allEngines(), planFor(t, func(s *models.Settings) { s.DNSMode = "secure" }))
	for _, e := range engines {
		if e.Name() != NameSingBox {
			continue
		}
		if _, ok := e.(RuleSetUser); !ok {
			t.Error("sing-box lost RuleSetUser")
		}
		if _, ok := e.(TagAware); !ok {
			t.Error("sing-box lost TagAware")
		}
	}
}
