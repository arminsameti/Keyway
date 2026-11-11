package engine

import (
	"errors"
	"testing"

	"keyway/internal/profile"
)

func pinnedVMess(pin string) profile.Profile {
	p := vmessHop()
	if pin != "" {
		p.Overrides = &profile.Overrides{Engine: pin}
	}
	return p
}

func TestSelectHonoursPinOverGlobalPreference(t *testing.T) {
	e, err := Select(pinnedVMess("sing-box"), NameXray, allEngines(), everyInstalled)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != NameSingBox {
		t.Fatalf("engine = %s", e.Name())
	}
}

func TestSelectPinOptInAllowedWhenGlobalDiffers(t *testing.T) {
	e, err := Select(pinnedVMess("v2ray"), NameXray, allEngines(), everyInstalled)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != NameV2Ray {
		t.Fatalf("engine = %s", e.Name())
	}
}

func TestSelectPinIncompatibleFails(t *testing.T) {
	tuic := profile.Profile{Protocol: profile.TUIC, Server: "a.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "quic"}}
	tuic.Overrides = &profile.Overrides{Engine: NameXray}
	if _, err := Select(tuic, NameXray, allEngines(), everyInstalled); err == nil {
		t.Fatal("incompatible pin accepted")
	} else if !errors.Is(err, ErrNoEngine) {
		t.Fatalf("err = %v", err)
	}
}

func TestSelectPinUnknownEngineFails(t *testing.T) {
	p := pinnedVMess("bad-engine")
	if _, err := Select(p, NameXray, allEngines(), everyInstalled); err == nil {
		t.Fatal("unknown pin accepted")
	}
}

func TestPlanHonoursConflictingPins(t *testing.T) {
	h1 := pinnedVMess("xray")
	h2 := pinnedVMess("sing-box")
	steps, err := PlanSegments([]profile.Profile{h1, h2}, NameXray, allEngines(), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("steps = %d, want 2 (pins conflict)", len(steps))
	}
	if steps[0].Engine.Name() != NameXray || steps[1].Engine.Name() != NameSingBox {
		t.Fatalf("plan = %s", EngineNames(steps))
	}
}

func TestPlanPinExtendsWhenCapable(t *testing.T) {
	h1 := vmessHop()
	h2 := pinnedVMess("sing-box")
	steps, err := PlanSegments([]profile.Profile{h1, h2}, NameXray, allEngines(), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || steps[0].Engine.Name() != NameSingBox {
		t.Fatalf("plan = %s, want single sing-box run", EngineNames(steps))
	}
}
