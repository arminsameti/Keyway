package service

import (
	"testing"

	"keyway/internal/engine"
	"keyway/internal/profile"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func testEngines() []engine.Engine {
	return []engine.Engine{engine.Xray{}, &engine.SingBox{}, engine.V2Ray{}}
}

func testVMess() profile.Profile {
	return profile.Profile{Protocol: profile.VMess, Server: "a.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "tls", SNI: "a.example"}}
}

func allInstalled(string) bool { return true }

func TestRunsOnAppliesOverrides(t *testing.T) {
	ov := &profile.Overrides{Fingerprint: "chrome"}
	e, err := runsOn(testVMess(), ov, engine.NameV2Ray, testEngines(), allInstalled)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != engine.NameXray {
		t.Fatalf("engine = %s", e.Name())
	}
}

func TestRunsOnNamesTheInstalledEngine(t *testing.T) {
	installed := func(n string) bool { return n != engine.NameV2Ray }
	e, err := runsOn(testVMess(), nil, engine.NameV2Ray, testEngines(), installed)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != engine.NameXray {
		t.Fatalf("engine = %s", e.Name())
	}
}

func TestRunsOnNothingInstalled(t *testing.T) {
	e, err := runsOn(testVMess(), nil, engine.NameV2Ray, testEngines(), func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != engine.NameV2Ray {
		t.Fatalf("engine = %s", e.Name())
	}
}

func TestPlanShownNamesTheInstalledEngine(t *testing.T) {
	installed := func(n string) bool { return n != engine.NameV2Ray }
	hops := []profile.Profile{testVMess(), testVMess()}
	steps, err := planShown(hops, engine.NameV2Ray, testEngines(), installed, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.EngineNames(steps); got != "Xray core" {
		t.Fatalf("plan = %s", got)
	}
}

func TestPlanShownNothingInstalled(t *testing.T) {
	steps, err := planShown([]profile.Profile{testVMess()}, engine.NameV2Ray, testEngines(), func(string) bool { return false }, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.EngineNames(steps); got != "V2Ray core" {
		t.Fatalf("plan = %s", got)
	}
}
