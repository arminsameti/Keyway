package engine

import (
	"errors"
	"testing"

	"keyway/internal/profile"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

func allEngines() []Engine { return []Engine{Xray{}, &SingBox{}, V2Ray{}} }

func vmessHop() profile.Profile {
	return profile.Profile{Protocol: profile.VMess, Server: "a.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"}}
}

func realityHop() profile.Profile {
	return profile.Profile{Protocol: profile.VLESS, Server: "b.example", Port: 443, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"},
		Security:  profile.Security{Kind: "reality", SNI: "b.example", PublicKey: "x", ShortID: "ab"}}
}

func everyInstalled(string) bool { return true }

func TestDefaultPreferenceSkipsV2Ray(t *testing.T) {
	steps, err := PlanSegments([]profile.Profile{vmessHop()}, NameXray, allEngines(), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Engine.Name() != NameXray {
		t.Fatalf("engine = %s", steps[0].Engine.Name())
	}
}

func TestV2RayPreferencePicksSupported(t *testing.T) {
	steps, err := PlanSegments([]profile.Profile{vmessHop()}, NameV2Ray, allEngines(), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Engine.Name() != NameV2Ray {
		t.Fatalf("vmess engine = %s", steps[0].Engine.Name())
	}
	steps, err = PlanSegments([]profile.Profile{realityHop()}, NameV2Ray, allEngines(), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Engine.Name() != NameXray {
		t.Fatalf("reality engine = %s", steps[0].Engine.Name())
	}
}

func TestV2RayPreferenceNotInstalled(t *testing.T) {
	installed := func(n string) bool { return n != NameV2Ray }
	steps, err := PlanSegments([]profile.Profile{vmessHop()}, NameV2Ray, allEngines(), installed, "")
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Engine.Name() != NameXray {
		t.Fatalf("engine = %s", steps[0].Engine.Name())
	}
}

func TestV2RayPreferenceNothingInstalled(t *testing.T) {
	_, err := PlanSegments([]profile.Profile{vmessHop()}, NameV2Ray, allEngines(), func(string) bool { return false }, "")
	var ni *NotInstalledError
	if !errors.As(err, &ni) {
		t.Fatalf("err = %v", err)
	}
}

func TestV2RayMixedChain(t *testing.T) {
	hops := []profile.Profile{vmessHop(), realityHop()}
	steps, err := PlanSegments(hops, NameV2Ray, allEngines(), everyInstalled, "")
	if err != nil {
		t.Fatal(err)
	}
	covered := 0
	for k, st := range steps {
		if st.From != covered {
			t.Fatalf("step %d starts at %d, want %d", k, st.From, covered)
		}
		covered = st.To
		if err := st.Engine.SupportsSegment(st.Hops(hops), st.From > 0); err != nil {
			t.Fatalf("step %d on %s: %v", k, st.Engine.Name(), err)
		}
	}
	if covered != len(hops) {
		t.Fatalf("covered %d of %d hops", covered, len(hops))
	}
}

func TestSelectKeepsXrayNextUnderV2RayPreference(t *testing.T) {
	installed := func(n string) bool { return n != NameV2Ray }
	e, err := Select(vmessHop(), NameV2Ray, allEngines(), installed)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() != NameXray {
		t.Fatalf("engine = %s", e.Name())
	}
}
