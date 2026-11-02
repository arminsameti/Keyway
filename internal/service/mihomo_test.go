package service

import (
	"slices"
	"testing"

	"keyway/internal/engine"
	"keyway/internal/profile"
)

func TestEngineProtocolsMihomo(t *testing.T) {
	got := engineProtocols(engine.Mihomo{})
	want := []string{"VLESS", "VMess", "Trojan", "Shadowsocks", "Hysteria2", "WireGuard", "SOCKS", "HTTP", "TUIC", "AnyTLS"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}

// Adding Mihomo to the list must not change what the other engines list.
func TestEngineProtocolsOfTheOthersAreUnchanged(t *testing.T) {
	if got, want := engineProtocols(engine.V2Ray{}), []string{"VLESS", "VMess", "Trojan", "Shadowsocks", "SOCKS", "HTTP"}; !slices.Equal(got, want) {
		t.Fatalf("v2ray: %v", got)
	}
	if got := engineProtocols(engine.Xray{}); !slices.Contains(got, "WireGuard") || !slices.Contains(got, "Trojan") || slices.Contains(got, "TUIC") {
		t.Fatalf("xray: %v", got)
	}
}

func mihomoEngines() []engine.Engine {
	return []engine.Engine{engine.Xray{}, &engine.SingBox{}, engine.V2Ray{}, engine.Mihomo{}}
}

func TestDefaultPreferenceNeverShowsMihomo(t *testing.T) {
	onlyMihomo := func(n string) bool { return n == engine.NameMihomo }
	e, err := runsOn(testVMess(), nil, "xray", mihomoEngines(), onlyMihomo)
	if err != nil {
		t.Fatal(err)
	}
	if e.Name() == engine.NameMihomo {
		t.Fatal("the server list would say Mihomo runs a server although the preference is Xray")
	}
	steps, err := planShown([]profile.Profile{testVMess()}, "xray", mihomoEngines(), onlyMihomo, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.EngineNames(steps); got == "Mihomo" {
		t.Fatalf("plan = %s", got)
	}
}

func TestMihomoPreferenceIsShown(t *testing.T) {
	e, err := runsOn(testVMess(), nil, engine.NameMihomo, mihomoEngines(), allInstalled)
	if err != nil || e.Name() != engine.NameMihomo || e.DisplayName() != "Mihomo" {
		t.Fatalf("engine = %v, %v", e, err)
	}
	// not downloaded yet: the plan still names it, so the app can say so
	steps, err := planShown([]profile.Profile{testVMess()}, engine.NameMihomo, mihomoEngines(), func(n string) bool { return n != engine.NameMihomo }, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.EngineNames(steps); got == "Mihomo" {
		t.Fatalf("an engine that is not installed was shown as the one that runs: %s", got)
	}
}

// Mihomo's /connections answers with the same totals as sing-box's Clash API,
// which is what the traffic meter reads.
func TestParseMihomoConnections(t *testing.T) {
	const out = `{"downloadTotal":647,"uploadTotal":584,"connections":[],"memory":31260672}`
	up, down, err := parseSingBoxConnections([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if up != 584 || down != 647 {
		t.Fatalf("up %d down %d", up, down)
	}
}
