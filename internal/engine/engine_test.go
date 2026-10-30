package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// fake supports the listed protocols; maxRun limits how many hops it chains
// in one process (0 = unlimited) and noUpstream makes it refuse a bridge.
type fake struct {
	name       string
	protos     map[string]bool
	maxRun     int
	noUpstream bool
}

func (f fake) Name() string        { return f.name }
func (f fake) DisplayName() string { return f.name }
func (f fake) Supports(p profile.Profile) error {
	if f.protos[p.Protocol] {
		return nil
	}
	return fmt.Errorf("%s cannot run %s", f.name, p.Protocol)
}
func (f fake) SupportsSegment(hops []profile.Profile, up bool) error {
	for _, h := range hops {
		if err := f.Supports(h); err != nil {
			return err
		}
	}
	if f.maxRun > 0 && len(hops) > f.maxRun {
		return fmt.Errorf("%s chains at most %d", f.name, f.maxRun)
	}
	if up && f.noUpstream {
		return fmt.Errorf("%s cannot follow another process", f.name)
	}
	return nil
}
func (fake) Config(profile.Segment, models.Settings) ([]byte, error) { return nil, nil }
func (fake) ProbeConfig(profile.Segment, int) ([]byte, error)        { return nil, nil }
func (fake) Check(context.Context, Install, string) error            { return nil }
func (fake) Launch(Install, string) Launch                           { return Launch{} }

func TestSelect(t *testing.T) {
	x := fake{name: "xray", protos: map[string]bool{"vless": true, "hysteria2": true}}
	sb := fake{name: "sing-box", protos: map[string]bool{"vless": true, "hysteria2": true, "tuic": true}}
	all := []Engine{x, sb}
	both := func(string) bool { return true }
	onlyXray := func(n string) bool { return n == "xray" }

	cases := []struct {
		proto, pref string
		inst        func(string) bool
		want        string
		notInst     bool
	}{
		{"vless", "xray", both, "xray", false},
		{"vless", "sing-box", both, "sing-box", false},
		{"vless", "sing-box", onlyXray, "xray", false}, // preference never beats "not installed"
		{"tuic", "xray", both, "sing-box", false},      // only capable engine wins regardless of preference
		{"tuic", "xray", onlyXray, "sing-box", true},
	}
	for _, c := range cases {
		e, err := Select(profile.Profile{Protocol: c.proto}, c.pref, all, c.inst)
		var ni *NotInstalledError
		if e == nil || e.Name() != c.want || errors.As(err, &ni) != c.notInst {
			t.Errorf("%s pref=%s: got %v, %v", c.proto, c.pref, e, err)
		}
	}
	if _, err := Select(profile.Profile{Protocol: "ssr"}, "xray", all, both); !errors.Is(err, ErrNoEngine) {
		t.Errorf("unsupported protocol: %v", err)
	}
}

func hopsOf(protos ...string) []profile.Profile {
	out := make([]profile.Profile, len(protos))
	for i, p := range protos {
		out[i] = profile.Profile{Protocol: p}
	}
	return out
}

func shape(steps []Step) string {
	var parts []string
	for _, s := range steps {
		parts = append(parts, fmt.Sprintf("%s[%d:%d]", s.Engine.Name(), s.From, s.To))
	}
	return strings.Join(parts, " ")
}

func TestPlanSegments(t *testing.T) {
	x := fake{name: "xray", protos: map[string]bool{"vless": true, "trojan": true, "wireguard": true}, maxRun: 4}
	sb := fake{name: "sing-box", protos: map[string]bool{"vless": true, "trojan": true, "wireguard": true, "openvpn": true, "tuic": true}}
	xOnly := fake{name: "xray", protos: map[string]bool{"vless": true, "xhttp": true}, noUpstream: false}
	all := func(string) bool { return true }

	cases := []struct {
		name    string
		hops    []string
		engines []Engine
		pref    string
		want    string
	}{
		{"one server", []string{"vless"}, []Engine{x, sb}, "xray", "xray[0:1]"},
		{"preference decides a tie", []string{"vless", "trojan"}, []Engine{x, sb}, "sing-box", "sing-box[0:2]"},
		{"longest run wins", []string{"openvpn", "vless", "wireguard"}, []Engine{x, sb}, "xray", "sing-box[0:3]"},
		{"split by engine", []string{"openvpn", "xhttp", "vless"}, []Engine{xOnly, sb}, "xray", "sing-box[0:1] xray[1:3]"},
		{"entry on one engine, rest on another", []string{"xhttp", "openvpn"}, []Engine{xOnly, sb}, "sing-box", "xray[0:1] sing-box[1:2]"},
		{"alternating", []string{"openvpn", "xhttp", "openvpn", "vless"}, []Engine{xOnly, sb}, "sing-box", "sing-box[0:1] xray[1:2] sing-box[2:4]"},
		{"run limit of an engine", []string{"vless", "vless", "vless", "vless", "vless"}, []Engine{x}, "xray", "xray[0:4] xray[4:5]"},
	}
	for _, c := range cases {
		steps, err := PlanSegments(hopsOf(c.hops...), c.pref, c.engines, all)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got := shape(steps); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}

	// an installed engine beats an equally capable one that is not installed
	onlySB := func(n string) bool { return n == "sing-box" }
	steps, err := PlanSegments(hopsOf("vless", "trojan"), "xray", []Engine{x, sb}, onlySB)
	if err != nil || shape(steps) != "sing-box[0:2]" {
		t.Errorf("installed engine must win a tie: %s %v", shape(steps), err)
	}
	// a needed engine that is not installed is reported with the plan
	steps, err = PlanSegments(hopsOf("openvpn", "vless"), "xray", []Engine{x, sb}, func(n string) bool { return n == "xray" })
	var ni *NotInstalledError
	if !errors.As(err, &ni) || ni.Engine.Name() != "sing-box" || shape(steps) != "sing-box[0:2]" {
		t.Errorf("missing engine: %s %v", shape(steps), err)
	}
	// nothing can run a hop: the error names the hop and every engine's reason
	_, err = PlanSegments(hopsOf("vless", "ssh"), "xray", []Engine{x, sb}, all)
	if !errors.Is(err, ErrNoEngine) || !strings.Contains(err.Error(), "hop 2") || !strings.Contains(err.Error(), "xray cannot run ssh") || !strings.Contains(err.Error(), "sing-box cannot run ssh") {
		t.Errorf("unsupported hop: %v", err)
	}
	// an engine that cannot follow another process leaves the hop to one that can
	noUp := fake{name: "xray", protos: map[string]bool{"vless": true, "xhttp": true}, noUpstream: true}
	steps, err = PlanSegments(hopsOf("openvpn", "vless"), "xray", []Engine{noUp, sb}, all)
	if err != nil || shape(steps) != "sing-box[0:2]" {
		t.Errorf("noUpstream: %s %v", shape(steps), err)
	}
	if _, err := PlanSegments(nil, "xray", []Engine{x}, all); err == nil {
		t.Error("an empty chain is refused")
	}
	if EngineNames([]Step{{Engine: sb}, {Engine: x}, {Engine: x}, {Engine: sb}}) != "sing-box + xray + sing-box" {
		t.Error("engine names")
	}
}
