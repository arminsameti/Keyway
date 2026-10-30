package engine

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// fake supports the listed protocols.
type fake struct {
	name   string
	protos map[string]bool
}

func (f fake) Name() string        { return f.name }
func (f fake) DisplayName() string { return f.name }
func (f fake) Supports(p profile.Profile) error {
	if f.protos[p.Protocol] {
		return nil
	}
	return fmt.Errorf("%s cannot run %s", f.name, p.Protocol)
}
func (fake) Config(profile.Profile, models.Settings) ([]byte, error) { return nil, nil }
func (fake) ProbeConfig(profile.Profile, int) ([]byte, error)        { return nil, nil }
func (fake) Check(context.Context, Install, string) error            { return nil }
func (fake) Launch(Install, string) Launch                           { return Launch{} }

func TestSelect(t *testing.T) {
	x := fake{"xray", map[string]bool{"vless": true, "hysteria2": true}}
	sb := fake{"sing-box", map[string]bool{"vless": true, "hysteria2": true, "tuic": true}}
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
