package profile

import "testing"

func TestOverridesEngineValidate(t *testing.T) {
	for _, good := range []string{"", "xray", "sing-box", "v2ray", "mihomo", "tor", " sing-box "} {
		if err := (&Overrides{Engine: good}).Validate(); err != nil {
			t.Fatalf("engine %q: %v", good, err)
		}
	}
	if err := (&Overrides{Engine: "bad"}).Validate(); err == nil {
		t.Fatal("bad engine accepted")
	}
}

func TestOverridesEngineIsZero(t *testing.T) {
	if !(&Overrides{}).IsZero() {
		t.Fatal("empty overrides not zero")
	}
	if (&Overrides{Engine: "  "}).IsZero() == false {
		t.Fatal("whitespace engine should count as zero")
	}
	if (&Overrides{Engine: "xray"}).IsZero() {
		t.Fatal("pinned engine counts as non-zero")
	}
}

func TestPinnedEngine(t *testing.T) {
	var o *Overrides
	if o.PinnedEngine() != "" {
		t.Fatal("nil overrides should pin nothing")
	}
	if got := (&Overrides{Engine: " sing-box "}).PinnedEngine(); got != "sing-box" {
		t.Fatalf("pin = %q", got)
	}
	p := Profile{Protocol: VMess, Overrides: &Overrides{Engine: "v2ray"}}
	if p.PinnedEngine() != "v2ray" {
		t.Fatalf("profile pin = %q", p.PinnedEngine())
	}
}
