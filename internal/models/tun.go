package models

// TUNSettings captures all of the Mac's traffic with a virtual network
// interface instead of relying on programs to honour the system proxy. It needs
// administrator rights, which the user grants either on every connect or once.
type TUNSettings struct {
	Enabled   bool   `json:"enabled"`
	Privilege string `json:"privilege"` // prompt: ask on every connect | helper: allow once, no more prompts
	Stack     string `json:"stack"`     // mixed | system | gvisor
	MTU       int    `json:"mtu"`
	Strict    bool   `json:"strict"` // strict_route: also stop apps from bypassing the tunnel through other interfaces
}

var (
	tunPrivileges = map[string]bool{"prompt": true, "helper": true}
	tunStacks     = map[string]bool{"mixed": true, "system": true, "gvisor": true}
)

func (t *TUNSettings) normalize() {
	if t.Privilege == "" {
		t.Privilege = "prompt"
	}
	if t.Stack == "" {
		t.Stack = "mixed"
	}
	if t.MTU == 0 {
		t.MTU = 9000
	}
}

func (t TUNSettings) validate(add func(string, ...any)) {
	if !tunPrivileges[t.Privilege] {
		add("TUN privilege must be prompt or helper")
	}
	if !tunStacks[t.Stack] {
		add("TUN stack must be mixed, system or gvisor")
	}
	if t.MTU < 576 || t.MTU > 65535 {
		add("TUN MTU must be 576-65535, got %d", t.MTU)
	}
}
