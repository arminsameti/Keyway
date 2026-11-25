package privileged_test

import (
	"encoding/json"
	"testing"

	"keyway/internal/models"
	"keyway/internal/privileged"
	"keyway/internal/profile"
	"keyway/internal/singbox"
)

// The TUN helper must accept the config of a TUN connection that blocks with
// the filter lists: a local binary rule set and a reject rule.
func TestTUNValidatorAcceptsFilters(t *testing.T) {
	s := models.DefaultSettings()
	s.TUN.Enabled = true
	seg := profile.Single(profile.Profile{Protocol: profile.VLESS, Server: "a.example", Port: 443,
		UUID: "b831381d-6324-4d53-ad4f-8cda48b30811", Transport: profile.Transport{Type: "tcp"},
		Security: profile.Security{Kind: "tls", SNI: "a.example"}})
	seg.TUN = &profile.TUNOptions{Stack: "mixed", MTU: 9000}
	seg.Block = &profile.BlockFiles{SingBoxPath: "/Users/someone/Library/Application Support/Keyway/filters/active/keyway-block.srs"}
	cfg, err := singbox.BuildConfig(seg, s, func(n string) string { return "/rules/" + n + ".srs" })
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := privileged.ValidateConfig(raw); err != nil {
		t.Fatalf("the helper refuses a TUN config with filter lists: %v", err)
	}
}
