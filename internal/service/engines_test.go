package service

import (
	"slices"
	"testing"

	"keyway/internal/engine"
)

func TestEngineProtocolsV2Ray(t *testing.T) {
	got := engineProtocols(engine.V2Ray{})
	want := []string{"VLESS", "VMess", "Trojan", "Shadowsocks", "SOCKS", "HTTP"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}
