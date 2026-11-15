package tor

import (
	"testing"

	"keyway/internal/profile"
)

func TestBootstrapLimit(t *testing.T) {
	direct := profile.Segment{Hops: []profile.Profile{{Protocol: profile.Tor, Tor: &profile.TorOpts{Bridges: profile.TorBridgeNone}}}}
	bridged := profile.Segment{Hops: []profile.Profile{{Protocol: profile.Tor, Tor: &profile.TorOpts{Bridges: profile.TorBridgeObfs4}}}}
	chained := profile.Segment{
		Hops:     []profile.Profile{{Protocol: profile.Tor, Tor: &profile.TorOpts{Bridges: profile.TorBridgeNone}}},
		Upstream: &profile.Bridge{Port: 1080, User: "u", Pass: "p"},
	}
	chainedBridged := profile.Segment{
		Hops:     []profile.Profile{{Protocol: profile.Tor, Tor: &profile.TorOpts{Bridges: profile.TorBridgeObfs4}}},
		Upstream: &profile.Bridge{Port: 1080, User: "u", Pass: "p"},
	}
	for _, tc := range []struct {
		name string
		seg  profile.Segment
		want string
	}{
		{"direct Tor gets the short budget", direct, "1m0s"},
		{"bridged Tor gets the long budget", bridged, "2m0s"},
		{"chained Tor gets the long budget", chained, "2m0s"},
		{"chained bridged Tor gets the long budget", chainedBridged, "2m0s"},
	} {
		if got := bootstrapLimit(tc.seg).String(); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}
