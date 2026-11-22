package singbox

import (
	"testing"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func ovpnProfile() profile.Profile {
	return profile.Profile{Protocol: profile.OpenVPN, Server: "vpn.example", Port: 1194, Username: "u", Password: "p",
		Transport: profile.Transport{Type: "udp"}, OpenVPN: &profile.OpenVPNOpts{CA: "CA"}}
}

func wgProfile(local ...string) profile.Profile {
	return profile.Profile{Protocol: profile.WireGuard, Server: "wg.example", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "k", PeerPublicKey: "pk", LocalAddress: local}}
}

func dnsStrategy(t *testing.T, hops ...profile.Profile) string {
	t.Helper()
	seg := profile.Segment{Hops: hops, TUN: &profile.TUNOptions{Stack: "mixed", MTU: 9000}}
	s := models.DefaultSettings()
	s.TUN.Enabled = true
	cfg, err := BuildConfig(seg, s, ruleSetPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg.DNS.Strategy
}

// The TUN carries IPv6 (so nothing leaks), and apps then ask for AAAA records
// and connect over IPv6. An exit without an IPv6 address rejects those
// connections ("missing IPv6 local address"), which the app sees as a reset on
// every site it does not retry over IPv4. DNS must not offer IPv6 to such an exit.
func TestDNSStaysIPv4OnAnExitWithoutIPv6(t *testing.T) {
	cases := []struct {
		name string
		hops []profile.Profile
		want string
	}{
		{"openvpn exit", []profile.Profile{ovpnProfile()}, "ipv4_only"},
		{"openvpn behind a proxy", []profile.Profile{goldenProfile(), ovpnProfile()}, "ipv4_only"},
		{"wireguard with only an IPv4 address", []profile.Profile{wgProfile("10.7.0.2/32")}, "ipv4_only"},
		{"wireguard with both families", []profile.Profile{wgProfile("10.7.0.2/32", "fd00::2/128")}, ""},
		{"a proxy exit resolves for itself", []profile.Profile{goldenProfile()}, ""},
		{"a proxy after openvpn dials names itself", []profile.Profile{ovpnProfile(), goldenProfile()}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dnsStrategy(t, c.hops...); got != c.want {
				t.Errorf("dns strategy = %q, want %q", got, c.want)
			}
		})
	}
}
