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

// DNS hijacking decides which queries sing-box's own resolver answers, so every
// DNS setting (secure DNS, FakeIP, IPv4-only answers) depends on it. Matching on
// the sniffed protocol alone breaks it whenever sniffing is off: the queries
// then go straight to whatever resolver the system uses, answers and all.
func TestTUNHijacksDNSWithoutSniffing(t *testing.T) {
	seg := profile.Single(goldenProfile())
	seg.TUN = &profile.TUNOptions{Stack: "mixed", MTU: 9000}
	s := models.DefaultSettings()
	s.TUN.Enabled, s.Sniffing = true, false
	cfg, err := BuildConfig(seg, s, ruleSetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range cfg.Route.Rules {
		if r.Action == "hijack-dns" && len(r.Port) == 1 && r.Port[0] == 53 {
			return
		}
	}
	t.Fatalf("with sniffing off, DNS on port 53 is not hijacked: %+v", cfg.Route.Rules)
}

// macOS sends DNS bound to the Wi-Fi interface, around the tunnel, so apps can
// still be handed AAAA records that DNS filtering never sees. The TUN accepts a
// TCP handshake before it routes the connection, so an IPv6 connection that the
// exit cannot carry "succeeds" and is then reset: the app cannot fall back to
// IPv4. Rejecting it up front makes connect() fail, and the app falls back at once.
//
// sing-box can only decide before the handshake while no rule ahead of the
// rejection needs the connection's data, and a sniff rule does. Measured on a
// real TUN: with sniff first the connection was accepted and reset, with the
// rejection ahead of it, refused.
func TestTUNRejectsIPv6ForAnExitWithoutIt(t *testing.T) {
	build := func(sniff bool, hops ...profile.Profile) []Rule {
		seg := profile.Segment{Hops: hops, TUN: &profile.TUNOptions{Stack: "mixed", MTU: 9000, ExcludePaths: []string{"/engine/sing-box"}}}
		s := models.DefaultSettings()
		s.TUN.Enabled, s.Sniffing = true, sniff
		cfg, err := BuildConfig(seg, s, ruleSetPath)
		if err != nil {
			t.Fatal(err)
		}
		return cfg.Route.Rules
	}
	index := func(rules []Rule, match func(Rule) bool) int {
		for i, r := range rules {
			if match(r) {
				return i
			}
		}
		return -1
	}
	isReject6 := func(r Rule) bool { return r.Action == "reject" && r.IPVersion == 6 }
	isSniff := func(r Rule) bool { return r.Action == "sniff" }
	isPort53 := func(r Rule) bool { return r.Action == "hijack-dns" && len(r.Port) == 1 && r.Port[0] == 53 }
	isExclude := func(r Rule) bool { return len(r.ProcessPath) > 0 }
	isPrivate6 := func(r Rule) bool { return r.IPVersion == 6 && r.IPIsPrivate && r.Outbound == "direct" }

	for _, sniff := range []bool{true, false} {
		rules := build(sniff, ovpnProfile())
		rej := index(rules, isReject6)
		if rej < 0 {
			t.Fatalf("sniff=%v: an OpenVPN exit must reject IPv6 in the tunnel: %+v", sniff, rules)
		}
		for name, match := range map[string]func(Rule) bool{"DNS on port 53 is hijacked": isPort53, "the engine's own traffic is excluded": isExclude, "private IPv6 stays direct": isPrivate6} {
			if i := index(rules, match); i < 0 || i > rej {
				t.Errorf("sniff=%v: %s before IPv6 is rejected: want it ahead of index %d, got %d", sniff, name, rej, i)
			}
		}
		if sn := index(rules, isSniff); sniff && (sn < 0 || sn < rej) {
			t.Errorf("sniff rule at %d must come after the rejection at %d, or sing-box accepts the connection first", sn, rej)
		}
		// nothing of the user's routing comes before it either
		for i := 0; i < rej; i++ {
			if r := rules[i]; !isPort53(r) && !isExclude(r) && !isPrivate6(r) {
				t.Errorf("sniff=%v: unexpected rule ahead of the IPv6 rejection: %+v", sniff, r)
			}
		}
	}

	if index(build(true, goldenProfile()), isReject6) >= 0 {
		t.Error("an exit that carries IPv6 must not have it rejected")
	}
	if index(build(true, wgProfile("10.7.0.2/32", "fd00::2/128")), isReject6) >= 0 {
		t.Error("WireGuard with an IPv6 address must not have it rejected")
	}
}
