package profile

import (
	"fmt"
	"strings"
)

// Chain is the pseudo-protocol of a saved chain: Node.Protocol only. A chain
// has no Profile of its own; it lists the nodes whose profiles are its hops.
const Chain = "chain"

// MaxChainHops bounds a chain. Each hop adds a connection setup and latency,
// so very long chains are never useful; the limit only stops runaway input.
const MaxChainHops = 16

// RelaysUDP reports whether the protocol can carry UDP datagrams for a hop
// that follows it. Hops that are themselves UDP-based (WireGuard, Hysteria,
// TUIC, OpenVPN over UDP) need such a predecessor.
func RelaysUDP(p Profile) bool {
	switch p.Protocol {
	case VLESS, VMess, Trojan, Shadowsocks, SOCKS, Hysteria2, Hysteria, TUIC, WireGuard, OpenVPN, AnyTLS:
		return true
	}
	return false
}

// CheckChain validates the order of a chain (entry first, exit last). names
// label the hops in messages and may be nil.
func CheckChain(hops []Profile, names []string) error {
	if len(hops) < 2 {
		return fmt.Errorf("a chain needs at least two servers")
	}
	if len(hops) > MaxChainHops {
		return fmt.Errorf("a chain can have at most %d servers", MaxChainHops)
	}
	label := func(i int) string {
		if i < len(names) && strings.TrimSpace(names[i]) != "" {
			return fmt.Sprintf("%d “%s” (%s)", i+1, names[i], ProtocolName(hops[i].Protocol))
		}
		return fmt.Sprintf("%d (%s)", i+1, ProtocolName(hops[i].Protocol))
	}
	for i, h := range hops {
		if err := h.Validate(); err != nil {
			return fmt.Errorf("hop %s: %w", label(i), err)
		}
		if h.Protocol == Custom {
			return fmt.Errorf("hop %s is a custom config, which cannot be part of a chain", label(i))
		}
		if i > 0 && h.UDPBased() && !RelaysUDP(hops[i-1]) {
			return fmt.Errorf("hop %s is UDP-based, but the hop before it, %s, cannot carry UDP", label(i), label(i-1))
		}
	}
	return nil
}
