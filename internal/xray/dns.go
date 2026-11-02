package xray

import (
	"fmt"

	"keyway/internal/models"
)

// DNSTag is the inbound tag Xray gives its own DNS queries, so routing rules
// can steer them like any other connection.
const DNSTag = "dns-in"

// SupportsDNS reports whether Xray can honour the DNS settings. It cannot do
// DNS over TLS: given tls://host it starts a plain UDP resolver named
// "tls://host" and never says so.
func SupportsDNS(p models.DNSPlan) error {
	servers := p.Servers
	if p.Direct != nil {
		servers = append(append([]models.DNSServer{}, servers...), *p.Direct)
	}
	for _, d := range servers {
		if d.Kind == models.DNSTLS {
			return fmt.Errorf("Xray core cannot do DNS over TLS (%s); sing-box can", d)
		}
	}
	return nil
}

// DNSServer is a resolver that only answers for some domains.
type DNSServer struct {
	Address      string   `json:"address"`
	Domains      []string `json:"domains,omitempty"`
	SkipFallback bool     `json:"skipFallback,omitempty"` // do not ask it about domains it was not named for
}

// applyDNS replaces the default resolvers with the plan's. The queries of the
// secure and custom modes leave through the proxy: the first rules pin the
// DNS inbound to it (and the direct resolver to "direct"), whatever the
// routing mode would have made of a DNS server's address.
func applyDNS(cfg *Config, p models.DNSPlan) {
	if p.IsDefault() {
		return
	}
	if p.Mode == models.DNSModeSystem {
		cfg.DNS = &DNS{Servers: []any{"localhost"}} // answered by the OS: no connection to steer
		return
	}
	var servers []any
	var pin []Rule
	if domains := directDomains(cfg.Routing.Rules); p.Direct != nil && len(domains) > 0 {
		servers = append(servers, DNSServer{Address: p.Direct.String(), Domains: domains, SkipFallback: true})
		pin = append(pin, Rule{Type: "field", InboundTag: []string{DNSTag}, IP: []string{p.Direct.Host}, OutboundTag: "direct"})
	}
	for _, d := range p.Servers {
		servers = append(servers, d.String())
	}
	cfg.DNS = &DNS{Servers: servers, Tag: DNSTag}
	pin = append(pin, Rule{Type: "field", InboundTag: []string{DNSTag}, OutboundTag: cfg.Outbounds[0].Tag})
	cfg.Routing.Rules = append(pin, cfg.Routing.Rules...)
}

// directDomains collects the domain matchers of the rules that bypass the
// proxy, which are the names the direct resolver answers for.
func directDomains(rules []Rule) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range rules {
		if r.OutboundTag != "direct" {
			continue
		}
		for _, d := range r.Domain {
			if kind, err := models.EntryKind(d); err == nil && kind == models.KindDomain && !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}
