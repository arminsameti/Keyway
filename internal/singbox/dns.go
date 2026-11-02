package singbox

import "keyway/internal/models"

// FakeIP address ranges: the benchmarking block 198.18.0.0/15 and a unique
// local IPv6 prefix, neither routed on the internet.
const (
	fakeIPv4 = "198.18.0.0/15"
	fakeIPv6 = "fc00::/18"
)

// applyDNS replaces the system resolver by the plan's. sing-box has no failover
// between DNS servers, so the first server answers everything and the others
// are left out (EffectiveDNS says so). Its queries go out through the "proxy"
// outbound, except a direct resolver's, which answers for the domains the
// routing rules send direct. fakeip answers every lookup of an app with an
// address that the tunnel maps back to the name, so only a process that owns
// the TUN interface (tun) may use it.
func applyDNS(cfg *Config, p models.DNSPlan, s models.Settings, tun bool) error {
	if p.IsDefault() {
		return nil
	}
	dns := cfg.DNS
	if len(p.Servers) > 0 && p.Servers[0].Kind != models.DNSLocal {
		dns.Servers = append(dns.Servers, server(p.Servers[0], "dns-0", "proxy"))
		dns.Final = "dns-0"
	}
	if p.Direct != nil {
		rules, err := directDNSRules(s)
		if err != nil {
			return err
		}
		if len(rules) > 0 {
			dns.Servers = append(dns.Servers, server(*p.Direct, "dns-direct", ""))
			dns.Rules = append(dns.Rules, rules...)
		}
	}
	if p.FakeIP && tun {
		dns.Servers = append(dns.Servers, DNSServer{Type: "fakeip", Tag: "fakeip", Inet4Range: fakeIPv4, Inet6Range: fakeIPv6})
		dns.Rules = append(dns.Rules, DNSRule{QueryType: []string{"A", "AAAA"}, Action: "route", Server: "fakeip"})
	}
	return nil
}

func server(d models.DNSServer, tag, detour string) DNSServer {
	out := DNSServer{Tag: tag, Server: d.Host, ServerPort: d.Port, Detour: detour}
	switch d.Kind {
	case models.DNSHTTPS:
		out.Type, out.Path = "https", d.Path
	case models.DNSTLS:
		out.Type = "tls"
	default:
		out.Type = "udp"
	}
	return out
}

// directDNSRules turns the domain matchers of the lists that bypass the proxy
// into DNS rules. IP matchers cannot select a DNS server, and the rule sets
// they use are already declared by the routing.
func directDNSRules(s models.Settings) ([]DNSRule, error) {
	var out []DNSRule
	for _, l := range routeLists(s) {
		if l.target != "direct" {
			continue
		}
		var domains []string
		for _, e := range l.entries {
			if kind, err := models.EntryKind(e); err == nil && kind == models.KindDomain {
				domains = append(domains, e)
			}
		}
		rules, err := listRules(routeList{target: "direct", entries: domains}, map[string]bool{})
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			out = append(out, DNSRule{RuleSet: r.RuleSet, Domain: r.Domain, DomainSuffix: r.DomainSuffix,
				DomainKeyword: r.DomainKeyword, DomainRegex: r.DomainRegex, Action: "route", Server: "dns-direct"})
		}
	}
	return out, nil
}
