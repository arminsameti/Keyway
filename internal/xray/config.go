package xray

import (
	"fmt"
	"strings"

	"keyway/internal/models"
	"keyway/internal/profile"
)

var defaultDNS = []string{"1.1.1.1", "8.8.8.8", "localhost"}

// BuildConfig renders the Xray configuration of one segment. The last segment
// of a chain carries the user's inbounds and routing; a segment with Listen set
// is a middle segment and only exposes its exit on that bridge. The settings
// are validated first, so a config that cannot work is never written.
func BuildConfig(seg profile.Segment, s models.Settings) (*Config, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	outs, err := segmentOutbounds(seg)
	if err != nil {
		return nil, err
	}
	dns := s.DNS
	if len(dns) == 0 {
		dns = defaultDNS
	}
	cfg := &Config{
		Log: LogConfig{LogLevel: s.LogLevel},
		DNS: &DNS{Servers: dns},
		Outbounds: append(outs,
			Outbound{Tag: "direct", Protocol: "freedom"},
			Outbound{Tag: "block", Protocol: "blackhole"}),
	}
	if seg.Listen != nil {
		cfg.Inbounds = []Inbound{bridgeInbound(*seg.Listen)}
		cfg.Routing = Routing{DomainStrategy: "AsIs", Rules: []Rule{}}
		return cfg, nil
	}
	if on, conc := muxFor(s, seg.Hops[len(seg.Hops)-1]); on && cfg.Outbounds[0].MuxCapable() {
		cfg.Outbounds[0].Mux = &Mux{Enabled: true, Concurrency: conc}
	}
	cfg.Inbounds = buildInbounds(s)
	rules, err := buildRules(s)
	if err != nil {
		return nil, err
	}
	cfg.Routing = Routing{DomainStrategy: "IPIfNonMatch", Rules: rules}
	if seg.Stats != nil {
		addStats(cfg, seg.Stats.Port)
	}
	return cfg, nil
}

// muxFor resolves multiplexing for the exit server: its own override, else the global setting.
func muxFor(s models.Settings, exit profile.Profile) (bool, int) {
	on, conc := s.Mux, s.MuxConcurrency
	if o := exit.Overrides; o != nil {
		if o.Mux != nil {
			on = *o.Mux
		}
		if o.MuxConcurrency > 0 {
			conc = o.MuxConcurrency
		}
	}
	return on, conc
}

// StatsTag is the inbound that carries the stats gRPC API.
const StatsTag = "stats-api"

// addStats turns on Xray's per-outbound counters and exposes them on a
// loopback-only dokodemo inbound that is routed to the API handler.
func addStats(cfg *Config, port int) {
	cfg.Stats = &struct{}{}
	cfg.API = &API{Tag: "api", Services: []string{"StatsService"}}
	cfg.Policy = &Policy{System: PolicySystem{OutboundUplink: true, OutboundDownlink: true}}
	cfg.Inbounds = append(cfg.Inbounds, Inbound{Tag: StatsTag, Protocol: "dokodemo-door", Listen: "127.0.0.1", Port: port,
		Settings: map[string]any{"address": "127.0.0.1"}})
	cfg.Routing.Rules = append([]Rule{{Type: "field", InboundTag: []string{StatsTag}, OutboundTag: "api"}}, cfg.Routing.Rules...)
}

func bridgeInbound(b profile.Bridge) Inbound {
	return Inbound{Tag: "bridge-in", Protocol: "socks", Listen: "127.0.0.1", Port: b.Port,
		Settings: &SocksInbound{Auth: "password", Accounts: []Account{{User: b.User, Pass: b.Pass}}}}
}

func buildInbounds(s models.Settings) []Inbound {
	var out []Inbound
	for _, ib := range s.Inbounds {
		if !ib.Enabled {
			continue
		}
		in := Inbound{
			Tag:      ib.Tag,
			Protocol: ib.Protocol,
			Listen:   s.EffectiveListen(ib),
			Port:     ib.Port,
			Sniffing: &Sniffing{Enabled: s.Sniffing, DestOverride: []string{"http", "tls", "quic"}},
		}
		var accounts []Account
		if ib.Username != "" {
			accounts = []Account{{User: ib.Username, Pass: ib.Password}}
		}
		switch ib.Protocol {
		case "http":
			in.Settings = &HTTPInbound{Accounts: accounts}
		default:
			auth := "noauth"
			if accounts != nil {
				auth = "password"
			}
			in.Settings = &SocksInbound{Auth: auth, Accounts: accounts, UDP: ib.UDP}
		}
		out = append(out, in)
	}
	return out
}

// SplitList splits a comma/newline separated list, dropping blanks.
func SplitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// buildRules honours DirectSites / ProxySites / BlockedSites / BlockAds in every
// mode. Order matters: block, then explicit proxy, then direct.
func buildRules(s models.Settings) ([]Rule, error) {
	var rules []Rule
	add := func(tag string, domains, ips []string) {
		if len(domains) > 0 || len(ips) > 0 {
			rules = append(rules, Rule{Type: "field", Domain: domains, IP: ips, OutboundTag: tag})
		}
	}

	blocked := SplitList(s.BlockedSites)
	if s.BlockAds && len(blocked) == 0 {
		blocked = []string{"geosite:category-ads-all"}
	}
	if s.BlockAds || s.RoutingMode == "custom" {
		add("block", blocked, nil)
	}

	switch s.RoutingMode {
	case "rules":
		custom, err := customRules(s)
		if err != nil {
			return nil, err
		}
		rules = append(rules, custom...)
	case "global":
		// Everything through the proxy: only the block rule above applies.
	case "custom":
		add("proxy", SplitList(s.ProxySites), nil)
		add("direct", SplitList(s.DirectSites), nil)
	default: // bypass-private
		add("direct", nil, []string{"geoip:private"})
		direct := SplitList(s.DirectSites)
		if len(direct) == 0 {
			direct = []string{"geosite:private", "geosite:cn"}
		}
		add("direct", direct, nil)
	}
	if rules == nil {
		rules = []Rule{}
	}
	return rules, nil
}

// customRules turns the active rule set into Xray rules. Xray ANDs the fields
// of one rule, so each kind of entry becomes a rule of its own; they share an
// outbound and keep the user's order.
func customRules(s models.Settings) ([]Rule, error) {
	var out []Rule
	for _, r := range s.ActiveRules() {
		var domains, ips, ports []string
		for _, e := range r.Entries {
			kind, err := models.EntryKind(e)
			if err != nil {
				return nil, err
			}
			switch kind {
			case models.KindDomain:
				domains = append(domains, strings.TrimSpace(e))
			case models.KindIP:
				ips = append(ips, strings.TrimSpace(e))
			case models.KindPort:
				ports = append(ports, strings.TrimPrefix(strings.TrimSpace(e), "port:"))
			default:
				return nil, fmt.Errorf("routing entry %q matches by app, which only sing-box can do; choose sing-box as the engine", e)
			}
		}
		if len(domains) > 0 {
			out = append(out, Rule{Type: "field", Domain: domains, OutboundTag: r.Outbound})
		}
		if len(ips) > 0 {
			out = append(out, Rule{Type: "field", IP: ips, OutboundTag: r.Outbound})
		}
		if len(ports) > 0 {
			out = append(out, Rule{Type: "field", Port: strings.Join(ports, ","), OutboundTag: r.Outbound})
		}
	}
	return out, nil
}

// UsesGeoData reports whether the config needs geoip.dat / geosite.dat.
func (c *Config) UsesGeoData() bool {
	for _, r := range c.Routing.Rules {
		for _, v := range append(append([]string{}, r.Domain...), r.IP...) {
			if strings.HasPrefix(v, "geosite:") || strings.HasPrefix(v, "geoip:") {
				return true
			}
		}
	}
	return false
}

// ProbeConfig is a minimal config used to measure a node through a real Xray
// instance: a middle segment exposes its bridge, the last segment a SOCKS
// inbound on 127.0.0.1:port.
func ProbeConfig(seg profile.Segment, port int) (*Config, error) {
	outs, err := segmentOutbounds(seg)
	if err != nil {
		return nil, err
	}
	in := Inbound{Tag: "probe", Protocol: "socks", Listen: "127.0.0.1", Port: port, Settings: &SocksInbound{Auth: "noauth"}}
	if seg.Listen != nil {
		in = bridgeInbound(*seg.Listen)
	}
	return &Config{
		Log:       LogConfig{LogLevel: "none"},
		Inbounds:  []Inbound{in},
		Outbounds: outs,
		Routing:   Routing{DomainStrategy: "AsIs", Rules: []Rule{}},
	}, nil
}
