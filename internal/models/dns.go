package models

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// DNS resolver modes. "default" is what Keyway always did and leaves the
// generated configs untouched; the others take control of how names resolve.
const (
	DNSModeDefault = "default" // Xray: the DNS list; sing-box: the system resolver
	DNSModeSystem  = "system"  // the system resolver, in every engine
	DNSModeSecure  = "secure"  // built-in DNS over HTTPS, sent through the proxy
	DNSModeCustom  = "custom"  // the user's own list, sent through the proxy
)

var dnsModes = map[string]bool{DNSModeDefault: true, DNSModeSystem: true, DNSModeSecure: true, DNSModeCustom: true}

// secureDNS are the servers of secure mode. They are addressed by IP so no
// bootstrap lookup is needed, and an IP-hosted DoH server works in every engine.
var secureDNS = []string{"https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"}

// Kinds of DNS server a user can name.
const (
	DNSPlain = "plain" // an IP address: UDP port 53
	DNSLocal = "local" // "localhost": the system resolver
	DNSHTTPS = "https" // DNS over HTTPS
	DNSTLS   = "tls"   // DNS over TLS
)

// DNSServer is one parsed entry of the DNS list.
type DNSServer struct {
	Raw  string // as written, trimmed
	Kind string
	Host string // an IP address or a domain name, without brackets
	Port int    // 0 = the protocol's own port
	Path string // DoH only
}

var (
	dnsLabelRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	dnsDigitsRe = regexp.MustCompile(`^[0-9]+$`)
)

const maxDNSEntry = 512

// ParseDNSServer reads one DNS server: an IP address, "localhost",
// https://host[:port][/path] or tls://host[:port]. Anything else is refused
// rather than guessed: engines read an unknown scheme as a plain UDP server and
// say nothing.
func ParseDNSServer(raw string) (DNSServer, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return DNSServer{}, fmt.Errorf("empty DNS server")
	case len(raw) > maxDNSEntry:
		return DNSServer{}, fmt.Errorf("DNS server is longer than %d characters", maxDNSEntry)
	case strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }):
		return DNSServer{}, fmt.Errorf("DNS server %q must not contain spaces", raw)
	case strings.EqualFold(raw, "localhost"):
		return DNSServer{Raw: raw, Kind: DNSLocal, Host: "localhost"}, nil
	case net.ParseIP(raw) != nil:
		return DNSServer{Raw: raw, Kind: DNSPlain, Host: raw}, nil
	}
	scheme, _, _ := strings.Cut(raw, "://")
	kind := strings.ToLower(scheme)
	if kind != DNSHTTPS && kind != DNSTLS || !strings.Contains(raw, "://") {
		return DNSServer{}, fmt.Errorf("DNS server %q must be an IP address, localhost, https://… or tls://…", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return DNSServer{}, fmt.Errorf("DNS server %q is not a valid address", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return DNSServer{}, fmt.Errorf("DNS server %q must not carry credentials, a query or a fragment", raw)
	}
	host := u.Hostname()
	if err := checkDNSHost(host); err != nil {
		return DNSServer{}, fmt.Errorf("DNS server %q: %w", raw, err)
	}
	d := DNSServer{Raw: raw, Kind: kind, Host: host}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return DNSServer{}, fmt.Errorf("DNS server %q: port must be 1-65535", raw)
		}
		d.Port = n
	}
	switch kind {
	case DNSHTTPS:
		d.Path = u.EscapedPath()
		if d.Path == "" {
			d.Path = "/dns-query"
		}
	case DNSTLS:
		if u.Path != "" {
			return DNSServer{}, fmt.Errorf("DNS server %q: DNS over TLS has no path", raw)
		}
	}
	return d, nil
}

func checkDNSHost(host string) error {
	if host == "" {
		return fmt.Errorf("no host")
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if len(host) > 253 {
		return fmt.Errorf("host name is too long")
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if !dnsLabelRe.MatchString(l) {
			return fmt.Errorf("%q is not a valid host name", host)
		}
	}
	if dnsDigitsRe.MatchString(labels[len(labels)-1]) {
		return fmt.Errorf("%q is not a valid IP address", host)
	}
	return nil
}

// IsIP reports whether the server is named by IP address, so reaching it needs
// no name lookup.
func (d DNSServer) IsIP() bool { return net.ParseIP(d.Host) != nil }

// String is the canonical text of the server, which is also how Xray and
// v2ray-core are told about it.
func (d DNSServer) String() string {
	switch d.Kind {
	case DNSLocal:
		return "localhost"
	case DNSHTTPS:
		return "https://" + d.hostPort() + d.Path
	case DNSTLS:
		return "tls://" + d.hostPort()
	}
	return d.Host
}

func (d DNSServer) hostPort() string {
	if d.Port != 0 {
		return net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	}
	if strings.Contains(d.Host, ":") {
		return "[" + d.Host + "]"
	}
	return d.Host
}

// DNSPlan is what the DNS settings amount to: the resolvers every engine is
// built from, so all of them read the settings the same way.
type DNSPlan struct {
	Mode    string
	Servers []DNSServer // empty in default mode
	Direct  *DNSServer  // resolves the bypassed domains; reached directly, not through the proxy
	FakeIP  bool        // TUN only: answer name lookups with fake addresses
}

// IsDefault reports whether the generated configs stay exactly as they were
// before the DNS controls existed.
func (p DNSPlan) IsDefault() bool { return p.Mode == DNSModeDefault && !p.FakeIP }

// DNSPlan resolves the settings. It fails on an entry that cannot be parsed
// instead of leaving it out; Validate catches that earlier with a better message.
func (s Settings) DNSPlan() (DNSPlan, error) {
	p := DNSPlan{Mode: s.DNSMode, FakeIP: s.FakeIP && s.TUN.Enabled}
	if p.Mode == "" {
		p.Mode = DNSModeDefault
	}
	var list []string
	switch p.Mode {
	case DNSModeDefault:
	case DNSModeSystem:
		list = []string{"localhost"}
	case DNSModeSecure:
		list = secureDNS
	case DNSModeCustom:
		list = s.DNS
	default:
		return DNSPlan{}, fmt.Errorf("unknown DNS mode %q", s.DNSMode)
	}
	for _, e := range list {
		d, err := ParseDNSServer(e)
		if err != nil {
			return DNSPlan{}, err
		}
		p.Servers = append(p.Servers, d)
	}
	if (p.Mode == DNSModeSecure || p.Mode == DNSModeCustom) && s.DNSDirect != "" {
		d, err := parseDirectDNS(s.DNSDirect)
		if err != nil {
			return DNSPlan{}, err
		}
		p.Direct = &d
	}
	return p, nil
}

// parseDirectDNS reads the resolver of the bypassed domains. It is dialed
// outside the proxy and matched by address, so it has to be named by IP.
func parseDirectDNS(raw string) (DNSServer, error) {
	d, err := ParseDNSServer(raw)
	if err != nil {
		return d, err
	}
	if d.Kind == DNSLocal || !d.IsIP() {
		return d, fmt.Errorf("the direct DNS server %q must be an IP address (or an https:// / tls:// address with an IP), so it can be reached without the proxy", raw)
	}
	return d, nil
}

func (s Settings) validateDNS(add func(string, ...any)) {
	if s.DNSMode != "" && !dnsModes[s.DNSMode] {
		add("unknown DNS mode %q", s.DNSMode)
		return
	}
	if s.DNSMode == DNSModeCustom && len(s.DNS) == 0 {
		add("custom DNS needs at least one server")
	}
	for _, e := range s.DNS {
		if s.DNSMode != DNSModeCustom || strings.ContainsAny(e, " \t\r\n") {
			continue // the default list keeps its lenient rules: Xray reads more forms than we do
		}
		if _, err := ParseDNSServer(e); err != nil {
			add("%v", err)
		}
	}
	if s.DNSDirect != "" {
		if _, err := parseDirectDNS(s.DNSDirect); err != nil {
			add("%v", err)
		}
	}
}

// EffectiveDNS describes, for the config preview, how names resolve under the
// given engine ("xray", "sing-box", "v2ray") with these settings.
func (s Settings) EffectiveDNS(engine string) string {
	p, err := s.DNSPlan()
	if err != nil {
		return "Invalid DNS settings: " + err.Error()
	}
	names := func(l []DNSServer) string {
		var out []string
		for _, d := range l {
			out = append(out, d.String())
		}
		return strings.Join(out, ", ")
	}
	var parts []string
	switch p.Mode {
	case DNSModeDefault:
		if engine == "sing-box" {
			parts = append(parts, "Default: the system resolver")
			break
		}
		list := s.DNS
		if len(list) == 0 {
			list = DefaultSettings().DNS
		}
		parts = append(parts, "Default: "+strings.Join(list, ", "))
	case DNSModeSystem:
		parts = append(parts, "System: the system resolver")
	default:
		label := "Custom: "
		if p.Mode == DNSModeSecure {
			label = "Secure DNS: "
		}
		route := "through the proxy"
		if engine == "v2ray" {
			route = "following the routing rules" // v2ray-core cannot pin its DNS queries to the proxy
		}
		servers := p.Servers
		if engine == "sing-box" && len(servers) > 1 {
			servers = servers[:1] // sing-box has no failover between DNS servers
			route += fmt.Sprintf(" · only the first of %d servers is used (sing-box has no DNS failover)", len(p.Servers))
		}
		parts = append(parts, label+names(servers), route)
		if p.Direct != nil {
			parts = append(parts, "bypassed domains: "+p.Direct.String()+" (direct)")
		}
	}
	if p.FakeIP {
		parts = append(parts, "FakeIP (TUN)")
	}
	return strings.Join(parts, " · ")
}
