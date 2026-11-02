package mihomo

import (
	"fmt"
	"net"
	"strings"

	"keyway/internal/models"
)

// Geodata files a configuration needs (core.GeoSiteFile / core.GeoIPFile).
const (
	geoSiteFile = "GeoSite.dat"
	geoIPFile   = "geoip.metadb"
)

// privateCIDRs is what "geoip:private" stands for. Mihomo's own GEOIP,private is
// not a list of addresses, so it is spelled out and a match is certain.
var privateCIDRs = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

// routeList sends every entry to one target ("proxy", "direct" or "block").
type routeList struct {
	target  string
	entries []string
}

// routeLists mirrors the Xray rule order: block, explicit proxy, then direct.
func routeLists(s models.Settings) []routeList {
	split := func(v string) []string {
		var out []string
		for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
			if e = strings.TrimSpace(e); e != "" {
				out = append(out, e)
			}
		}
		return out
	}
	var lists []routeList
	blocked := split(s.BlockedSites)
	if s.BlockAds && len(blocked) == 0 {
		blocked = []string{"geosite:category-ads-all"}
	}
	if s.BlockAds || s.RoutingMode == "custom" {
		lists = append(lists, routeList{"block", blocked})
	}
	switch s.RoutingMode {
	case "rules":
		for _, r := range s.ActiveRules() {
			lists = append(lists, routeList{r.Outbound, r.Entries})
		}
	case "custom":
		lists = append(lists, routeList{"proxy", split(s.ProxySites)}, routeList{"direct", split(s.DirectSites)})
	case "global":
	default: // bypass-private
		direct := split(s.DirectSites)
		if len(direct) == 0 {
			direct = []string{"geosite:private", "geosite:cn"}
		}
		lists = append(lists, routeList{"direct", append([]string{"geoip:private"}, direct...)})
	}
	return lists
}

func target(t string) string {
	switch t {
	case "direct":
		return "DIRECT"
	case "block":
		return "REJECT"
	}
	return "proxy" // the exit hop
}

// rule is one Mihomo rule; ip rules make Mihomo resolve a domain destination.
type rule struct {
	body string // "DOMAIN-SUFFIX,example.com"
	to   string
	ip   bool
}

func (r rule) text(noResolve bool) string {
	s := r.body + "," + r.to
	if noResolve {
		s += ",no-resolve"
	}
	return s
}

// buildRules turns the routing settings into Mihomo rules. Xray's
// domainStrategy "IPIfNonMatch" first tries every rule on the domain alone and
// only then resolves it and tries the IP rules again. Mihomo resolves at the
// first IP rule it meets, which would send every lookup out before the domain
// rules were read, so the IP rules go first with no-resolve (they match only
// destinations that are already addresses) and again, resolving, after the last
// rule.
func buildRules(s models.Settings) ([]string, error) {
	var all []rule
	for _, l := range routeLists(s) {
		for _, e := range l.entries {
			rs, err := entryRules(e, target(l.target))
			if err != nil {
				return nil, err
			}
			all = append(all, rs...)
		}
	}
	var out []string
	var second []string
	for _, r := range all {
		out = append(out, r.text(r.ip))
		if r.ip {
			second = append(second, r.text(false))
		}
	}
	out = append(out, second...)
	return append(out, "MATCH,proxy"), nil
}

// rulesNeed lists the geodata files a rule list refers to.
func rulesNeed(rules []string) []string {
	var site, ip bool
	for _, r := range rules {
		site = site || strings.HasPrefix(r, "GEOSITE,")
		ip = ip || strings.HasPrefix(r, "GEOIP,")
	}
	var out []string
	if site {
		out = append(out, geoSiteFile)
	}
	if ip {
		out = append(out, geoIPFile)
	}
	return out
}

// GeoData lists the geodata files the routing settings need, so they can be
// downloaded (and verified) before Mihomo starts.
func GeoData(s models.Settings) []string {
	rules, err := buildRules(s)
	if err != nil {
		return nil
	}
	return rulesNeed(rules)
}

func entryRules(e, to string) ([]rule, error) {
	kind, err := models.EntryKind(e)
	if err != nil {
		return nil, err
	}
	e = strings.TrimSpace(e)
	switch kind {
	case models.KindProcess:
		return nil, fmt.Errorf("routing entry %q matches by app, which only sing-box can do; choose sing-box as the engine", e)
	case models.KindPort:
		v := strings.ReplaceAll(strings.TrimPrefix(e, "port:"), ",", "/")
		return []rule{{body: "DST-PORT," + strings.ReplaceAll(v, " ", ""), to: to}}, nil
	case models.KindIP:
		return ipRules(e, to)
	}
	// domain entries
	typ, val := "DOMAIN-KEYWORD", e // Xray: a plain string is a substring match
	for prefix, t := range map[string]string{"domain:": "DOMAIN-SUFFIX", "full:": "DOMAIN", "keyword:": "DOMAIN-KEYWORD",
		"regexp:": "DOMAIN-REGEX", "geosite:": "GEOSITE", "ext:": ""} {
		if v, ok := strings.CutPrefix(e, prefix); ok {
			if t == "" {
				return nil, fmt.Errorf("routing entry %q (ext: files) is not supported by Mihomo", e)
			}
			typ, val = t, v
		}
	}
	if strings.Contains(val, ",") {
		return nil, fmt.Errorf("routing entry %q contains a comma, which a Mihomo rule cannot hold", e)
	}
	return []rule{{body: typ + "," + val, to: to}}, nil
}

func ipRules(e, to string) ([]rule, error) {
	if v, ok := strings.CutPrefix(e, "geoip:"); ok {
		if v == "private" {
			var out []rule
			for _, c := range privateCIDRs {
				out = append(out, cidrRule(c, to))
			}
			return out, nil
		}
		if strings.Contains(v, ",") {
			return nil, fmt.Errorf("routing entry %q contains a comma, which a Mihomo rule cannot hold", e)
		}
		return []rule{{body: "GEOIP," + v, to: to, ip: true}}, nil
	}
	if _, n, err := net.ParseCIDR(e); err == nil {
		return []rule{cidrRule(n.String(), to)}, nil
	}
	ip := net.ParseIP(e)
	if ip == nil {
		return nil, fmt.Errorf("routing entry %q is not an IP address", e)
	}
	bits := "/32"
	if ip.To4() == nil {
		bits = "/128"
	}
	return []rule{cidrRule(ip.String()+bits, to)}, nil
}

func cidrRule(cidr, to string) rule {
	if strings.Contains(cidr, ":") {
		return rule{body: "IP-CIDR6," + cidr, to: to, ip: true}
	}
	return rule{body: "IP-CIDR," + cidr, to: to, ip: true}
}
