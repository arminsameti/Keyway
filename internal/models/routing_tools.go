package models

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// RouteMatch is the outcome of asking which rule a destination would hit.
type RouteMatch struct {
	Outbound string   `json:"outbound"`          // proxy | direct | block
	RuleID   string   `json:"ruleId,omitempty"`  // empty when no rule matched
	Entry    string   `json:"entry,omitempty"`   // the entry that matched
	Unknown  []string `json:"unknown,omitempty"` // entries that cannot be evaluated offline (geosite/geoip/process)
}

// MatchRoute evaluates a destination against rules in order. Entries that need
// the engine's data files or the sending app are reported in Unknown instead of
// being guessed, so the answer never claims more than it knows.
func MatchRoute(rules []RouteRule, host string, port int) RouteMatch {
	host = strings.ToLower(strings.TrimSpace(host))
	ip := net.ParseIP(host)
	var unknown []string
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		for _, e := range r.Entries {
			ok, known := entryMatches(strings.TrimSpace(e), host, ip, port)
			if !known {
				unknown = append(unknown, e)
				continue
			}
			if ok {
				return RouteMatch{Outbound: r.Outbound, RuleID: r.ID, Entry: e, Unknown: unknown}
			}
		}
	}
	return RouteMatch{Outbound: "proxy", Unknown: unknown}
}

func entryMatches(e, host string, ip net.IP, port int) (match, known bool) {
	kind, err := EntryKind(e)
	if err != nil {
		return false, true
	}
	switch {
	case strings.HasPrefix(e, "geosite:"), strings.HasPrefix(e, "geoip:"), strings.HasPrefix(e, "ext:"), kind == KindProcess:
		return false, false
	case strings.HasPrefix(e, "domain:"):
		d := strings.ToLower(strings.TrimPrefix(e, "domain:"))
		return ip == nil && (host == d || strings.HasSuffix(host, "."+d)), true
	case strings.HasPrefix(e, "full:"):
		return host == strings.ToLower(strings.TrimPrefix(e, "full:")), true
	case strings.HasPrefix(e, "regexp:"):
		re, err := regexp.Compile(strings.TrimPrefix(e, "regexp:"))
		return err == nil && ip == nil && re.MatchString(host), true
	case strings.HasPrefix(e, "port:"):
		if port == 0 {
			return false, true
		}
		ranges, _ := PortRanges(strings.TrimPrefix(e, "port:"))
		for _, r := range ranges {
			if port >= r[0] && port <= r[1] {
				return true, true
			}
		}
		return false, true
	case kind == KindIP:
		if ip == nil {
			return false, true
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			return n.Contains(ip), true
		}
		return net.ParseIP(e).Equal(ip), true
	default: // keyword: or a bare word
		return ip == nil && strings.Contains(host, strings.ToLower(strings.TrimPrefix(e, "keyword:"))), true
	}
}

// ParseRules reads routing rules from Clash-style lines
// ("DOMAIN-SUFFIX,example.com,DIRECT") or from an Xray/v2rayN routing JSON
// (a rule array, or an object with a "rules" array). Consecutive rules for the
// same outbound are merged. Lines it cannot use are returned as skipped.
func ParseRules(text string) (rules []RouteRule, skipped []string, err error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil, fmt.Errorf("nothing to import")
	}
	var raw []RouteRule
	if text[0] == '{' || text[0] == '[' {
		raw, skipped, err = parseXrayRules(text)
	} else {
		raw, skipped = parseClashRules(text)
	}
	if err != nil {
		return nil, nil, err
	}
	for _, r := range raw {
		if n := len(rules); n > 0 && rules[n-1].Outbound == r.Outbound {
			rules[n-1].Entries = append(rules[n-1].Entries, r.Entries...)
			continue
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, skipped, fmt.Errorf("no usable rules found")
	}
	for i := range rules {
		rules[i].ID = fmt.Sprintf("imp%d", i+1)
		rules[i].Enabled = true
	}
	return rules, skipped, nil
}

func outboundFor(name string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "proxy", "select", "global":
		return "proxy", true
	case "direct":
		return "direct", true
	case "block", "reject", "reject-drop", "blackhole":
		return "block", true
	}
	return "", false
}

func parseClashRules(text string) (rules []RouteRule, skipped []string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "rules:") {
			continue
		}
		f := strings.Split(line, ",")
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
		}
		if len(f) < 3 {
			skipped = append(skipped, line)
			continue
		}
		out, ok := outboundFor(f[2])
		if !ok {
			out = "proxy" // a named proxy group: everything that is not direct or blocked uses the proxy
		}
		var entry string
		switch strings.ToUpper(f[0]) {
		case "DOMAIN":
			entry = "full:" + f[1]
		case "DOMAIN-SUFFIX":
			entry = "domain:" + f[1]
		case "DOMAIN-KEYWORD":
			entry = "keyword:" + f[1]
		case "DOMAIN-REGEX":
			entry = "regexp:" + f[1]
		case "IP-CIDR", "IP-CIDR6":
			entry = f[1]
		case "GEOIP":
			entry = "geoip:" + strings.ToLower(f[1])
		case "GEOSITE":
			entry = "geosite:" + strings.ToLower(f[1])
		case "DST-PORT":
			entry = "port:" + strings.ReplaceAll(f[1], "/", ",")
		case "PROCESS-NAME":
			entry = "process:" + f[1]
		case "PROCESS-PATH":
			entry = "process-path:" + f[1]
		default:
			skipped = append(skipped, line)
			continue
		}
		if _, err := EntryKind(entry); err != nil {
			skipped = append(skipped, line)
			continue
		}
		rules = append(rules, RouteRule{Outbound: out, Entries: []string{entry}})
	}
	return rules, skipped
}

func parseXrayRules(text string) (rules []RouteRule, skipped []string, err error) {
	type xrule struct {
		Domain      []string `json:"domain"`
		IP          []string `json:"ip"`
		Port        any      `json:"port"`
		OutboundTag string   `json:"outboundTag"`
		Remarks     string   `json:"remarks"`
	}
	var list []xrule
	if text[0] == '[' {
		err = json.Unmarshal([]byte(text), &list)
	} else {
		var obj struct {
			Rules   []xrule `json:"rules"`
			Routing struct {
				Rules []xrule `json:"rules"`
			} `json:"routing"`
		}
		if err = json.Unmarshal([]byte(text), &obj); err == nil {
			list = append(obj.Rules, obj.Routing.Rules...)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("that is not valid routing JSON: %w", err)
	}
	for i, x := range list {
		out, ok := outboundFor(x.OutboundTag)
		if !ok {
			skipped = append(skipped, fmt.Sprintf("rule %d (outbound %q)", i+1, x.OutboundTag))
			continue
		}
		var entries []string
		entries = append(entries, x.Domain...)
		entries = append(entries, x.IP...)
		switch p := x.Port.(type) {
		case string:
			if p != "" {
				entries = append(entries, "port:"+p)
			}
		case float64:
			entries = append(entries, "port:"+strconv.Itoa(int(p)))
		}
		var good []string
		for _, e := range entries {
			if _, err := EntryKind(e); err != nil {
				skipped = append(skipped, e)
				continue
			}
			good = append(good, e)
		}
		if len(good) > 0 {
			rules = append(rules, RouteRule{Name: x.Remarks, Outbound: out, Entries: good})
		}
	}
	return rules, skipped, nil
}
