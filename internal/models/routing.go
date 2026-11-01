package models

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RouteRule sends everything that matches any of its entries to one outbound.
// Entries use Xray's routing syntax so both engines read the same text:
//
//	domain:example.com   the domain and its subdomains
//	full:a.example.com   exactly this domain
//	keyword:ads          any domain containing this
//	regexp:^ad[0-9]+\.   a regular expression
//	geosite:cn           a community domain list
//	geoip:cn, geoip:private, 10.0.0.0/8, 1.2.3.4   IP lists and ranges
//	port:80,443,8000-9000
//	process:Telegram, process-path:/Applications/X.app/Contents/MacOS/X,
//	app:/Applications/Telegram.app   every program inside that app   (sing-box only)
//
// A bare word is a keyword match.
type RouteRule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name,omitempty"`
	Enabled  bool     `json:"enabled"`
	Entries  []string `json:"entries"`
	Outbound string   `json:"outbound"` // proxy | direct | block
}

// RuleSet is a named, ordered list of rules. The first matching rule wins; when
// none match, traffic goes through the proxy.
type RuleSet struct {
	ID    string      `json:"id"`
	Name  string      `json:"name"`
	Rules []RouteRule `json:"rules"`
}

const (
	maxRuleSets       = 20
	maxRulesPerSet    = 200
	maxEntriesPerRule = 1000
)

var ruleOutbounds = map[string]bool{"proxy": true, "direct": true, "block": true}

// Entry kinds returned by EntryKind.
const (
	KindDomain  = "domain"
	KindIP      = "ip"
	KindPort    = "port"
	KindProcess = "process"
)

// EntryKind classifies one routing entry and validates it.
func EntryKind(e string) (string, error) {
	e = strings.TrimSpace(e)
	if e == "" {
		return "", fmt.Errorf("empty entry")
	}
	if strings.ContainsAny(e, " \t\r\n") && !strings.HasPrefix(e, "process-path:") && !strings.HasPrefix(e, "app:") && !strings.HasPrefix(e, "regexp:") {
		return "", fmt.Errorf("entry %q must not contain spaces", e)
	}
	for _, p := range []string{"domain:", "full:", "keyword:", "regexp:", "geosite:", "ext:"} {
		if v, ok := strings.CutPrefix(e, p); ok {
			if strings.TrimSpace(v) == "" {
				return "", fmt.Errorf("entry %q has nothing after %q", e, p)
			}
			return KindDomain, nil
		}
	}
	if v, ok := strings.CutPrefix(e, "geoip:"); ok {
		if v == "" {
			return "", fmt.Errorf("entry %q has nothing after \"geoip:\"", e)
		}
		return KindIP, nil
	}
	if v, ok := strings.CutPrefix(e, "port:"); ok {
		return KindPort, validatePorts(v)
	}
	for _, p := range []string{"process:", "process-path:", "app:"} {
		if v, ok := strings.CutPrefix(e, p); ok {
			if strings.TrimSpace(v) == "" {
				return "", fmt.Errorf("entry %q has nothing after %q", e, p)
			}
			return KindProcess, nil
		}
	}
	if _, _, err := net.ParseCIDR(e); err == nil {
		return KindIP, nil
	}
	if net.ParseIP(e) != nil {
		return KindIP, nil
	}
	if strings.Contains(e, ":") {
		return "", fmt.Errorf("unknown entry type in %q", e)
	}
	return KindDomain, nil
}

// PortRanges parses "80,443,8000-9000" into [from, to] pairs.
func PortRanges(v string) ([][2]int, error) {
	var out [][2]int
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port in %q", v)
		}
		lo, hi, found := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil || a < 1 || a > 65535 {
			return nil, fmt.Errorf("bad port %q", part)
		}
		b := a
		if found {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil || b < a || b > 65535 {
				return nil, fmt.Errorf("bad port range %q", part)
			}
		}
		out = append(out, [2]int{a, b})
	}
	return out, nil
}

func validatePorts(v string) error {
	_, err := PortRanges(v)
	return err
}

// ActiveRules returns the enabled rules of the active rule set.
func (s Settings) ActiveRules() []RouteRule {
	for _, set := range s.RuleSets {
		if set.ID != s.ActiveRuleSet {
			continue
		}
		var out []RouteRule
		for _, r := range set.Rules {
			if r.Enabled && len(r.Entries) > 0 {
				out = append(out, r)
			}
		}
		return out
	}
	return nil
}

// validateRuleSets reports every problem of the saved rule sets.
func (s Settings) validateRuleSets(add func(string, ...any)) {
	if len(s.RuleSets) > maxRuleSets {
		add("at most %d rule sets", maxRuleSets)
	}
	ids := map[string]bool{}
	for _, set := range s.RuleSets {
		if set.ID == "" || ids[set.ID] {
			add("rule set %q needs a unique ID", set.Name)
		}
		ids[set.ID] = true
		if strings.TrimSpace(set.Name) == "" {
			add("a rule set needs a name")
		}
		if len(set.Rules) > maxRulesPerSet {
			add("rule set %q has more than %d rules", set.Name, maxRulesPerSet)
		}
		for i, r := range set.Rules {
			where := fmt.Sprintf("rule set %q, rule %d", set.Name, i+1)
			if !ruleOutbounds[r.Outbound] {
				add("%s: outbound must be proxy, direct or block", where)
			}
			if len(r.Entries) > maxEntriesPerRule {
				add("%s has more than %d entries", where, maxEntriesPerRule)
			}
			if r.Enabled && len(r.Entries) == 0 {
				add("%s: add at least one entry or turn the rule off", where)
			}
			for _, e := range r.Entries {
				if _, err := EntryKind(e); err != nil {
					add("%s: %v", where, err)
				}
			}
		}
	}
	if s.RoutingMode == "rules" && !ids[s.ActiveRuleSet] {
		add("choose a rule set for routing mode \"rules\"")
	}
	if s.ActiveRuleSet != "" && !ids[s.ActiveRuleSet] {
		add("the active rule set no longer exists")
	}
}

// NeedsProcessRouting reports whether an enabled rule matches by program.
func (s Settings) NeedsProcessRouting() bool {
	if s.RoutingMode != "rules" {
		return false
	}
	for _, r := range s.ActiveRules() {
		for _, e := range r.Entries {
			if k, err := EntryKind(e); err == nil && k == KindProcess {
				return true
			}
		}
	}
	return false
}

// NeedsSingBox reports whether the settings need a feature only sing-box has.
func (s Settings) NeedsSingBox() bool { return s.NeedsProcessRouting() || s.TUN.Enabled }
