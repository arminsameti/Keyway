package models

import "strings"

// Synthetic rule IDs for the rules a routing mode generates on its own.
const (
	ModeRuleDirectPrivate = "mode-direct-private"
	ModeRuleDirect        = "mode-direct"
	ModeRuleProxy         = "mode-proxy"
	// ModeRuleBlocked labels the block list (Blocked Sites, or the default
	// ads geosite) in the rule tester.
	ModeRuleBlocked = "blocked-sites"
)

// SplitSites splits a comma/newline separated list, trimming entries and
// dropping the empty ones.
func SplitSites(v string) []string {
	var out []string
	for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// RouteList sends every entry to one target ("proxy", "direct" or "block").
type RouteList struct {
	Target  string
	Entries []string
	// ID is the stable rule ID of a list a routing mode generates itself;
	// empty for the block list and for the user's own rules.
	ID string
	// IPOnly marks the geoip:private list of bypass-private, which engines
	// that tell domain and IP matchers apart must treat as IP matchers.
	IPOnly bool
}

// RouteLists is what the routing settings ask for, in the order the engines
// apply it: block, explicit proxy, then direct.
func RouteLists(s Settings) []RouteList {
	var lists []RouteList
	blocked := SplitSites(s.BlockedSites)
	if s.BlockAds && len(blocked) == 0 {
		blocked = []string{"geosite:category-ads-all"}
	}
	if s.BlockAds || s.RoutingMode == "custom" {
		lists = append(lists, RouteList{Target: "block", Entries: blocked, ID: ModeRuleBlocked})
	}
	switch s.RoutingMode {
	case "rules":
		for _, r := range s.ActiveRules() {
			lists = append(lists, RouteList{Target: r.Outbound, Entries: r.Entries, ID: r.ID})
		}
	case "custom":
		lists = append(lists,
			RouteList{Target: "proxy", Entries: SplitSites(s.ProxySites), ID: ModeRuleProxy},
			RouteList{Target: "direct", Entries: SplitSites(s.DirectSites), ID: ModeRuleDirect})
	case "global":
	default: // bypass-private
		direct := SplitSites(s.DirectSites)
		if len(direct) == 0 {
			direct = []string{"geosite:private", "geosite:cn"}
		}
		lists = append(lists,
			RouteList{Target: "direct", Entries: []string{"geoip:private"}, ID: ModeRuleDirectPrivate, IPOnly: true},
			RouteList{Target: "direct", Entries: direct, ID: ModeRuleDirect})
	}
	return lists
}

// EffectiveRules returns the non-block rules the routing mode gives the
// engines, in the order they apply (RouteLists order). The generated ones
// carry stable IDs so a UI can label them.
func EffectiveRules(s Settings) []RouteRule {
	if s.RoutingMode == "rules" {
		return s.ActiveRules()
	}
	var out []RouteRule
	for _, l := range RouteLists(s) {
		if l.Target == "block" {
			continue
		}
		out = append(out, RouteRule{ID: l.ID, Enabled: true, Entries: l.Entries, Outbound: l.Target})
	}
	return out
}
