package models

import "strings"

// Synthetic rule IDs for the rules a routing mode generates on its own.
const (
	ModeRuleDirectPrivate = "mode-direct-private"
	ModeRuleDirect        = "mode-direct"
	ModeRuleProxy         = "mode-proxy"
)

func splitSites(v string) []string {
	var out []string
	for _, e := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// EffectiveRules returns the non-block rules the routing mode gives the
// engines, in the order they apply (the engines' routeLists order). The
// generated ones carry stable IDs so a UI can label them.
func EffectiveRules(s Settings) []RouteRule {
	mk := func(id, outbound string, entries []string) RouteRule {
		return RouteRule{ID: id, Enabled: true, Entries: entries, Outbound: outbound}
	}
	switch s.RoutingMode {
	case "rules":
		return s.ActiveRules()
	case "custom":
		return []RouteRule{
			mk(ModeRuleProxy, "proxy", splitSites(s.ProxySites)),
			mk(ModeRuleDirect, "direct", splitSites(s.DirectSites)),
		}
	case "global":
		return nil
	default: // bypass-private
		direct := splitSites(s.DirectSites)
		if len(direct) == 0 {
			direct = []string{"geosite:private", "geosite:cn"}
		}
		return []RouteRule{
			mk(ModeRuleDirectPrivate, "direct", []string{"geoip:private"}),
			mk(ModeRuleDirect, "direct", direct),
		}
	}
}
