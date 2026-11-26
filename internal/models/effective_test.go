package models

import (
	"reflect"
	"testing"
)

func TestEffectiveRules(t *testing.T) {
	rule := func(id, out string, e ...string) RouteRule {
		return RouteRule{ID: id, Enabled: true, Entries: e, Outbound: out}
	}
	t.Run("bypass-private default", func(t *testing.T) {
		got := EffectiveRules(Settings{RoutingMode: "bypass-private"})
		want := []RouteRule{
			rule("mode-direct-private", "direct", "geoip:private"),
			rule("mode-direct", "direct", "geosite:private", "geosite:cn"),
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("bypass-private custom direct", func(t *testing.T) {
		got := EffectiveRules(Settings{RoutingMode: "bypass-private", DirectSites: "a.com, b.com\nc.com"})
		if len(got) != 2 || !reflect.DeepEqual(got[1].Entries, []string{"a.com", "b.com", "c.com"}) {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("custom", func(t *testing.T) {
		got := EffectiveRules(Settings{RoutingMode: "custom", ProxySites: "p.com", DirectSites: "d.com"})
		want := []RouteRule{rule("mode-proxy", "proxy", "p.com"), rule("mode-direct", "direct", "d.com")}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("global", func(t *testing.T) {
		if got := EffectiveRules(Settings{RoutingMode: "global"}); len(got) != 0 {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("rules", func(t *testing.T) {
		s := Settings{RoutingMode: "rules", ActiveRuleSet: "s1", RuleSets: []RuleSet{{ID: "s1", Rules: []RouteRule{rule("r1", "direct", "x.com")}}}}
		got := EffectiveRules(s)
		if !reflect.DeepEqual(got, s.ActiveRules()) || len(got) != 1 {
			t.Fatalf("got %+v", got)
		}
	})
}
