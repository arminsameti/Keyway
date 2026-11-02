package link

import (
	"slices"
	"strings"
	"testing"

	"keyway/internal/models"
)

const clashWithGroups = `
proxies:
  - {name: HK 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-256-gcm, password: p1}
  - {name: JP 01, type: ss, server: jp.example.com, port: 8388, cipher: aes-256-gcm, password: p2}
  - {name: US 01, type: ss, server: us.example.com, port: 8388, cipher: aes-256-gcm, password: p3}
  - {name: Odd, type: snell, server: odd.example.com, port: 1234, psk: x}
proxy-groups:
  - {name: Proxy, type: select, proxies: [Auto, HK 01, JP 01, DIRECT]}
  - {name: Auto, type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, proxies: [HK 01, JP 01, US 01]}
  - {name: Backup, type: Fallback, proxies: [US 01, HK 01, HK 01]}
  - {name: Spread, type: load-balance, proxies: [HK 01, JP 01]}
  - {name: Hop, type: relay, proxies: [HK 01, JP 01]}
  - {name: Nothing, type: select, proxies: [DIRECT, REJECT, Odd]}
`

func idOf(t *testing.T, items []Item, name string) string {
	t.Helper()
	for _, it := range items {
		if it.Kind == KindReady && it.Name == name {
			return it.Result.Node.ID
		}
	}
	t.Fatalf("no ready item named %q", name)
	return ""
}

func TestMapClashGroups(t *testing.T) {
	items := Classify(clashWithGroups)
	hk, jp, us := idOf(t, items, "HK 01"), idOf(t, items, "JP 01"), idOf(t, items, "US 01")

	specs, warns := MapClashGroups(clashWithGroups, items)

	byName := map[string]GroupSpec{}
	for _, s := range specs {
		byName[s.Name] = s
	}
	if len(specs) != 3 {
		t.Fatalf("want select, url-test and fallback only, got %+v", specs)
	}
	if g := byName["Proxy"]; g.Strategy != models.StrategySelect || !slices.Equal(g.Members, []string{hk, jp}) {
		t.Errorf("Proxy = %+v (members that are other groups or DIRECT are left out)", g)
	}
	if g := byName["Auto"]; g.Strategy != models.StrategyURLTest || !slices.Equal(g.Members, []string{hk, jp, us}) {
		t.Errorf("Auto = %+v", g)
	}
	if g := byName["Backup"]; g.Strategy != models.StrategyFallback || !slices.Equal(g.Members, []string{us, hk}) {
		t.Errorf("Backup = %+v (type matching is case-insensitive, duplicates collapse, order is kept)", g)
	}

	all := strings.Join(warns, "\n")
	for _, want := range []string{
		"Spread", "load-balance", // skipped, named
		"Hop", "relay",
		"Nothing", // no member could be matched
		"Proxy",   // two of four entries left out
	} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings do not mention %q:\n%s", want, all)
		}
	}
	if strings.Contains(strings.Join(warns, "\n"), "Backup") {
		t.Errorf("a clean group gets no warning:\n%s", all)
	}
}

func TestMapClashGroupsNeverEchoesServerAddresses(t *testing.T) {
	items := Classify(clashWithGroups)
	_, warns := MapClashGroups(clashWithGroups, items)
	for _, w := range warns {
		if strings.Contains(w, "example.com") || strings.Contains(w, "psk") {
			t.Errorf("warning leaks server details: %q", w)
		}
	}
}

func TestMapClashGroupsOtherFormats(t *testing.T) {
	for _, text := range []string{"vless://u@a.example:443#A", "proxies:\n  - {name: A, type: ss, server: a, port: 1, cipher: aes-256-gcm, password: p}\n"} {
		specs, warns := MapClashGroups(text, Classify(text))
		if len(specs) != 0 || len(warns) != 0 {
			t.Errorf("no proxy-groups means nothing to map: %+v %v", specs, warns)
		}
	}
}
