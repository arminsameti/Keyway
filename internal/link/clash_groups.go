package link

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"keyway/internal/models"
)

// GroupSpec is a proxy group found in a config, with its members already
// resolved to the IDs of imported servers.
type GroupSpec struct {
	Name     string
	Strategy string   // models.Strategy*
	Members  []string // node IDs in the group's own order
}

// clashStrategies maps the Clash group types Keyway has an equivalent for.
// Anything else (load-balance, relay, ...) is reported, never approximated.
var clashStrategies = map[string]string{
	"select":   models.StrategySelect,
	"url-test": models.StrategyURLTest,
	"fallback": models.StrategyFallback,
}

// MapClashGroups turns the "proxy-groups" of a Clash config into groups of the
// servers in items (the result of classifying the same text). Members are
// matched by name; entries that are not imported servers (DIRECT, REJECT,
// other groups, servers Keyway cannot run) are left out. Every group that is
// skipped or shortened is named in the warnings, which never contain server
// addresses. Text that is not a Clash config yields nothing.
func MapClashGroups(text string, items []Item) ([]GroupSpec, []string) {
	if !LooksLikeClash(text) {
		return nil, nil
	}
	var doc struct {
		Groups []struct {
			Name    string `yaml:"name"`
			Type    string `yaml:"type"`
			Proxies []any  `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, []string{"Groups could not be read: " + firstLine(err.Error())}
	}
	ids := map[string]string{} // entry name -> node ID; the first of equal names wins
	for _, it := range items {
		if it.Kind == KindReady && it.Name != "" {
			if _, dup := ids[it.Name]; !dup {
				ids[it.Name] = it.Result.Node.ID
			}
		}
	}

	var specs []GroupSpec
	var warns []string
	for _, g := range doc.Groups {
		name, typ := strings.TrimSpace(g.Name), strings.ToLower(strings.TrimSpace(g.Type))
		strategy, ok := clashStrategies[typ]
		if !ok {
			warns = append(warns, fmt.Sprintf("Group “%s” skipped: %s groups are not supported", name, typ))
			continue
		}
		spec := GroupSpec{Name: name, Strategy: strategy}
		seen := map[string]bool{}
		left := 0
		for _, e := range g.Proxies {
			id, found := ids[strings.TrimSpace(fmt.Sprint(e))]
			switch {
			case !found:
				left++
			case !seen[id]:
				seen[id] = true
				spec.Members = append(spec.Members, id)
			}
		}
		switch {
		case name == "":
			warns = append(warns, "A group without a name was skipped")
		case len(spec.Members) == 0:
			warns = append(warns, fmt.Sprintf("Group “%s” skipped: none of its %d entries is a server that was imported", name, len(g.Proxies)))
		default:
			specs = append(specs, spec)
			if left > 0 {
				warns = append(warns, fmt.Sprintf("Group “%s”: %d of %d entries left out (DIRECT, REJECT, other groups or servers that could not be imported)", name, left, len(g.Proxies)))
			}
		}
	}
	return specs, warns
}
