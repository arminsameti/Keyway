package models

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// Group strategies, named as in Clash.
const (
	StrategySelect   = "select"   // the user picks the server
	StrategyFallback = "fallback" // the first member that works, in list order
	StrategyURLTest  = "url-test" // the fastest member, with hysteresis
)

const maxGroupName = 64

var strategies = map[string]bool{StrategySelect: true, StrategyFallback: true, StrategyURLTest: true}

// Group is a set of servers that act as one selectable "server". Its Current
// member is what a connection actually uses while the group is active.
//
// A group is made by hand (Source empty), follows a subscription (Source set,
// Follow true: its members are always every server of that subscription), or
// is imported from a subscription's Clash proxy-groups (Source set, Follow
// false: refreshed together with the subscription).
//
// Members are plain servers or chains, never other groups, and a group cannot
// be a hop of a chain.
type Group struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Strategy string   `json:"strategy"`          // select | fallback | url-test
	Members  []string `json:"members"`           // node IDs, in priority order (fallback walks this list)
	Current  string   `json:"current,omitempty"` // member in use: the user's pick for select, the automatic choice otherwise
	Source   string   `json:"source,omitempty"`  // subscription ID; empty for groups made by hand
	Follow   bool     `json:"follow,omitempty"`  // members are all servers of Source
}

// Imported reports whether the group came from a subscription's own group
// definitions, so a refresh owns its name, strategy and members.
func (g Group) Imported() bool { return g.Source != "" && !g.Follow }

// FindGroup returns the group with the given ID.
func (d AppData) FindGroup(id string) (Group, bool) {
	for _, g := range d.Groups {
		if g.ID == id {
			return g, true
		}
	}
	return Group{}, false
}

// Validate checks a group against the servers it may contain.
func (g Group) Validate(nodes []Node) error {
	name := strings.TrimSpace(g.Name)
	if name == "" || utf8.RuneCountInString(name) > maxGroupName {
		return invalid("a group needs a name of up to %d characters", maxGroupName)
	}
	if !strategies[g.Strategy] {
		return invalid("unknown group strategy %q (use select, fallback or url-test)", g.Strategy)
	}
	if len(g.Members) == 0 {
		return invalid("a group needs at least one server")
	}
	have := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		have[n.ID] = true
	}
	seen := map[string]bool{}
	for i, id := range g.Members {
		switch {
		case !have[id]:
			return invalid("member %d is no longer in your server list", i+1)
		case seen[id]:
			return invalid("a server cannot be in a group twice")
		}
		seen[id] = true
	}
	return nil
}

// ReconcileGroups restores the invariants between groups, servers and
// subscriptions after any change: groups of removed subscriptions are dropped,
// members that no longer exist are pruned, Current is always a member, and the
// active group (if any) decides the active server. It runs on every store update.
func (d *AppData) ReconcileGroups() {
	if d.Groups == nil {
		d.Groups = []Group{}
	}
	nodeIDs := make(map[string]bool, len(d.Nodes))
	for _, n := range d.Nodes {
		nodeIDs[n.ID] = true
	}
	subs := make(map[string]bool, len(d.Subscriptions))
	for _, s := range d.Subscriptions {
		subs[s.ID] = true
	}
	kept := d.Groups[:0]
	for _, g := range d.Groups {
		if g.Source != "" && !subs[g.Source] {
			continue
		}
		if g.Follow {
			g.Members = g.Members[:0:0]
			for _, n := range d.Nodes {
				if n.Source == g.Source {
					g.Members = append(g.Members, n.ID)
				}
			}
		} else {
			members := make([]string, 0, len(g.Members))
			for _, id := range g.Members {
				if nodeIDs[id] && !slices.Contains(members, id) {
					members = append(members, id)
				}
			}
			g.Members = members
		}
		if !slices.Contains(g.Members, g.Current) {
			g.Current = ""
			if len(g.Members) > 0 {
				g.Current = g.Members[0]
			}
		}
		kept = append(kept, g)
	}
	d.Groups = kept

	if d.ActiveGroupID == "" {
		return
	}
	if g, ok := d.FindGroup(d.ActiveGroupID); ok && g.Current != "" {
		d.ActiveNodeID = g.Current
		return
	}
	d.ActiveGroupID = "" // gone, or left without servers: keep the server that was active
}
