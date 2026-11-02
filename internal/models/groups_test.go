package models

import (
	"slices"
	"strings"
	"testing"
)

func nodes(ids ...string) []Node {
	out := make([]Node, len(ids))
	for i, id := range ids {
		out[i] = Node{ID: id, Name: id}
	}
	return out
}

func TestReconcilePrunesMembersAndFixesCurrent(t *testing.T) {
	d := AppData{
		Nodes: nodes("a", "b", "c"),
		Groups: []Group{
			{ID: "g1", Name: "G", Strategy: StrategySelect, Members: []string{"a", "gone", "b", "a"}, Current: "gone"},
			{ID: "g2", Name: "H", Strategy: StrategyFallback, Members: []string{"b", "c"}, Current: "c"},
		},
	}
	d.ReconcileGroups()
	if got := d.Groups[0].Members; !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("members = %v", got)
	}
	if d.Groups[0].Current != "a" {
		t.Errorf("a vanished current falls back to the first member, got %q", d.Groups[0].Current)
	}
	if d.Groups[1].Current != "c" {
		t.Errorf("a valid current is kept, got %q", d.Groups[1].Current)
	}
}

func TestReconcileFollowGroupTracksSubscription(t *testing.T) {
	ns := nodes("a", "b", "c")
	ns[0].Source, ns[2].Source = "sub1", "sub1"
	d := AppData{
		Nodes:         ns,
		Subscriptions: []Subscription{{ID: "sub1"}},
		Groups:        []Group{{ID: "g", Name: "All", Strategy: StrategyURLTest, Source: "sub1", Follow: true, Members: []string{"b"}}},
	}
	d.ReconcileGroups()
	if got := d.Groups[0].Members; !slices.Equal(got, []string{"a", "c"}) {
		t.Errorf("members = %v", got)
	}
}

func TestReconcileDropsGroupsOfRemovedSubscriptions(t *testing.T) {
	d := AppData{
		Nodes: nodes("a"),
		Groups: []Group{
			{ID: "g1", Source: "gone", Members: []string{"a"}},
			{ID: "g2", Members: []string{"a"}},
		},
		ActiveGroupID: "g1",
	}
	d.ReconcileGroups()
	if len(d.Groups) != 1 || d.Groups[0].ID != "g2" {
		t.Fatalf("groups = %+v", d.Groups)
	}
	if d.ActiveGroupID != "" {
		t.Errorf("active group %q survived its deletion", d.ActiveGroupID)
	}
}

func TestReconcileActiveGroupDrivesActiveNode(t *testing.T) {
	d := AppData{
		Nodes:         nodes("a", "b"),
		Groups:        []Group{{ID: "g", Strategy: StrategySelect, Members: []string{"a", "b"}, Current: "b"}},
		ActiveGroupID: "g",
		ActiveNodeID:  "a",
	}
	d.ReconcileGroups()
	if d.ActiveNodeID != "b" {
		t.Errorf("active node = %q, want the group's current server", d.ActiveNodeID)
	}
}

func TestReconcileEmptyActiveGroupIsDeactivated(t *testing.T) {
	d := AppData{
		Nodes:         nodes("a"),
		Groups:        []Group{{ID: "g", Strategy: StrategySelect, Members: []string{"gone"}}},
		ActiveGroupID: "g",
		ActiveNodeID:  "a",
	}
	d.ReconcileGroups()
	if d.ActiveGroupID != "" || d.ActiveNodeID != "a" {
		t.Errorf("active group %q node %q", d.ActiveGroupID, d.ActiveNodeID)
	}
	if len(d.Groups) != 1 {
		t.Errorf("an emptied group is kept so the user can refill it")
	}
}

func TestReconcileLeavesDataWithoutGroupsAlone(t *testing.T) {
	d := DefaultAppData()
	d.Nodes = nodes("a")
	d.ActiveNodeID = "a"
	d.ReconcileGroups()
	if d.ActiveNodeID != "a" || d.Groups == nil || len(d.Groups) != 0 {
		t.Errorf("node %q groups %v", d.ActiveNodeID, d.Groups)
	}
}

func TestCloneCopiesGroups(t *testing.T) {
	d := AppData{Groups: []Group{{ID: "g", Members: []string{"a"}}}}
	c := d.Clone()
	c.Groups[0].Members[0] = "changed"
	if d.Groups[0].Members[0] != "a" {
		t.Error("Clone shares group members")
	}
}

func TestFindGroup(t *testing.T) {
	d := AppData{Groups: []Group{{ID: "g"}}}
	if _, ok := d.FindGroup("g"); !ok {
		t.Error("not found")
	}
	if _, ok := d.FindGroup("x"); ok {
		t.Error("found a ghost")
	}
}

func TestValidateGroup(t *testing.T) {
	ns := nodes("a", "b")
	cases := []struct {
		name string
		g    Group
		want string // substring of the error, "" for valid
	}{
		{"ok", Group{Name: "G", Strategy: StrategyFallback, Members: []string{"a", "b"}}, ""},
		{"no name", Group{Strategy: StrategySelect, Members: []string{"a"}}, "name"},
		{"bad strategy", Group{Name: "G", Strategy: "random", Members: []string{"a"}}, "strategy"},
		{"no members", Group{Name: "G", Strategy: StrategySelect}, "at least one"},
		{"unknown member", Group{Name: "G", Strategy: StrategySelect, Members: []string{"zzz"}}, "no longer"},
		{"duplicate member", Group{Name: "G", Strategy: StrategySelect, Members: []string{"a", "a"}}, "twice"},
		{"too long", Group{Name: string(make([]byte, 70)), Strategy: StrategySelect, Members: []string{"a"}}, "name"},
	}
	for _, c := range cases {
		err := c.g.Validate(ns)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: got %v, want mention of %q", c.name, err, c.want)
		}
	}
}
