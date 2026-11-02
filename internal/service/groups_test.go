package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"keyway/internal/models"
)

func node(id string) models.Node {
	return models.Node{ID: id, Name: id, LatencyMs: models.LatencyUnknown}
}

func nodeList(ids ...string) []models.Node {
	out := make([]models.Node, len(ids))
	for i, id := range ids {
		out[i] = node(id)
	}
	return out
}

func TestGroupChoiceFallbackTakesTheFirstThatWorks(t *testing.T) {
	g := models.Group{Strategy: models.StrategyFallback, Current: "b"}
	ms := nodeList("a", "b", "c")
	cases := []struct {
		name string
		lat  map[string]int64
		want string
	}{
		{"primary is back", map[string]int64{"a": 300, "b": 20, "c": 10}, "a"},
		{"primary down", map[string]int64{"a": models.LatencyFailed, "b": 90, "c": 10}, "b"},
		{"first two down", map[string]int64{"a": models.LatencyFailed, "b": models.LatencyFailed, "c": 500}, "c"},
		{"unmeasurable counts as usable", map[string]int64{"a": models.LatencyFailed, "b": models.LatencyNA, "c": 5}, "b"},
		{"never measured counts as usable", map[string]int64{"a": models.LatencyFailed}, "b"},
		{"all down keeps the current one", map[string]int64{"a": models.LatencyFailed, "b": models.LatencyFailed, "c": models.LatencyFailed}, "b"},
	}
	for _, c := range cases {
		if got := groupChoice(g, ms, c.lat); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestGroupChoiceURLTestUsesHysteresis(t *testing.T) {
	g := models.Group{Strategy: models.StrategyURLTest, Current: "a"}
	ms := nodeList("a", "b", "c")
	cases := []struct {
		name string
		lat  map[string]int64
		want string
	}{
		{"slightly faster rival does not win", map[string]int64{"a": 100, "b": 90, "c": 95}, "a"},
		{"clearly faster rival wins", map[string]int64{"a": 400, "b": 100, "c": 250}, "b"},
		{"current is down", map[string]int64{"a": models.LatencyFailed, "b": 300, "c": 200}, "c"},
		{"current was not measured", map[string]int64{"b": 300, "c": 200}, "c"},
		{"everything is down keeps the current one", map[string]int64{"a": models.LatencyFailed, "b": models.LatencyFailed, "c": models.LatencyFailed}, "a"},
		{"n/a members are never chosen", map[string]int64{"a": 400, "b": models.LatencyNA, "c": 100}, "c"},
	}
	for _, c := range cases {
		if got := groupChoice(g, ms, c.lat); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	g.Current = ""
	if got := groupChoice(g, ms, map[string]int64{"a": 50, "b": 10}); got != "b" {
		t.Errorf("a group without a current member takes the best one, got %q", got)
	}
}

func TestGroupChoiceSelectNeverMoves(t *testing.T) {
	g := models.Group{Strategy: models.StrategySelect, Current: "c"}
	if got := groupChoice(g, nodeList("a", "b", "c"), map[string]int64{"a": 1, "b": 1, "c": models.LatencyFailed}); got != "c" {
		t.Errorf("the user's pick stays, got %q", got)
	}
}

// ---- service level ----

// importNodes adds servers by share link and returns their IDs in order.
func importNodes(t *testing.T, svc *Service, links ...string) []string {
	t.Helper()
	if _, err := svc.Import(context.Background(), strings.Join(links, "\n"), ""); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, l := range links {
		for _, n := range svc.store.Get().Nodes {
			if n.RawLink == l {
				ids = append(ids, n.ID)
			}
		}
	}
	if len(ids) != len(links) {
		t.Fatalf("imported %d of %d", len(ids), len(links))
	}
	return ids
}

func vlessAt(host string, port int, name string) string {
	return fmt.Sprintf("vless://b831381d-6324-4d53-ad4f-8cda48b30811@%s:%d?security=none&type=tcp#%s", host, port, name)
}

func TestCreateGroupAndActivate(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)

	g, err := svc.CreateGroup(GroupInput{Name: "Mine", Strategy: models.StrategySelect, Members: ids})
	if err != nil {
		t.Fatal(err)
	}
	if g.Current != ids[0] || g.MemberCount != 2 {
		t.Fatalf("group = %+v", g)
	}
	if err := svc.SetActiveGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	d := svc.store.Get()
	if d.ActiveGroupID != g.ID || d.ActiveNodeID != ids[0] {
		t.Fatalf("active group %q node %q", d.ActiveGroupID, d.ActiveNodeID)
	}

	if err := svc.SelectGroupMember(g.ID, ids[1]); err != nil {
		t.Fatal(err)
	}
	if got := svc.store.Get().ActiveNodeID; got != ids[1] {
		t.Errorf("choosing a member of the active group switches the server, got %q", got)
	}

	if err := svc.SetActive(ids[0]); err != nil {
		t.Fatal(err)
	}
	if d := svc.store.Get(); d.ActiveGroupID != "" || d.ActiveNodeID != ids[0] {
		t.Errorf("picking a plain server leaves the group: group %q node %q", d.ActiveGroupID, d.ActiveNodeID)
	}
	st := svc.State()
	if len(st.Groups) != 1 || st.ActiveGroupID != "" {
		t.Errorf("state groups = %+v active %q", st.Groups, st.ActiveGroupID)
	}
}

func TestGroupValidationMessages(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)
	cases := []struct {
		name string
		in   GroupInput
		want string
	}{
		{"strategy", GroupInput{Name: "G", Strategy: "random", Members: ids}, "strategy"},
		{"empty", GroupInput{Name: "G", Strategy: models.StrategySelect}, "at least one"},
		{"ghost", GroupInput{Name: "G", Strategy: models.StrategySelect, Members: []string{"nope"}}, "no longer"},
		{"unknown subscription", GroupInput{Name: "G", Strategy: models.StrategySelect, SubscriptionID: "nope"}, "subscription"},
	}
	for _, c := range cases {
		_, err := svc.CreateGroup(c.in)
		var ve *models.ValidationError
		if err == nil || !asValidation(err, &ve) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func asValidation(err error, target **models.ValidationError) bool {
	return errors.As(err, target)
}

func TestSelectGroupMemberOnlyForSelectGroups(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)
	g, err := svc.CreateGroup(GroupInput{Name: "Auto", Strategy: models.StrategyURLTest, Members: ids})
	if err != nil {
		t.Fatal(err)
	}
	err = svc.SelectGroupMember(g.ID, ids[1])
	if err == nil || !strings.Contains(err.Error(), "chosen automatically") {
		t.Errorf("err = %v", err)
	}
	g2, _ := svc.CreateGroup(GroupInput{Name: "Pick", Strategy: models.StrategySelect, Members: ids[:1]})
	if err := svc.SelectGroupMember(g2.ID, ids[1]); err == nil || !strings.Contains(err.Error(), "not in this group") {
		t.Errorf("err = %v", err)
	}
}

func TestGroupsCannotBeChainHops(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)
	g, err := svc.CreateGroup(GroupInput{Name: "Auto", Strategy: models.StrategyURLTest, Members: ids})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.CreateNode(NodeInput{Name: "c", Chain: []string{ids[0], g.ID}})
	if err == nil || !strings.Contains(err.Error(), "hop 2 “Auto” is a group; a chain can only contain single servers") {
		t.Errorf("err = %v", err)
	}
	// but a chain can be a member of a group
	chain, err := svc.CreateNode(NodeInput{Name: "c", Chain: ids})
	if err != nil {
		t.Skipf("chain creation needs engines here: %v", err)
	}
	if _, err := svc.CreateGroup(GroupInput{Name: "WithChain", Strategy: models.StrategySelect, Members: []string{chain.ID}}); err != nil {
		t.Errorf("a chain may be a group member: %v", err)
	}
}

func TestDeletingTheCurrentMemberMovesTheActiveGroupOn(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)
	g, _ := svc.CreateGroup(GroupInput{Name: "G", Strategy: models.StrategySelect, Members: ids})
	if err := svc.SetActiveGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DeleteNodes(ids[0]); err != nil {
		t.Fatal(err)
	}
	if d := svc.store.Get(); d.ActiveNodeID != ids[1] || d.ActiveGroupID != g.ID {
		t.Errorf("node %q group %q", d.ActiveNodeID, d.ActiveGroupID)
	}
}

func TestUpdateAndDeleteGroup(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)
	g, _ := svc.CreateGroup(GroupInput{Name: "G", Strategy: models.StrategySelect, Members: ids[:1]})
	got, err := svc.UpdateGroup(g.ID, GroupInput{Name: "Renamed", Strategy: models.StrategyFallback, Members: []string{ids[1], ids[0]}})
	if err != nil || got.Name != "Renamed" || got.Strategy != models.StrategyFallback || got.Members[0] != ids[1] {
		t.Fatalf("got %+v err %v", got, err)
	}
	if err := svc.DeleteGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteGroup(g.ID); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("err = %v", err)
	}
	if _, err := svc.UpdateGroup("nope", GroupInput{}); !errors.Is(err, ErrGroupNotFound) {
		t.Errorf("err = %v", err)
	}
}

func TestDeletingTheActiveGroupKeepsTheServer(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA)
	g, _ := svc.CreateGroup(GroupInput{Name: "G", Strategy: models.StrategySelect, Members: ids})
	_ = svc.SetActiveGroup(g.ID)
	if err := svc.DeleteGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if d := svc.store.Get(); d.ActiveGroupID != "" || d.ActiveNodeID != ids[0] {
		t.Errorf("group %q node %q", d.ActiveGroupID, d.ActiveNodeID)
	}
}

// listener returns the port of a TCP listener that accepts connections.
func listener(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

// deadPort returns a loopback port nothing listens on.
func deadPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestEvaluateFallbackGroupSkipsDeadServers(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc,
		vlessAt("127.0.0.1", deadPort(t), "Dead"),
		vlessAt("127.0.0.1", listener(t), "Live1"),
		vlessAt("127.0.0.1", listener(t), "Live2"))
	g, err := svc.CreateGroup(GroupInput{Name: "FB", Strategy: models.StrategyFallback, Members: ids})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetActiveGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	res, err := svc.EvaluateGroup(context.Background(), g.ID, ModeTCP, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != ids[1] || !res.Changed {
		t.Fatalf("result = %+v", res)
	}
	if d := svc.store.Get(); d.ActiveNodeID != ids[1] || d.Groups[0].Current != ids[1] {
		t.Errorf("active node %q current %q", d.ActiveNodeID, d.Groups[0].Current)
	}
	if n, _ := svc.store.Get().FindNode(ids[0]); n.LatencyMs != models.LatencyFailed {
		t.Errorf("latencies of the members are stored: %d", n.LatencyMs)
	}
}

func TestEvaluateGroupAllFailed(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessAt("127.0.0.1", deadPort(t), "D1"), vlessAt("127.0.0.1", deadPort(t), "D2"))
	g, _ := svc.CreateGroup(GroupInput{Name: "A", Strategy: models.StrategyURLTest, Members: ids})
	res, err := svc.EvaluateGroup(context.Background(), g.ID, ModeTCP, false)
	if !errors.Is(err, ErrAllFailed) {
		t.Fatalf("err = %v", err)
	}
	if res.Latency[ids[0]] != models.LatencyFailed {
		t.Errorf("the measured latencies are still reported: %+v", res.Latency)
	}
	if got := svc.store.Get().Groups[0].Current; got != ids[0] {
		t.Errorf("nothing works: the current member stays, got %q", got)
	}
}

func TestSetActiveGroupUsesKnownLatencies(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessA, vlessB)
	svc.applyLatencies(map[string]int64{ids[0]: models.LatencyFailed, ids[1]: 80})
	g, _ := svc.CreateGroup(GroupInput{Name: "FB", Strategy: models.StrategyFallback, Members: ids})
	if err := svc.SetActiveGroup(g.ID); err != nil {
		t.Fatal(err)
	}
	if got := svc.store.Get().ActiveNodeID; got != ids[1] {
		t.Errorf("activating an automatic group starts from what is already known, got %q", got)
	}
}

func TestAutoPickLeavesAnActiveGroupAlone(t *testing.T) {
	svc := newTestService(t)
	ids := importNodes(t, svc, vlessAt("127.0.0.1", listener(t), "A"), vlessAt("127.0.0.1", listener(t), "B"))
	g, _ := svc.CreateGroup(GroupInput{Name: "G", Strategy: models.StrategySelect, Members: ids[:1]})
	_ = svc.SetActiveGroup(g.ID)
	switched, err := svc.AutoPickOnce(context.Background())
	if err != nil || switched {
		t.Fatalf("switched=%v err=%v", switched, err)
	}
	if svc.store.Get().ActiveGroupID != g.ID {
		t.Error("auto-pick dropped the group")
	}
}

func TestFollowGroupOfASubscription(t *testing.T) {
	body := vlessA + "\n" + vlessB + "\n"
	srv := subServer(t, nil, &body)
	svc := newTestService(t)
	sub, _, _, err := svc.AddSubscription(context.Background(), "S", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	g, err := svc.CreateGroup(GroupInput{Name: "All of S", Strategy: models.StrategyURLTest, SubscriptionID: sub.ID})
	if err != nil {
		t.Fatal(err)
	}
	if g.MemberCount != 2 || !g.Follow || g.Source != sub.ID {
		t.Fatalf("group = %+v", g)
	}
	if _, err := svc.CreateGroup(GroupInput{Name: "again", Strategy: models.StrategySelect, SubscriptionID: sub.ID}); err == nil ||
		!strings.Contains(err.Error(), "already has a group") {
		t.Errorf("err = %v", err)
	}

	// the provider adds a server: the group follows
	body = vlessA + "\n" + vlessB + "\n" + vlessAt("c.example.com", 443, "Gamma") + "\n"
	if _, _, _, err := svc.RefreshSubscription(context.Background(), sub.ID); err != nil {
		t.Fatal(err)
	}
	if got := svc.State().Groups[0].MemberCount; got != 3 {
		t.Errorf("members = %d", got)
	}
	// members and strategy of a followed subscription: members cannot be edited
	if _, err := svc.UpdateGroup(g.ID, GroupInput{Name: "x", Strategy: models.StrategySelect, Members: []string{"a"}}); err == nil {
		t.Error("the members of a subscription group are the subscription's servers")
	}
	// removing the subscription removes its group
	if err := svc.RemoveSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	if len(svc.store.Get().Groups) != 0 {
		t.Error("group outlived its subscription")
	}
}

const clashSub = `proxies:
  - {name: HK 01, type: ss, server: hk.example.com, port: 8388, cipher: aes-256-gcm, password: p1}
  - {name: JP 01, type: ss, server: jp.example.com, port: 8388, cipher: aes-256-gcm, password: p2}
proxy-groups:
  - {name: Proxy, type: select, proxies: [HK 01, JP 01]}
  - {name: Spread, type: load-balance, proxies: [HK 01, JP 01]}
`

func TestClashSubscriptionGroups(t *testing.T) {
	body := clashSub
	srv := subServer(t, nil, &body)
	svc := newTestService(t)
	sub, added, errs, err := svc.AddSubscription(context.Background(), "C", srv.URL)
	if err != nil || added != 2 {
		t.Fatalf("added=%d err=%v", added, err)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "Spread") || !strings.Contains(errs[0], "load-balance") {
		t.Errorf("the import reports the skipped group: %v", errs)
	}
	got, _ := svc.findSub(sub.ID)
	if len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "Spread") {
		t.Errorf("the subscription keeps its warnings: %v", got.Warnings)
	}
	gs := svc.store.Get().Groups
	if len(gs) != 1 || gs[0].Name != "Proxy" || gs[0].Source != sub.ID || gs[0].Follow || len(gs[0].Members) != 2 {
		t.Fatalf("groups = %+v", gs)
	}

	// a refresh keeps the group's identity and the user's choice
	id, chosen := gs[0].ID, gs[0].Members[1]
	if err := svc.SelectGroupMember(id, chosen); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := svc.RefreshSubscription(context.Background(), sub.ID); err != nil {
		t.Fatal(err)
	}
	gs = svc.store.Get().Groups
	if len(gs) != 1 || gs[0].ID != id || gs[0].Current != chosen {
		t.Errorf("after refresh: %+v", gs)
	}

	// a group that vanished from the file vanishes here; the file is the source of truth
	body = strings.Replace(clashSub, "- {name: Proxy, type: select, proxies: [HK 01, JP 01]}", "- {name: Other, type: fallback, proxies: [JP 01]}", 1)
	if _, _, _, err := svc.RefreshSubscription(context.Background(), sub.ID); err != nil {
		t.Fatal(err)
	}
	gs = svc.store.Get().Groups
	if len(gs) != 1 || gs[0].Name != "Other" || gs[0].Strategy != models.StrategyFallback {
		t.Errorf("after the file changed: %+v", gs)
	}

	// imported groups belong to the subscription
	if err := svc.DeleteGroup(gs[0].ID); err == nil || !strings.Contains(err.Error(), "subscription") {
		t.Errorf("deleting an imported group: %v", err)
	}
	if _, err := svc.UpdateGroup(gs[0].ID, GroupInput{Name: "x", Strategy: models.StrategySelect, Members: gs[0].Members}); err == nil {
		t.Error("an imported group is edited in the subscription's file, not here")
	}
}

func TestPastedClashConfigCreatesGroups(t *testing.T) {
	svc := newTestService(t)
	res, err := svc.Import(context.Background(), clashSub, "")
	if err != nil || res.Added != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "Spread") {
		t.Errorf("errors = %v", res.Errors)
	}
	gs := svc.store.Get().Groups
	if len(gs) != 1 || gs[0].Name != "Proxy" || gs[0].Source != "" {
		t.Fatalf("a pasted config gives groups the user owns: %+v", gs)
	}
	// pasting it again does not pile up copies
	res, _ = svc.Import(context.Background(), clashSub, "")
	if got := len(svc.store.Get().Groups); got != 1 {
		t.Errorf("groups after a second paste = %d (%v)", got, res.Errors)
	}
}
