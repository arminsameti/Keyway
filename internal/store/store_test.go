package store

import (
	"os"
	"path/filepath"
	"testing"

	"keyway/internal/models"
)

// legacyData is a data.json as written before subscription details and groups
// existed (schema 3): it must keep loading unchanged.
const legacyData = `{
  "version": 3,
  "activeNodeId": "n2",
  "engines": {"xray": "v25.1.1"},
  "engineChecks": {},
  "nodes": [
    {"id": "n1", "name": "Alpha", "protocol": "vless", "server": "a.example", "port": 443,
     "rawLink": "vless://u@a.example:443#Alpha", "source": "s1", "createdAt": "2025-01-02T03:04:05Z", "latencyMs": 120},
    {"id": "n2", "name": "Beta", "protocol": "trojan", "server": "b.example", "port": 443,
     "rawLink": "trojan://p@b.example:443#Beta", "createdAt": "2025-01-02T03:04:05Z", "latencyMs": -1}
  ],
  "subscriptions": [
    {"id": "s1", "name": "Provider", "url": "https://sub.example/x", "updatedAt": "2025-02-01T00:00:00Z",
     "nodeCount": 1, "format": "links"}
  ],
  "settings": {"routingMode": "global", "subUpdateHours": 12, "autoPick": true,
    "inbounds": [{"tag": "socks-in", "protocol": "socks", "port": 10808, "listen": "127.0.0.1", "udp": true, "enabled": true}]}
}`

func TestOpenLoadsDataWrittenBeforeGroupsUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(legacyData), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Warning() != "" {
		t.Fatalf("legacy data was set aside: %s", s.Warning())
	}
	d := s.Get()
	if len(d.Nodes) != 2 || d.Nodes[0].ID != "n1" || d.Nodes[0].Source != "s1" || d.Nodes[0].LatencyMs != 120 {
		t.Errorf("nodes = %+v", d.Nodes)
	}
	if d.ActiveNodeID != "n2" || d.ActiveGroupID != "" {
		t.Errorf("active node %q group %q", d.ActiveNodeID, d.ActiveGroupID)
	}
	if len(d.Subscriptions) != 1 {
		t.Fatalf("subscriptions = %+v", d.Subscriptions)
	}
	sub := d.Subscriptions[0]
	if sub.Name != "Provider" || sub.NodeCount != 1 || sub.Format != "links" || sub.Usage != nil || sub.Title != "" || sub.UpdateHours != 0 || len(sub.Warnings) != 0 {
		t.Errorf("subscription = %+v", sub)
	}
	if d.Groups == nil || len(d.Groups) != 0 {
		t.Errorf("groups = %#v, want an empty list", d.Groups)
	}
	if d.Settings.RoutingMode != "global" || d.Settings.SubUpdateHours != 12 || !d.Settings.AutoPick {
		t.Errorf("settings = %+v", d.Settings)
	}

	// saving and reloading keeps everything, now including the empty group list
	if _, err := s.Update(func(*models.AppData) error { return nil }); err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := again.Get(); got.ActiveNodeID != "n2" || len(got.Nodes) != 2 || len(got.Subscriptions) != 1 {
		t.Errorf("after a save: %+v", got)
	}
}

func TestGroupsAreReconciledOnEveryUpdate(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Update(func(d *models.AppData) error {
		d.Nodes = []models.Node{{ID: "a"}, {ID: "b"}}
		d.Groups = []models.Group{{ID: "g", Name: "G", Strategy: models.StrategySelect, Members: []string{"a", "b"}, Current: "b"}}
		d.ActiveGroupID = "g"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Get(); got.ActiveNodeID != "b" {
		t.Fatalf("active node = %q", got.ActiveNodeID)
	}
	// deleting the group's current member moves the group (and the active node) on
	d, err := s.Update(func(d *models.AppData) error {
		d.Nodes = d.Nodes[:1]
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.ActiveNodeID != "a" || d.Groups[0].Current != "a" || len(d.Groups[0].Members) != 1 {
		t.Errorf("after deleting b: node %q group %+v", d.ActiveNodeID, d.Groups[0])
	}
}
