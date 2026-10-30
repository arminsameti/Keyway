package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"xray-friendly/internal/models"
)

func TestRoundTripAndBackup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(func(d *models.AppData) error {
		d.Nodes = append(d.Nodes, models.Node{ID: "n1", Name: "one"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Update(func(d *models.AppData) error { d.ActiveNodeID = "n1"; return nil }); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := s2.Get()
	if len(d.Nodes) != 1 || d.ActiveNodeID != "n1" {
		t.Fatalf("not persisted: %+v", d)
	}
	if _, err := os.Stat(filepath.Join(dir, "data.json.bak")); err != nil {
		t.Fatalf("expected .bak: %v", err)
	}
	st, _ := os.Stat(filepath.Join(dir, "data.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("data.json perms = %v", st.Mode().Perm())
	}
}

func TestCorruptFileIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Warning() == "" {
		t.Fatal("expected a warning")
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "data.json.corrupt-*"))
	if len(matches) != 1 {
		t.Fatalf("corrupt file should be moved aside, got %v", matches)
	}
	b, _ := os.ReadFile(matches[0])
	if !strings.Contains(string(b), "not json") {
		t.Fatal("quarantined file lost its content")
	}
}

func TestOldFileKeepsNewDefaults(t *testing.T) {
	dir := t.TempDir()
	old := `{"activeNodeId":"x","nodes":[{"id":"x","name":"n","rawLink":"vless://a@b:1","outbound":{"protocol":"vless"}}],
	"settings":{"inbounds":[{"tag":"a","protocol":"socks","port":1080,"listen":"127.0.0.1","enabled":true}],"routingMode":"global","logLevel":"info"}}`
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := s.Get()
	if d.Settings.AutoPickMin != 10 || d.Settings.MuxConcurrency != 8 || d.Settings.SubUpdateHours != 24 {
		t.Fatalf("defaults not applied: %+v", d.Settings)
	}
	if d.Settings.RoutingMode != "global" || len(d.Nodes) != 1 {
		t.Fatalf("old data lost: %+v", d)
	}
}

func TestGetReturnsCopy(t *testing.T) {
	s, _ := Open(t.TempDir())
	_, _ = s.Update(func(d *models.AppData) error { d.Nodes = []models.Node{{ID: "a"}}; return nil })
	g := s.Get()
	g.Nodes[0].ID = "mutated"
	if s.Get().Nodes[0].ID != "a" {
		t.Fatal("Get leaks internal state")
	}
}

func TestFailedUpdateChangesNothing(t *testing.T) {
	s, _ := Open(t.TempDir())
	_, err := s.Update(func(d *models.AppData) error {
		d.ActiveNodeID = "x"
		return os.ErrInvalid
	})
	if err == nil || s.Get().ActiveNodeID != "" {
		t.Fatal("failed update must not be published")
	}
}

// Run with -race: concurrent readers and writers must not race.
func TestConcurrentAccess(t *testing.T) {
	s, _ := Open(t.TempDir())
	_, _ = s.Update(func(d *models.AppData) error {
		for i := 0; i < 20; i++ {
			d.Nodes = append(d.Nodes, models.Node{ID: string(rune('a' + i))})
		}
		return nil
	})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				_, _ = s.Update(func(d *models.AppData) error {
					for j := range d.Nodes {
						d.Nodes[j].LatencyMs = int64(i)
					}
					return nil
				})
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				for _, n := range s.Get().Nodes {
					_ = n.LatencyMs
				}
			}
		}()
	}
	wg.Wait()
}
