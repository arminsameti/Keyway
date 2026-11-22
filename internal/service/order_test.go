package service

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"keyway/internal/models"
)

func seedNodes(t *testing.T, svc *Service, ids ...string) {
	t.Helper()
	if _, err := svc.store.Update(func(d *models.AppData) error {
		d.Nodes = nodeList(ids...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func order(svc *Service) []string {
	var out []string
	for _, n := range svc.store.Get().Nodes {
		out = append(out, n.ID)
	}
	return out
}

func TestMoveNodes(t *testing.T) {
	cases := []struct {
		name          string
		ids           []string
		before, after string
		want          []string
	}{
		{"one before another", []string{"d"}, "b", "", []string{"a", "d", "b", "c", "e"}},
		{"one after another", []string{"a"}, "", "d", []string{"b", "c", "d", "a", "e"}},
		{"to the very end", []string{"b"}, "", "e", []string{"a", "c", "d", "e", "b"}},
		{"to the very start", []string{"e"}, "a", "", []string{"e", "a", "b", "c", "d"}},
		{"several keep their list order", []string{"d", "b"}, "a", "", []string{"b", "d", "a", "c", "e"}},
		{"several after an anchor", []string{"a", "c"}, "", "d", []string{"b", "d", "a", "c", "e"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := newTestService(t)
			seedNodes(t, svc, "a", "b", "c", "d", "e")
			if err := svc.MoveNodes(c.ids, c.before, c.after); err != nil {
				t.Fatal(err)
			}
			if got := order(svc); !reflect.DeepEqual(got, c.want) {
				t.Errorf("order = %v, want %v", got, c.want)
			}
		})
	}
}

func TestMoveNodesRefusesBadInput(t *testing.T) {
	svc := newTestService(t)
	seedNodes(t, svc, "a", "b", "c")
	bad := []struct {
		name          string
		ids           []string
		before, after string
	}{
		{"no servers", nil, "a", ""},
		{"no anchor", []string{"a"}, "", ""},
		{"two anchors", []string{"a"}, "b", "c"},
		{"unknown server", []string{"zzz"}, "a", ""},
		{"unknown anchor", []string{"a"}, "zzz", ""},
		{"anchor is being moved", []string{"a", "b"}, "b", ""},
	}
	for _, c := range bad {
		err := svc.MoveNodes(c.ids, c.before, c.after)
		var ve *models.ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("%s: err = %v, want a validation error", c.name, err)
		}
	}
	if got := order(svc); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("a refused move changed the order: %v", got)
	}
}

func TestTestLatencyOnlyMeasuresTheGivenServers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port

	svc := newTestService(t)
	if _, err := svc.store.Update(func(d *models.AppData) error {
		d.Nodes = nodeList("a", "b", "c")
		for i := range d.Nodes {
			d.Nodes[i].Protocol, d.Nodes[i].Server, d.Nodes[i].Port = "vless", "127.0.0.1", port
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	lat, _, err := svc.TestLatency(context.Background(), "tcp", "b", "c")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := lat["a"]; ok || len(lat) != 2 {
		t.Fatalf("measured %v, want only b and c", lat)
	}
	for _, n := range svc.store.Get().Nodes {
		measured := n.LatencyMs >= 0
		if measured != (n.ID != "a") {
			t.Errorf("node %s latency %d: only b and c should have been stored", n.ID, n.LatencyMs)
		}
	}
	if _, _, err := svc.TestLatency(context.Background(), "tcp", "nope"); err == nil {
		t.Error("an unknown server must be refused")
	}
}
