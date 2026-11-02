package service

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/store"
)

// newTestService builds a Service over a temp store with no engine installed
// and no automatic downloads. Subscription fetches go through fetchFrom with
// the SSRF guard off, so httptest servers on loopback work.
func newTestService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := core.NewManager(filepath.Join(dir, "engines", engine.NameXray), core.XraySource)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{
		Store:   st,
		Engines: []EngineSlot{{Engine: engine.Xray{}, Manager: mgr}},
		Runner:  engine.NewRunner(""), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.fetch = func(ctx context.Context, raw string) (subResponse, error) {
		return fetchFrom(ctx, raw, func(net.IP) bool { return false })
	}
	return svc
}
