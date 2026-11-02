package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keyway/internal/appupdate"
	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/service"
	"keyway/internal/store"
)

type stubUpdater struct{}

func (stubUpdater) Current() string { return "v0.2.1" }
func (stubUpdater) Latest(context.Context) (appupdate.Release, error) {
	return appupdate.Release{Tag: "v0.2.2"}, nil
}
func (stubUpdater) Download(_ context.Context, r appupdate.Release, dir string, _ func(done, total int64)) (string, error) {
	return filepath.Join(dir, r.DiskImage()), nil
}

func updateHandler(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	m, err := core.NewManager(filepath.Join(dir, "engines", "xray"), core.XraySource)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := service.New(service.Config{
		Store: st, Engines: []service.EngineSlot{{Engine: engine.Xray{}, Manager: m}},
		Runner: engine.NewRunner(filepath.Join(dir, "xray.pid")), Dir: dir,
		AppUpdater: stubUpdater{}, DownloadsDir: filepath.Join(dir, "Downloads"),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(svc, Config{Token: "tok", Port: 1234})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

func call(h http.Handler, method, path string) (int, map[string]any) {
	r := httptest.NewRequest(method, path, strings.NewReader(""))
	r.Host = "127.0.0.1:1234"
	r.Header.Set(TokenHeader, "tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestAppUpdateEndpoints(t *testing.T) {
	h := updateHandler(t)

	code, out := call(h, "GET", "/api/app-update")
	if u, _ := out["update"].(map[string]any); code != 200 || u["current"] != "v0.2.1" || u["available"] != false {
		t.Fatalf("GET: %d %v", code, out)
	}

	code, out = call(h, "POST", "/api/app-update/check")
	if u, _ := out["update"].(map[string]any); code != 200 || u["latest"] != "v0.2.2" || u["available"] != true {
		t.Fatalf("check: %d %v", code, out)
	}

	code, out = call(h, "POST", "/api/app-update/download")
	if u, _ := out["update"].(map[string]any); code != 200 || u["download"] == nil {
		t.Fatalf("download: %d %v", code, out)
	}
	time.Sleep(50 * time.Millisecond) // let the background download finish before the temp dir goes
}

func TestAppUpdateNeedsTheToken(t *testing.T) {
	h := updateHandler(t)
	r := httptest.NewRequest("GET", "/api/app-update", nil)
	r.Host = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", w.Code)
	}
}
