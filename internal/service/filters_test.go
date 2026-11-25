package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"keyway/internal/engine"
	"keyway/internal/filters"
	"keyway/internal/models"
)

// filterEnv is a test service plus a TLS list server whose body can be swapped.
type filterEnv struct {
	svc  *Service
	srv  *httptest.Server
	body atomic.Value // string
	hits atomic.Int32
}

func newFilterEnv(t *testing.T) *filterEnv {
	t.Helper()
	e := &filterEnv{svc: newTestService(t)}
	e.body.Store("||a.com^\n||b.com^\n0.0.0.0 c.com\n")
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.hits.Add(1)
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(e.body.Load().(string)))
	}))
	t.Cleanup(e.srv.Close)
	trustServer(t, e.srv)
	e.svc.fetchGuard = allowAll
	return e
}

func (e *filterEnv) setLists(t *testing.T, blockAds bool, lists ...models.FilterList) {
	t.Helper()
	if _, err := e.svc.store.Update(func(d *models.AppData) error {
		d.Settings.BlockAds = blockAds
		d.Settings.FilterLists = lists
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *filterEnv) custom(id string) models.FilterList {
	return models.FilterList{ID: id, Name: id, URL: e.srv.URL, Enabled: true}
}

func (e *filterEnv) compiled(name string) string {
	return filepath.Join(e.svc.dir, "filters", "compiled", name)
}

func TestRefreshFiltersWritesStatus(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	st := e.svc.store.Get().FilterStatus["l1"]
	if st.Domains != 3 || st.LastError != "" || st.UpdatedAt.IsZero() || st.ETag != `"v1"` || st.URL != e.srv.URL {
		t.Fatalf("status = %+v", st)
	}
	if _, err := os.Stat(e.compiled(filters.SingBoxFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.svc.dir, "filters", "raw", "l1.txt")); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Filters(); v.Domains != 3 || len(v.Lists) != 1 || v.Lists[0].Status.Domains != 3 {
		t.Fatalf("view = %+v", v)
	}
}

func TestRefreshFiltersKeepsLastGood(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	ctx := context.Background()
	if err := e.svc.RefreshFilters(ctx, "l1"); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(e.svc.dir, "filters", "raw", "l1.txt")
	before, _ := os.ReadFile(raw)
	// the server now ignores conditional requests and answers with an error page
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html><body>Service unavailable</body></html>"))
	})
	if err := e.svc.RefreshFilters(ctx, "l1"); err == nil {
		t.Fatal("want an error for an HTML page")
	}
	st := e.svc.store.Get().FilterStatus["l1"]
	after, _ := os.ReadFile(raw)
	if st.LastError == "" || st.Domains != 3 || string(before) != string(after) {
		t.Fatalf("status = %+v, raw changed = %v", st, string(before) != string(after))
	}
}

func TestRefreshNotModified(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	ctx := context.Background()
	if err := e.svc.RefreshFilters(ctx, "l1"); err != nil {
		t.Fatal(err)
	}
	first := e.svc.store.Get().FilterStatus["l1"]
	if err := e.svc.RefreshFilters(ctx, "l1"); err != nil {
		t.Fatal(err)
	}
	second := e.svc.store.Get().FilterStatus["l1"]
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Error("UpdatedAt not bumped")
	}
	if second.Domains != first.Domains || second.ETag != `"v1"` || second.LastError != "" {
		t.Errorf("first %+v second %+v", first, second)
	}
}

func TestFilterDue(t *testing.T) {
	now := time.Now()
	cat := filters.Catalog{Lists: []filters.CatalogList{{Key: "k", ExpiresSec: 345600}}}
	cl := models.FilterList{ID: "a", CatalogKey: "k"}
	if !filterDue(cl, models.FilterStatus{UpdatedAt: now.Add(-96 * time.Hour)}, cat, now) {
		t.Error("catalog list not due after 96h")
	}
	if filterDue(cl, models.FilterStatus{UpdatedAt: now.Add(-95 * time.Hour)}, cat, now) {
		t.Error("catalog list due after 95h")
	}
	custom := models.FilterList{ID: "b", URL: "https://x"}
	if !filterDue(custom, models.FilterStatus{UpdatedAt: now.Add(-24 * time.Hour)}, cat, now) ||
		filterDue(custom, models.FilterStatus{UpdatedAt: now.Add(-23 * time.Hour)}, cat, now) {
		t.Error("custom list should use 24h")
	}
	if filterDue(models.FilterList{ID: "c", URL: "https://x", UpdateHours: 2}, models.FilterStatus{UpdatedAt: now.Add(-time.Hour)}, cat, now) {
		t.Error("UpdateHours ignored")
	}
	if !filterDue(custom, models.FilterStatus{}, cat, now) {
		t.Error("never-updated list must be due")
	}
}

func TestCompileOverLimit(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(e.compiled(filters.SingBoxFile))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.maxMerged = 2
	if _, _, err := e.svc.compileFilters(); err == nil {
		t.Fatal("want an over-limit error")
	}
	after, _ := os.ReadFile(e.compiled(filters.SingBoxFile))
	if string(before) != string(after) {
		t.Error("compiled/ was modified")
	}
	if v := e.svc.Filters(); v.MergeError == "" {
		t.Error("MergeError not set")
	}
	e.svc.maxMerged = maxMergedDomains
	if _, _, err := e.svc.compileFilters(); err != nil || e.svc.Filters().MergeError != "" {
		t.Errorf("MergeError not cleared: %v", err)
	}
}

func TestCompileEmptyRemovesFiles(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	e.setLists(t, false, e.custom("l1")) // Block ads off
	set, _, err := e.svc.compileFilters()
	if err != nil || set.Len() != 0 {
		t.Fatalf("set %v err %v", set, err)
	}
	for _, f := range []string{filters.XrayFile, filters.SingBoxFile, filters.MihomoFile} {
		if _, err := os.Stat(e.compiled(f)); !os.IsNotExist(err) {
			t.Errorf("%s still present", f)
		}
	}
	if v := e.svc.Filters(); v.Domains != 0 || v.Lists[0].ApplyOnConnect {
		t.Errorf("view = %+v", v)
	}
}

func TestSettingsSaveTriggersRefresh(t *testing.T) {
	e := newFilterEnv(t)
	got := make(chan string, 4)
	e.svc.filterRefresh = func(_ context.Context, id string) error { got <- id; return nil }
	in := e.svc.store.Get().Settings
	in.BlockAds = true
	in.FilterLists = []models.FilterList{
		{ID: "on", Name: "on", URL: "https://example.com/a", Enabled: true},
		{ID: "off", Name: "off", URL: "https://example.com/b"},
	}
	if _, err := e.svc.UpdateSettings(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	e.svc.bg.Wait()
	if len(got) != 1 || <-got != "on" {
		t.Fatalf("want exactly one refresh, for %q", "on")
	}
	// saving again with nothing newly enabled starts no refresh
	if _, err := e.svc.UpdateSettings(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	e.svc.bg.Wait()
	if len(got) != 0 {
		t.Fatal("unchanged save refreshed")
	}
}

func TestRemovedListLosesFileAndStatus(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	e.svc.filterRefresh = func(context.Context, string) error { return nil }
	in := e.svc.store.Get().Settings
	in.FilterLists = nil
	if _, err := e.svc.UpdateSettings(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.svc.store.Get().FilterStatus["l1"]; ok {
		t.Error("status kept")
	}
	if _, err := os.Stat(filepath.Join(e.svc.dir, "filters", "raw", "l1.txt")); !os.IsNotExist(err) {
		t.Error("raw file kept")
	}
	if _, err := os.Stat(e.compiled(filters.SingBoxFile)); !os.IsNotExist(err) {
		t.Error("compiled set kept for an empty selection")
	}
}

func TestBackgroundRefreshDoesNotReconnect(t *testing.T) {
	e := newFilterEnv(t)
	e.svc.running = func() bool { return true }
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	if e.svc.run.IsRunning() {
		t.Fatal("refresh started an engine")
	}
	v := e.svc.Filters()
	if !v.ApplyOnConnect || !v.Lists[0].ApplyOnConnect {
		t.Fatalf("ApplyOnConnect not set: %+v", v)
	}
	e.svc.filtersMu.Lock()
	e.svc.lastConnectHash = e.svc.compiledSum
	e.svc.filtersMu.Unlock()
	if v := e.svc.Filters(); v.ApplyOnConnect || v.Lists[0].ApplyOnConnect {
		t.Fatalf("flag set although the connect used this content: %+v", v)
	}
	e.svc.running = func() bool { return false }
	e.svc.filtersMu.Lock()
	e.svc.lastConnectHash = ""
	e.svc.filtersMu.Unlock()
	if e.svc.Filters().ApplyOnConnect {
		t.Fatal("flag set while not connected")
	}
}

func writeCatalogCache(t *testing.T, s *Service, c filters.Catalog) {
	t.Helper()
	b, _ := json.Marshal(c)
	p := filepath.Join(s.dir, "filters", "catalog.json")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogListURLResolution(t *testing.T) {
	e := newFilterEnv(t)
	l := models.FilterList{ID: "c1", CatalogKey: "k", Name: "k", URL: "https://ignored.invalid/x", Enabled: true}
	e.setLists(t, true, l)
	ctx := context.Background()

	// no cache and no known URL
	if err := e.svc.RefreshFilters(ctx, "c1"); err == nil || !strings.Contains(e.svc.store.Get().FilterStatus["c1"].LastError, "no longer in AdGuard's catalog") {
		t.Fatalf("err %v status %+v", err, e.svc.store.Get().FilterStatus["c1"])
	}
	// catalog entry wins and FilterList.URL is ignored
	writeCatalogCache(t, e.svc, filters.Catalog{FetchedAt: time.Now(), Lists: []filters.CatalogList{{Key: "k", DownloadURL: e.srv.URL}}})
	if err := e.svc.RefreshFilters(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if st := e.svc.store.Get().FilterStatus["c1"]; st.URL != e.srv.URL || st.LastError != "" {
		t.Fatalf("status %+v", st)
	}
	// the list vanished from the catalog: fall back to the last known URL
	writeCatalogCache(t, e.svc, filters.Catalog{FetchedAt: time.Now(), Lists: []filters.CatalogList{{Key: "other", DownloadURL: "https://x.invalid"}}})
	e.body.Store("||a.com^\n")
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("||a.com^\n")) })
	if err := e.svc.RefreshFilters(ctx, "c1"); err != nil {
		t.Fatal(err)
	}
	if st := e.svc.store.Get().FilterStatus["c1"]; st.Domains != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestFilterCatalogFetchAndCache(t *testing.T) {
	e := newFilterEnv(t)
	var hits atomic.Int32
	cat := `{"filters":[{"filterKey":"k","filterId":1,"groupId":1,"name":"K","downloadUrl":"https://example.com/k.txt","expires":3600}],"tags":[],"groups":[{"groupId":1,"groupName":"General","displayNumber":1}]}`
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(cat))
	})
	e.svc.catalogURL = e.srv.URL
	ctx := context.Background()
	if _, err := e.svc.FilterCatalog(ctx, false); err == nil {
		t.Fatal("no cache and no refresh must error")
	}
	if hits.Load() != 0 {
		t.Fatal("network used without refresh")
	}
	c, err := e.svc.FilterCatalog(ctx, true)
	if err != nil || len(c.Lists) != 1 || c.FetchedAt.IsZero() {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := e.svc.FilterCatalog(ctx, true); err != nil || hits.Load() != 1 {
		t.Fatalf("fresh cache refetched: hits=%d err=%v", hits.Load(), err)
	}
	// stale cache + failing server: the cache is returned
	c.FetchedAt = time.Now().Add(-48 * time.Hour)
	writeCatalogCache(t, e.svc, c)
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	if c2, err := e.svc.FilterCatalog(ctx, true); err != nil || len(c2.Lists) != 1 {
		t.Fatalf("%+v %v", c2, err)
	}
}

func TestProxyAddr(t *testing.T) {
	e := newFilterEnv(t)
	e.setLists(t, true)
	if _, err := e.svc.store.Update(func(d *models.AppData) error {
		d.Settings.Inbounds = []models.Inbound{
			{Protocol: "http", Port: 1, Enabled: true},
			{Protocol: "socks", Port: 2, Enabled: true, Username: "u", Password: "p"},
			{Protocol: "socks", Port: 3, Enabled: false},
			{Protocol: "socks", Port: 4, Enabled: true},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if a := e.svc.listProxyAddr(); a != "" {
		t.Errorf("not running: %q", a)
	}
	e.svc.running = func() bool { return true }
	if a := e.svc.listProxyAddr(); a != "127.0.0.1:4" {
		t.Errorf("got %q", a)
	}
}

// placeEnv is a compiled set plus a plan of an Xray step, a sing-box step and a
// Mihomo step with install dirs in a temp tree.
func placeEnv(t *testing.T) (*filterEnv, *connPlan, []string) {
	t.Helper()
	e := newFilterEnv(t)
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	xdir := filepath.Join(root, "xray", "v1")
	mdir := filepath.Join(root, "mihomo", "v1")
	sdir := filepath.Join(root, "sing-box", "v1")
	for _, d := range []string{xdir, mdir, sdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	pl := &connPlan{
		steps:    []engine.Step{{Engine: engine.Xray{}}, {Engine: &engine.SingBox{}}, {Engine: engine.Mihomo{}}},
		installs: []engine.Install{{AssetDir: xdir}, {AssetDir: sdir}, {AssetDir: mdir}},
	}
	return e, pl, []string{xdir, sdir, filepath.Join(filepath.Dir(mdir), "data")}
}

func TestPlaceFilterFiles(t *testing.T) {
	e, pl, dirs := placeEnv(t)
	blk, err := e.svc.placeFilterFiles(pl)
	if err != nil {
		t.Fatal(err)
	}
	wantActive := filepath.Join(e.svc.dir, "filters", "active", filters.SingBoxFile)
	if blk == nil || blk.SingBoxPath != wantActive {
		t.Fatalf("block = %+v, want sing-box path %s", blk, wantActive)
	}
	compiledDat, _ := os.ReadFile(e.compiled(filters.XrayFile))
	for path, want := range map[string]string{
		filepath.Join(dirs[0], filters.XrayFile):   string(compiledDat),
		filepath.Join(dirs[2], filters.MihomoFile): "",
		wantActive: "",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if want != "" && string(got) != want {
			t.Errorf("%s differs from the compiled file", path)
		}
	}
	// nothing leaks into the sing-box install dir
	if ents, _ := os.ReadDir(dirs[1]); len(ents) != 0 {
		t.Errorf("sing-box install dir has files: %v", ents)
	}
	// a compiled file changed after placement does not change the active copy
	before, _ := os.ReadFile(wantActive)
	if err := os.WriteFile(e.compiled(filters.SingBoxFile), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(wantActive)
	if string(before) != string(after) || string(after) == "changed" {
		t.Error("the active copy follows the compiled file")
	}
}

func TestPlaceFilterFilesRecordsHash(t *testing.T) {
	e, pl, _ := placeEnv(t)
	e.svc.running = func() bool { return true }
	if !e.svc.Filters().ApplyOnConnect {
		t.Fatal("want apply-on-connect before the first placement")
	}
	if _, err := e.svc.placeFilterFiles(pl); err != nil {
		t.Fatal(err)
	}
	if e.svc.Filters().ApplyOnConnect {
		t.Error("placed files still reported as waiting for connect")
	}
}

func TestPlaceFilterFilesNothingToPlace(t *testing.T) {
	e, pl, dirs := placeEnv(t)
	// Block ads off
	e.setLists(t, false, e.custom("l1"))
	if blk, err := e.svc.placeFilterFiles(pl); blk != nil || err != nil {
		t.Fatalf("block ads off: %+v, %v", blk, err)
	}
	// on again, but nothing compiled
	e.setLists(t, true, e.custom("l1"))
	e.svc.filtersMu.Lock()
	e.svc.compiledSum = ""
	e.svc.filtersMu.Unlock()
	if blk, err := e.svc.placeFilterFiles(pl); blk != nil || err != nil {
		t.Fatalf("nothing compiled: %+v, %v", blk, err)
	}
	if _, err := os.Stat(filepath.Join(dirs[0], filters.XrayFile)); !os.IsNotExist(err) {
		t.Errorf("a file was placed for nothing: %v", err)
	}
}

func TestPreviewBlockHasNoSideEffects(t *testing.T) {
	e, _, _ := placeEnv(t)
	blk := e.svc.previewBlock()
	if blk == nil || blk.SingBoxPath != filepath.Join(e.svc.dir, "filters", "active", filters.SingBoxFile) {
		t.Fatalf("preview block = %+v", blk)
	}
	if _, err := os.Stat(blk.SingBoxPath); !os.IsNotExist(err) {
		t.Errorf("preview copied a file: %v", err)
	}
}
