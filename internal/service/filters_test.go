package service

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
	blk, hash := e.svc.placeFilterFiles(pl)
	if hash == "" {
		t.Fatal("no hash returned")
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
	_, hash := e.svc.placeFilterFiles(pl)
	if !e.svc.Filters().ApplyOnConnect {
		t.Error("placing alone must not count as applied; only a started engine does")
	}
	e.svc.commitConnectHash(hash)
	if e.svc.Filters().ApplyOnConnect {
		t.Error("placed files still reported as waiting for connect")
	}
}

func TestPlaceFilterFilesNothingToPlace(t *testing.T) {
	e, pl, dirs := placeEnv(t)
	// Block ads off
	e.setLists(t, false, e.custom("l1"))
	if blk, h := e.svc.placeFilterFiles(pl); blk != nil || h != "" {
		t.Fatalf("block ads off: %+v, %q", blk, h)
	}
	// on again, but nothing compiled
	e.setLists(t, true, e.custom("l1"))
	e.svc.filtersMu.Lock()
	e.svc.compiledSum = ""
	e.svc.filtersMu.Unlock()
	if blk, h := e.svc.placeFilterFiles(pl); blk != nil || h != "" {
		t.Fatalf("nothing compiled: %+v, %q", blk, h)
	}
	if _, err := os.Stat(filepath.Join(dirs[0], filters.XrayFile)); !os.IsNotExist(err) {
		t.Errorf("a file was placed for nothing: %v", err)
	}
}

func TestPreviewBlockHasNoSideEffects(t *testing.T) {
	e, _, _ := placeEnv(t)
	blk := e.svc.previewBlock()
	if blk == nil || blk.SingBoxPath != filepath.Join(e.svc.dir, "filters", "active", filters.SingBoxBinaryFile) {
		t.Fatalf("preview block = %+v", blk)
	}
	if _, err := os.Stat(blk.SingBoxPath); !os.IsNotExist(err) {
		t.Errorf("preview copied a file: %v", err)
	}
}

func TestPlaceFilterFilesFailureDoesNotBreakConnect(t *testing.T) {
	e, pl, dirs := placeEnv(t)
	if err := os.Remove(e.compiled(filters.XrayFile)); err != nil {
		t.Fatal(err)
	}
	blk, hash := e.svc.placeFilterFiles(pl)
	if blk != nil || hash != "" {
		t.Fatalf("want no block and no hash, got %+v %q", blk, hash)
	}
	if e.svc.Filters().PlaceError == "" {
		t.Error("PlaceError not set")
	}
	_ = dirs
	// the next successful placement clears it
	if err := filters.WriteAll(filepath.Join(e.svc.dir, "filters", "compiled"), e.svc.set); err != nil {
		t.Fatal(err)
	}
	if blk, _ := e.svc.placeFilterFiles(pl); blk == nil {
		t.Fatal("placement should succeed again")
	}
	if e.svc.Filters().PlaceError != "" {
		t.Error("PlaceError not cleared")
	}
}

func TestSingBoxCopyOnlyWithSingBoxStep(t *testing.T) {
	e, pl, _ := placeEnv(t)
	pl.steps, pl.installs = pl.steps[:1], pl.installs[:1] // Xray only
	if blk, _ := e.svc.placeFilterFiles(pl); blk == nil {
		t.Fatal("no block")
	}
	for _, name := range []string{filters.SingBoxFile, filters.SingBoxBinaryFile} {
		if _, err := os.Stat(filepath.Join(e.svc.activeDir(), name)); !os.IsNotExist(err) {
			t.Errorf("sing-box %s made without a sing-box step: %v", name, err)
		}
	}
}

// fakeSingBox writes a shell script standing in for sing-box: it logs each
// call and, unless the fail marker exists, "compiles" by copying its input.
func fakeSingBox(t *testing.T) (bin, calls, failMarker string) {
	t.Helper()
	dir := t.TempDir()
	bin, calls, failMarker = filepath.Join(dir, "sing-box"), filepath.Join(dir, "calls"), filepath.Join(dir, "fail")
	script := "#!/bin/sh\n" +
		"[ \"$1 $2 $3\" = \"rule-set compile --output\" ] || exit 2\n" +
		"echo run >> '" + calls + "'\n" +
		"[ -f '" + failMarker + "' ] && exit 1\n" +
		"cp \"$5\" \"$4\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, calls, failMarker
}

func countCalls(t *testing.T, calls string) int {
	t.Helper()
	b, err := os.ReadFile(calls)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "run")
}

func TestSingBoxRuleSetIsCompiledOncePerHash(t *testing.T) {
	e, pl, _ := placeEnv(t)
	bin, calls, _ := fakeSingBox(t)
	pl.installs[1].Bin = bin
	wantSRS := filepath.Join(e.svc.dir, "filters", "active", filters.SingBoxBinaryFile)

	blk, hash := e.svc.placeFilterFiles(pl)
	if blk == nil || hash == "" || blk.SingBoxPath != wantSRS {
		t.Fatalf("block = %+v hash %q, want path %s", blk, hash, wantSRS)
	}
	src, _ := os.ReadFile(e.compiled(filters.SingBoxFile))
	if got, err := os.ReadFile(wantSRS); err != nil || !bytes.Equal(got, src) {
		t.Fatalf("compiled file = %q, %v", got, err)
	}
	if n := countCalls(t, calls); n != 1 {
		t.Fatalf("compile ran %d times, want 1", n)
	}
	if _, err := os.Stat(wantSRS + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file left behind: %v", err)
	}

	// same hash: cached
	if blk, _ := e.svc.placeFilterFiles(pl); blk == nil || blk.SingBoxPath != wantSRS {
		t.Fatalf("second block = %+v", blk)
	}
	if n := countCalls(t, calls); n != 1 {
		t.Fatalf("cached hash recompiled: %d calls", n)
	}

	// new hash: compiled again
	e.svc.filtersMu.Lock()
	e.svc.compiledSum = "another-hash"
	e.svc.filtersMu.Unlock()
	e.svc.placeFilterFiles(pl)
	if n := countCalls(t, calls); n != 2 {
		t.Fatalf("new hash: %d calls, want 2", n)
	}
}

func TestSingBoxCompileFailureFallsBackToSource(t *testing.T) {
	e, pl, _ := placeEnv(t)
	bin, calls, fail := fakeSingBox(t)
	pl.installs[1].Bin = bin
	// a good compile first, so there is an older .srs to retire
	e.svc.placeFilterFiles(pl)
	if err := os.WriteFile(fail, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	e.svc.filtersMu.Lock()
	e.svc.compiledSum = "another-hash"
	e.svc.filtersMu.Unlock()

	blk, hash := e.svc.placeFilterFiles(pl)
	wantJSON := filepath.Join(e.svc.dir, "filters", "active", filters.SingBoxFile)
	if blk == nil || hash == "" || blk.SingBoxPath != wantJSON {
		t.Fatalf("block = %+v hash %q, want source fallback %s", blk, hash, wantJSON)
	}
	if _, err := os.Stat(wantJSON); err != nil {
		t.Errorf("source copy missing: %v", err)
	}
	if _, err := os.Stat(e.svc.activeSingBoxPath()); !os.IsNotExist(err) {
		t.Errorf("stale binary rule set kept: %v", err)
	}
	if e.svc.Filters().PlaceError != "" {
		t.Errorf("a compile failure must not be a placement error: %s", e.svc.Filters().PlaceError)
	}
	if n := countCalls(t, calls); n != 2 {
		t.Errorf("calls = %d", n)
	}
}

func TestTestRouteFilterFirst(t *testing.T) {
	e := newFilterEnv(t)
	e.body.Store("||ads.example.com^\n||tracker.net^\n")
	l := e.custom("l1")
	l.Name = "AdGuard DNS filter"
	e.setLists(t, true, l)
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	direct := []models.RouteRule{{ID: "d", Enabled: true, Entries: []string{"ads.example.com"}, Outbound: "direct"}}
	r := e.svc.TestRoute("ads.example.com", 443, direct)
	if r.Outbound != "block" || r.FilterList != "AdGuard DNS filter" || r.AllowedBy {
		t.Fatalf("got %+v", r)
	}
	// Allowlisted: falls through to the rules.
	if _, err := e.svc.store.Update(func(d *models.AppData) error { d.Settings.AllowedSites = "ads.example.com"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.compileFilters(); err != nil {
		t.Fatal(err)
	}
	r = e.svc.TestRoute("ads.example.com", 443, direct)
	if r.Outbound != "direct" || !r.AllowedBy || r.RuleID != "d" || r.FilterList != "" {
		t.Fatalf("allowlisted: got %+v", r)
	}
}

func TestTestRouteAllowlistUsesCompileNormalization(t *testing.T) {
	e := newFilterEnv(t)
	e.body.Store("||xn--bcher-kva.de^\n")
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.store.Update(func(d *models.AppData) error { d.Settings.AllowedSites = "bücher.de"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.compileFilters(); err != nil {
		t.Fatal(err)
	}
	if r := e.svc.TestRoute("bücher.de", 443, nil); r.Outbound == "block" || !r.AllowedBy {
		t.Fatalf("got %+v, want allowed like the compiled set", r)
	}
}

func TestTestRouteBlockedSitesAndModes(t *testing.T) {
	svc := newTestService(t)
	set := func(f func(*models.Settings)) {
		if _, err := svc.store.Update(func(d *models.AppData) error { f(&d.Settings); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	set(func(s *models.Settings) { s.BlockAds = true; s.BlockedSites = "bad.com" })
	if r := svc.TestRoute("x.bad.com", 80, nil); r.Outbound != "block" || r.RuleID != "blocked-sites" || r.Entry != "bad.com" {
		t.Fatalf("got %+v", r)
	}
	// Block ads off in a non-custom mode: BlockedSites is not applied.
	set(func(s *models.Settings) { s.BlockAds = false })
	if r := svc.TestRoute("bad.com", 80, nil); r.Outbound == "block" {
		t.Fatalf("got %+v", r)
	}
	// Custom mode applies it regardless.
	set(func(s *models.Settings) { s.RoutingMode = "custom"; s.DirectSites = "keep.com" })
	if r := svc.TestRoute("bad.com", 80, nil); r.Outbound != "block" {
		t.Fatalf("custom: %+v", r)
	}
	if r := svc.TestRoute("keep.com", 80, nil); r.Outbound != "direct" || r.RuleID != "mode-direct" {
		t.Fatalf("custom direct: %+v", r)
	}
	// Block ads with empty BlockedSites: geosite default, unknown offline.
	set(func(s *models.Settings) { s.RoutingMode = "global"; s.BlockAds = true; s.BlockedSites = "" })
	r := svc.TestRoute("example.com", 80, nil)
	if r.Outbound == "block" || len(r.Unknown) == 0 || r.Unknown[0] != "geosite:category-ads-all" {
		t.Fatalf("default geosite: %+v", r)
	}
}

func TestPreviewFilterURL(t *testing.T) {
	e := newFilterEnv(t)
	e.body.Store("||g.com^\n||f.com^\n||e.com^\n||d.com^\n||c.com^\n||b.com^\n||a.com^\n!x\n/regex/\n")
	p, err := e.svc.PreviewFilterURL(context.Background(), e.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if p.Domains != 7 || p.Skipped != 1 || !reflect.DeepEqual(p.Sample, []string{"a.com", "b.com", "c.com", "d.com", "e.com"}) {
		t.Fatalf("got %+v", p)
	}
	e.body.Store("<html>nope</html>")
	if _, err := e.svc.PreviewFilterURL(context.Background(), e.srv.URL); err == nil {
		t.Fatal("want error for an HTML page")
	}
	if _, err := e.svc.PreviewFilterURL(context.Background(), "http://example.com/x"); err == nil {
		t.Fatal("want error for http")
	}
}

func TestUpdateSettingsTurnsSniffingOn(t *testing.T) {
	svc := newTestService(t)
	in := svc.store.Get().Settings
	in.BlockAds, in.Sniffing = true, false
	in.TUN.Enabled = true
	res, err := svc.UpdateSettings(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.SniffingTurnedOn || res.Warning != "" || !svc.store.Get().Settings.Sniffing {
		t.Fatalf("res=%+v sniffing=%v", res, svc.store.Get().Settings.Sniffing)
	}
	in = svc.store.Get().Settings
	in.Sniffing = false
	res, err = svc.UpdateSettings(context.Background(), in)
	if err != nil || res.SniffingTurnedOn || res.Warning != models.SniffingOffWarningMsg || svc.store.Get().Settings.Sniffing {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestApplyOnConnectCoversTurningListsOff(t *testing.T) {
	e := newFilterEnv(t)
	e.svc.running = func() bool { return true }
	e.setLists(t, true, e.custom("l1"))
	if err := e.svc.RefreshFilters(context.Background(), "l1"); err != nil {
		t.Fatal(err)
	}
	// the running connection placed this hash
	e.svc.commitConnectHash(e.svc.compiledSum)
	if v := e.svc.Filters(); v.ApplyOnConnect || v.Lists[0].ApplyOnConnect {
		t.Fatalf("same hash: %+v", v)
	}
	// Block ads off: compiles to nothing, but the engine still blocks the old set
	e.setLists(t, false, e.custom("l1"))
	if _, _, err := e.svc.compileFilters(); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Filters(); !v.ApplyOnConnect {
		t.Fatalf("turning lists off must hint a reconnect: %+v", v)
	}
	// a connect that placed nothing records ""; a later compile is then pending
	e.svc.commitConnectHash("")
	if v := e.svc.Filters(); v.ApplyOnConnect {
		t.Fatalf("nothing compiled and nothing placed: %+v", v)
	}
	e.setLists(t, true, e.custom("l1"))
	if _, _, err := e.svc.compileFilters(); err != nil {
		t.Fatal(err)
	}
	if v := e.svc.Filters(); !v.ApplyOnConnect || !v.Lists[0].ApplyOnConnect {
		t.Fatalf("new content after a list-less connect: %+v", v)
	}
}

func TestSingBoxRuleSetRecompiledWhenBinaryChanges(t *testing.T) {
	e, pl, _ := placeEnv(t)
	bin, calls, _ := fakeSingBox(t)
	pl.installs[1].Bin = bin
	e.svc.placeFilterFiles(pl)
	e.svc.placeFilterFiles(pl)
	if n := countCalls(t, calls); n != 1 {
		t.Fatalf("same binary: %d compiles, want 1", n)
	}
	// touching the binary (an engine update keeps the path) forces a rebuild
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(bin, later, later); err != nil {
		t.Fatal(err)
	}
	e.svc.placeFilterFiles(pl)
	if n := countCalls(t, calls); n != 2 {
		t.Fatalf("touched binary: %d compiles, want 2", n)
	}
	// replacing it with a different one (new size) as well
	script, _ := os.ReadFile(bin)
	if err := os.WriteFile(bin, append(script, []byte("# v2\n")...), 0o755); err != nil {
		t.Fatal(err)
	}
	e.svc.placeFilterFiles(pl)
	if n := countCalls(t, calls); n != 3 {
		t.Fatalf("replaced binary: %d compiles, want 3", n)
	}
}

func TestPlacementDoesNotBlockFiltersView(t *testing.T) {
	e, pl, _ := placeEnv(t)
	dir := t.TempDir()
	bin, started := filepath.Join(dir, "sing-box"), filepath.Join(dir, "started")
	script := "#!/bin/sh\ntouch '" + started + "'\nsleep 2\ncp \"$5\" \"$4\"\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	pl.installs[1].Bin = bin
	done := make(chan struct{})
	go func() { defer close(done); e.svc.placeFilterFiles(pl) }()
	for i := 0; ; i++ { // wait until the exec is really running
		if _, err := os.Stat(started); err == nil {
			break
		}
		if i > 200 {
			t.Fatal("fake sing-box never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	t0 := time.Now()
	e.svc.Filters()
	e.svc.TestRoute("a.com", 443, nil)
	e.svc.previewBlock()
	if d := time.Since(t0); d > 500*time.Millisecond {
		t.Fatalf("Filters/TestRoute/previewBlock blocked %v behind the compile", d)
	}
	<-done
}
