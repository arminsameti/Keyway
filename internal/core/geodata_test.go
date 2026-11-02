package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// geoServer serves the rolling "latest" release of the geodata repository. hits
// counts file downloads.
func geoServer(t *testing.T, files map[string][]byte, digests map[string]string, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/MetaCubeX/meta-rules-dat/releases/tags/latest" {
			var assets []string
			for name := range files {
				d := ""
				if dg, ok := digests[name]; ok {
					d = fmt.Sprintf(`,"digest":%q`, dg)
				}
				assets = append(assets, fmt.Sprintf(`{"name":%q,"browser_download_url":%q%s}`, name, ts.URL+"/dl/"+name, d))
			}
			fmt.Fprintf(w, `{"tag_name":"latest","assets":[%s]}`, strings.Join(assets, ","))
			return
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/dl/"); ok {
			hits.Add(1)
			w.Write(files[name])
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func geoManager(t *testing.T, ts *httptest.Server) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), MihomoSource)
	if err != nil {
		t.Fatal(err)
	}
	m.client, m.apiBase, m.allowHost = ts.Client(), ts.URL, func(string) bool { return true }
	return m
}

func TestEnsureGeoDataDownloadsAndVerifies(t *testing.T) {
	site, ip := []byte("geosite bytes"), []byte("geoip bytes")
	var hits atomic.Int32
	ts := geoServer(t, map[string][]byte{"geosite.dat": site, "geoip.metadb": ip},
		map[string]string{"geosite.dat": sha(site), "geoip.metadb": sha(ip)}, &hits)
	m := geoManager(t, ts)
	if err := m.EnsureGeoData(context.Background(), []string{GeoSiteFile, GeoIPFile}); err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string][]byte{GeoSiteFile: site, GeoIPFile: ip} {
		got, err := os.ReadFile(filepath.Join(m.GeoDataDir(), file))
		if err != nil || string(got) != string(want) {
			t.Errorf("%s = %q, %v", file, got, err)
		}
	}
	// a file that is there and fresh is not fetched again
	hits.Store(0)
	if err := m.EnsureGeoData(context.Background(), []string{GeoSiteFile, GeoIPFile}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Fatalf("downloaded %d files that were already there", hits.Load())
	}
}

func TestEnsureGeoDataRefusesAWrongDigest(t *testing.T) {
	var hits atomic.Int32
	ts := geoServer(t, map[string][]byte{"geosite.dat": []byte("tampered")},
		map[string]string{"geosite.dat": sha([]byte("the real file"))}, &hits)
	m := geoManager(t, ts)
	err := m.EnsureGeoData(context.Background(), []string{GeoSiteFile})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(m.GeoDataDir(), GeoSiteFile)); serr == nil {
		t.Fatal("a file that failed verification was kept")
	}
}

func TestEnsureGeoDataRefusesAMissingDigest(t *testing.T) {
	var hits atomic.Int32
	ts := geoServer(t, map[string][]byte{"geosite.dat": []byte("x")}, nil, &hits)
	err := geoManager(t, ts).EnsureGeoData(context.Background(), []string{GeoSiteFile})
	if err == nil || !strings.Contains(err.Error(), "refusing unverified download") {
		t.Fatalf("err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("downloaded a file with no checksum to verify it against")
	}
}

func TestEnsureGeoDataOnlyKnownFiles(t *testing.T) {
	var hits atomic.Int32
	m := geoManager(t, geoServer(t, nil, nil, &hits))
	for _, bad := range []string{"../evil", "country.mmdb", "GeoSite.dat/../x", ""} {
		if err := m.EnsureGeoData(context.Background(), []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestEnsureGeoDataKeepsAStaleFileWhenTheRefreshFails(t *testing.T) {
	var hits atomic.Int32
	ts := geoServer(t, nil, nil, &hits) // serves nothing: any refresh fails
	m := geoManager(t, ts)
	if err := os.MkdirAll(m.GeoDataDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(m.GeoDataDir(), GeoSiteFile)
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-90 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureGeoData(context.Background(), []string{GeoSiteFile}); err != nil {
		t.Fatalf("a failed refresh of an existing file must not block connecting: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "old" {
		t.Fatalf("file = %q", b)
	}
}
