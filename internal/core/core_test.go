package core

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	good := []string{"v25.1.1", "v1.8.24", "v26.10.3"}
	bad := []string{"", "25.1.1", "v25.1", "v25.1.1.1", "../v1.0.0", "v1.0.0/../..", "v1.0.0\n", "v1.0.0-rc1", "v..", "v1.0.0 ", "V1.0.0", "v1.0.0;rm"}
	for _, v := range good {
		if !ValidVersion(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	for _, v := range bad {
		if ValidVersion(v) {
			t.Errorf("%q must be rejected", v)
		}
	}
}

func TestCompareVersionsIsNumeric(t *testing.T) {
	if CompareVersions("v25.10.0", "v25.9.0") <= 0 {
		t.Fatal("v25.10.0 must be newer than v25.9.0")
	}
	if CompareVersions("v1.2.3", "v1.2.3") != 0 || CompareVersions("v1.2.3", "v1.2.4") >= 0 {
		t.Fatal("bad comparison")
	}
}

func TestInstalledSortsNumericallyAndResolveFallsBack(t *testing.T) {
	m, _ := NewManager(t.TempDir(), XraySource)
	for _, v := range []string{"v25.9.0", "v25.10.0", "v1.8.24"} {
		_ = os.MkdirAll(filepath.Join(m.dir, v), 0o755)
		_ = os.WriteFile(filepath.Join(m.dir, v, "xray"), []byte("x"), 0o755)
	}
	_ = os.MkdirAll(filepath.Join(m.dir, "../evil"), 0o755)
	_ = os.MkdirAll(filepath.Join(m.dir, "notaversion"), 0o755)
	got := strings.Join(m.Installed(), ",")
	if got != "v1.8.24,v25.9.0,v25.10.0" {
		t.Fatalf("Installed = %s", got)
	}
	_, _, v, err := m.Resolve("")
	if err != nil || v != "v25.10.0" {
		t.Fatalf("Resolve(\"\") = %s, %v", v, err)
	}
	_, _, v, _ = m.Resolve("v9.9.9") // vanished -> newest
	if v != "v25.10.0" {
		t.Fatalf("fallback = %s", v)
	}
	if _, _, _, err := m.Resolve("../../etc"); err == nil {
		t.Fatal("traversal must be rejected")
	}
}

func TestParseSHA256(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	dgst := "MD5= 1234\nSHA1= 5678\nSHA2-256= " + strings.ToUpper(sum) + "\nSHA2-512= beef\n"
	got, err := parseSHA256(dgst)
	if err != nil || got != sum {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := parseSHA256("MD5= 1234\n"); err == nil {
		t.Fatal("missing SHA2-256 must fail")
	}
}

func makeZip(t *testing.T, files map[string]string, symlinks map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	for name, target := range symlinks {
		hdr := &zip.FileHeader{Name: name}
		hdr.SetMode(os.ModeSymlink | 0o777)
		w, _ := zw.CreateHeader(hdr)
		_, _ = w.Write([]byte(target))
	}
	_ = zw.Close()
	p := filepath.Join(t.TempDir(), "a.zip")
	_ = os.WriteFile(p, buf.Bytes(), 0o600)
	return p
}

func TestExtractIgnoresEverythingButWhitelist(t *testing.T) {
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	_ = os.MkdirAll(dest, 0o755)
	zp := makeZip(t, map[string]string{
		"xray":                   "binary",
		"geoip.dat":              "geo",
		"../../escape.txt":       "pwn",
		"/abs/escape.txt":        "pwn",
		"sub/xray":               "nested",
		"README.md":              "readme",
		"..\\..\\win-escape.txt": "pwn",
	}, map[string]string{"geosite.dat": "/etc/passwd"})
	if err := extractWhitelisted(zp, dest, XraySource); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dest)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "geoip.dat,xray" {
		t.Fatalf("extracted %v", names)
	}
	if _, err := os.Stat(filepath.Join(root, "escape.txt")); err == nil {
		t.Fatal("zip-slip succeeded")
	}
	st, _ := os.Stat(filepath.Join(dest, "xray"))
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("xray mode %v", st.Mode())
	}
	g, _ := os.Stat(filepath.Join(dest, "geoip.dat"))
	if g.Mode().Perm() != 0o644 {
		t.Fatalf("geoip mode %v", g.Mode())
	}
}

func TestExtractRequiresBinary(t *testing.T) {
	zp := makeZip(t, map[string]string{"geoip.dat": "x"}, nil)
	if err := extractWhitelisted(zp, t.TempDir(), XraySource); err == nil {
		t.Fatal("archive without xray must fail")
	}
}

// fakeGitHub serves a release with a platform asset + .dgst.
func fakeGitHub(t *testing.T, zipBytes []byte, sum string) (*Manager, func()) {
	t.Helper()
	cands, err := xrayAssets("")
	if err != nil {
		t.Skip(err)
	}
	asset := cands[0]
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/XTLS/Xray-core/releases/tags/v9.9.9", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v9.9.9",
			"assets": []map[string]string{
				{"name": asset, "browser_download_url": srv.URL + "/dl/" + asset},
				{"name": asset + ".dgst", "browser_download_url": srv.URL + "/dl/" + asset + ".dgst"},
			},
		})
	})
	mux.HandleFunc("/dl/"+asset, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(zipBytes) })
	mux.HandleFunc("/dl/"+asset+".dgst", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "MD5= 00\nSHA2-256= %s\n", sum)
	})
	mux.HandleFunc("/repos/XTLS/Xray-core/releases", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"tag_name": "v9.9.9", "name": "ok"},
			{"tag_name": "v9.9.10", "name": "pre", "prerelease": true},
			{"tag_name": "v9.9.8", "name": "draft", "draft": true},
			{"tag_name": "weird", "name": "bad tag"},
		})
	})
	srv = httptest.NewTLSServer(mux)
	m, _ := NewManager(t.TempDir(), XraySource)
	m.apiBase = srv.URL
	m.client = srv.Client()
	m.allowHost = func(string) bool { return true }
	return m, srv.Close
}

func TestDownloadVerifiesChecksum(t *testing.T) {
	zb, _ := os.ReadFile(makeZip(t, map[string]string{"xray": "#!/bin/sh\n", "geoip.dat": "g", "geosite.dat": "s"}, nil))
	sum := sha256.Sum256(zb)

	m, closeSrv := fakeGitHub(t, zb, hex.EncodeToString(sum[:]))
	defer closeSrv()
	if err := m.Download(context.Background(), "9.9.9"); err != nil {
		t.Fatalf("download: %v", err)
	}
	if got := m.Installed(); len(got) != 1 || got[0] != "v9.9.9" {
		t.Fatalf("installed = %v", got)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "v9.9.9", "geosite.dat")); err != nil {
		t.Fatal("geosite.dat missing")
	}
	// no staging leftovers
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("leftover %s", e.Name())
		}
	}
}

func TestDownloadRejectsBadChecksum(t *testing.T) {
	zb, _ := os.ReadFile(makeZip(t, map[string]string{"xray": "x"}, nil))
	m, closeSrv := fakeGitHub(t, zb, strings.Repeat("0", 64))
	defer closeSrv()
	err := m.Download(context.Background(), "v9.9.9")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	if len(m.Installed()) != 0 {
		t.Fatal("tampered archive was installed")
	}
}

func TestDownloadRejectsBadVersionBeforeNetwork(t *testing.T) {
	m, _ := NewManager(t.TempDir(), XraySource)
	for _, v := range []string{"../../x", "v1.0.0/../..", "", "latest"} {
		if err := m.Download(context.Background(), v); err == nil {
			t.Errorf("%q must be rejected", v)
		}
	}
}

func TestFetchReleasesFilters(t *testing.T) {
	zb, _ := os.ReadFile(makeZip(t, map[string]string{"xray": "x"}, nil))
	m, closeSrv := fakeGitHub(t, zb, "00")
	defer closeSrv()
	rs, err := m.FetchReleases(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 1 || rs[0].Tag != "v9.9.9" {
		t.Fatalf("releases = %+v", rs)
	}
}

func TestRefusesNonAllowedHosts(t *testing.T) {
	m, _ := NewManager(t.TempDir(), XraySource)
	if _, err := m.get(context.Background(), "https://evil.example.com/x", "", 10); err == nil {
		t.Fatal("non-GitHub host must be refused")
	}
	if _, err := m.get(context.Background(), "http://github.com/x", "", 10); err == nil {
		t.Fatal("plain http must be refused")
	}
}
