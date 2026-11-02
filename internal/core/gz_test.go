package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func gzBytes(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzFile(t *testing.T, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.gz")
	if err := os.WriteFile(p, gzBytes(t, body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func gzSource(max uint64) Source {
	return Source{Name: "Mihomo", Binary: "mihomo", Archive: ArchiveGz,
		Files: map[string]Member{"mihomo": {0o755, max}}}
}

func TestExtractGzWritesTheBinary(t *testing.T) {
	dest := t.TempDir()
	if err := extractGz(gzFile(t, []byte("#!bin")), dest, gzSource(1<<10)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dest, "mihomo"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v", st.Mode())
	}
	b, _ := os.ReadFile(filepath.Join(dest, "mihomo"))
	if string(b) != "#!bin" {
		t.Fatalf("content = %q", b)
	}
}

func TestExtractGzEnforcesTheSizeLimit(t *testing.T) {
	err := extractGz(gzFile(t, bytes.Repeat([]byte("x"), 2048)), t.TempDir(), gzSource(1024))
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("err = %v", err)
	}
}

func TestExtractGzRefusesEmptyAndNotGzip(t *testing.T) {
	if err := extractGz(gzFile(t, nil), t.TempDir(), gzSource(1024)); err == nil {
		t.Fatal("an empty binary was accepted")
	}
	p := filepath.Join(t.TempDir(), "x.gz")
	if err := os.WriteFile(p, []byte("not gzip at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractGz(p, t.TempDir(), gzSource(1024)); err == nil {
		t.Fatal("a non-gzip file was accepted")
	}
}

func TestExtractGzRefusesAppendedData(t *testing.T) {
	// A second gzip member after the first would be silently concatenated by a
	// lenient reader; the checksum covers the whole file, but the extractor must
	// not rely on that for what it writes.
	b := append(gzBytes(t, []byte("one")), gzBytes(t, []byte("two"))...)
	p := filepath.Join(t.TempDir(), "x.gz")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := extractGz(p, t.TempDir(), gzSource(1024)); err == nil {
		t.Fatal("a multi-member gzip was accepted")
	}
}

func TestMihomoSourceUsesTheGitHubDigest(t *testing.T) {
	s := MihomoSource
	if s.Archive != ArchiveGz || s.Checksum != ChecksumDigest || s.Repo != "MetaCubeX/mihomo" || s.Binary != "mihomo" {
		t.Fatalf("source = %+v", s)
	}
	names, err := s.Assets("v1.19.33")
	if err != nil {
		t.Skip("unsupported platform")
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "mihomo-") || !strings.HasSuffix(n, "-v1.19.33.gz") {
			t.Errorf("asset name %q", n)
		}
	}
}

func TestMihomoAssetNames(t *testing.T) {
	cases := map[string]string{
		"darwin/arm64": "mihomo-darwin-arm64-v1.19.33.gz",
		// "compatible" is GOAMD64=v1: the plain amd64 build needs AVX2 and fails on older Intel Macs.
		"darwin/amd64": "mihomo-darwin-amd64-compatible-v1.19.33.gz",
		"linux/amd64":  "mihomo-linux-amd64-compatible-v1.19.33.gz",
		"linux/arm64":  "mihomo-linux-arm64-v1.19.33.gz",
	}
	for platform, want := range cases {
		got, err := mihomoAssetsFor(platform, "v1.19.33")
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("%s: got %v, %v; want %s", platform, got, err, want)
		}
	}
	if _, err := mihomoAssetsFor("windows/amd64", "v1.19.33"); err == nil {
		t.Error("windows accepted")
	}
}

// releaseServer serves one release whose asset digest is digest ("" = none).
func releaseServer(t *testing.T, asset []byte, digest string) *httptest.Server {
	t.Helper()
	var ts *httptest.Server
	ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/tags/v1.19.33"):
			d := ""
			if digest != "" {
				d = fmt.Sprintf(`,"digest":%q`, digest)
			}
			fmt.Fprintf(w, `{"tag_name":"v1.19.33","assets":[{"name":"mihomo-test-v1.19.33.gz","browser_download_url":%q%s}]}`, ts.URL+"/dl/a.gz", d)
		case r.URL.Path == "/dl/a.gz":
			w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func mihomoTestManager(t *testing.T, ts *httptest.Server) *Manager {
	t.Helper()
	src := MihomoSource
	src.Assets = func(string) ([]string, error) { return []string{"mihomo-test-v1.19.33.gz"}, nil }
	m, err := NewManager(t.TempDir(), src)
	if err != nil {
		t.Fatal(err)
	}
	m.client, m.apiBase, m.allowHost = ts.Client(), ts.URL, func(string) bool { return true }
	return m
}

func sha(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

func TestMihomoDownloadVerifiesTheDigestAndInstalls(t *testing.T) {
	asset := gzBytes(t, []byte("fake mihomo"))
	m := mihomoTestManager(t, releaseServer(t, asset, sha(asset)))
	if err := m.Download(context.Background(), "v1.19.33"); err != nil {
		t.Fatal(err)
	}
	if got := m.Installed(); len(got) != 1 || got[0] != "v1.19.33" {
		t.Fatalf("installed = %v", got)
	}
	b, _ := os.ReadFile(filepath.Join(m.Dir(), "v1.19.33", "mihomo"))
	if string(b) != "fake mihomo" {
		t.Fatalf("binary = %q", b)
	}
}

func TestMihomoDownloadRefusesAWrongDigest(t *testing.T) {
	asset := gzBytes(t, []byte("fake mihomo"))
	m := mihomoTestManager(t, releaseServer(t, asset, sha([]byte("something else"))))
	err := m.Download(context.Background(), "v1.19.33")
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("err = %v", err)
	}
	if len(m.Installed()) != 0 {
		t.Fatal("installed despite the mismatch")
	}
}

func TestMihomoDownloadRefusesAMissingDigest(t *testing.T) {
	asset := gzBytes(t, []byte("fake mihomo"))
	m := mihomoTestManager(t, releaseServer(t, asset, ""))
	err := m.Download(context.Background(), "v1.19.33")
	if err == nil || !strings.Contains(err.Error(), "refusing unverified download") {
		t.Fatalf("err = %v", err)
	}
	if len(m.Installed()) != 0 {
		t.Fatal("installed without a checksum")
	}
}
