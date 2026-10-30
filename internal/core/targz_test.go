package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name, body string
	typ        byte
	link       string
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: typ, Linkname: e.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func writeTmp(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTarGzExtractsOnlyWhitelist(t *testing.T) {
	dest := t.TempDir()
	outside := filepath.Join(filepath.Dir(dest), "pwned")
	tgz := makeTarGz(t, []tarEntry{
		{name: "sing-box-1.14.4-darwin-arm64/LICENSE", body: "gpl"},
		{name: "sing-box-1.14.4-darwin-arm64/sing-box", body: "#!/bin/sh\n"},
		{name: "../pwned", body: "x"},
		{name: "a/b/sing-box", body: "too deep"},
		{name: "evil/sing-box", typ: tar.TypeSymlink, link: "/etc/passwd"},
	})
	if err := extractTarGz(writeTmp(t, tgz), dest, SingBoxSource); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 1 || entries[0].Name() != "sing-box" {
		t.Fatalf("extracted %v", entries)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "sing-box")); string(b) != "#!/bin/sh\n" {
		t.Fatalf("binary = %q", b)
	}
	if st, _ := os.Stat(filepath.Join(dest, "sing-box")); st.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("path traversal wrote outside dest")
	}
}

func TestTarGzRejectsMissingBinaryAndOversize(t *testing.T) {
	if err := extractTarGz(writeTmp(t, makeTarGz(t, []tarEntry{{name: "x/LICENSE", body: "l"}})), t.TempDir(), SingBoxSource); err == nil {
		t.Fatal("archive without the binary must fail")
	}
	small := SingBoxSource
	small.Files = map[string]Member{"sing-box": {0o755, 4}}
	if err := extractTarGz(writeTmp(t, makeTarGz(t, []tarEntry{{name: "x/sing-box", body: "0123456789"}})), t.TempDir(), small); err == nil {
		t.Fatal("oversized member must fail")
	}
	if err := extractTarGz(writeTmp(t, []byte("not gzip")), t.TempDir(), SingBoxSource); err == nil {
		t.Fatal("garbage must fail")
	}
}

// fakeSingBox serves a sing-box release whose asset carries the given API digest.
func fakeSingBox(t *testing.T, archive []byte, digest string) *Manager {
	t.Helper()
	cands, err := singBoxAssets("v1.14.4")
	if err != nil {
		t.Skip(err)
	}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/SagerNet/sing-box/releases/tags/v1.14.4", func(w http.ResponseWriter, r *http.Request) {
		asset := map[string]string{"name": cands[0], "browser_download_url": srv.URL + "/dl/" + cands[0]}
		if digest != "" {
			asset["digest"] = digest
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.14.4", "assets": []map[string]string{asset}})
	})
	mux.HandleFunc("/dl/"+cands[0], func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(archive) })
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	m, _ := NewManager(t.TempDir(), SingBoxSource)
	m.apiBase, m.client, m.allowHost = srv.URL, srv.Client(), func(string) bool { return true }
	return m
}

func TestSingBoxDownloadVerifiesAPIDigest(t *testing.T) {
	archive := makeTarGz(t, []tarEntry{{name: "sing-box-1.14.4/sing-box", body: "#!/bin/sh\n"}})
	sum := sha256.Sum256(archive)

	m := fakeSingBox(t, archive, "sha256:"+hex.EncodeToString(sum[:]))
	if err := m.Download(context.Background(), "v1.14.4"); err != nil {
		t.Fatalf("download: %v", err)
	}
	bin, _, v, err := m.Resolve("")
	if err != nil || v != "v1.14.4" || filepath.Base(bin) != "sing-box" {
		t.Fatalf("resolve: %s %s %v", bin, v, err)
	}

	bad := fakeSingBox(t, archive, "sha256:"+strings.Repeat("0", 64))
	if err := bad.Download(context.Background(), "v1.14.4"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("tampered: %v", err)
	}
	if len(bad.Installed()) != 0 {
		t.Fatal("tampered archive was installed")
	}
	for _, d := range []string{"", "md5:abc", "sha256:short"} {
		m := fakeSingBox(t, archive, d)
		if err := m.Download(context.Background(), "v1.14.4"); err == nil || !strings.Contains(err.Error(), "SHA-256") {
			t.Errorf("digest %q: %v", d, err)
		}
	}
}

func TestDownloadReportsProgress(t *testing.T) {
	archive := makeTarGz(t, []tarEntry{{name: "x/sing-box", body: strings.Repeat("b", 100000)}})
	sum := sha256.Sum256(archive)
	m := fakeSingBox(t, archive, "sha256:"+hex.EncodeToString(sum[:]))
	var last, total int64
	ctx := WithProgress(context.Background(), func(d, tt int64) { last, total = d, tt })
	if err := m.Download(ctx, "v1.14.4"); err != nil {
		t.Fatal(err)
	}
	if last != int64(len(archive)) || (total != -1 && total != int64(len(archive))) {
		t.Fatalf("progress %d/%d for %d bytes", last, total, len(archive))
	}
}
