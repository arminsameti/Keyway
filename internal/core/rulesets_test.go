package core

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func blobSHA(b []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func fakeRuleSets(t *testing.T, files map[string][]byte, shaOverride string) (*Manager, *int) {
	t.Helper()
	calls := 0
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/repos/SagerNet/", func(w http.ResponseWriter, r *http.Request) {
		calls++
		name := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if r.URL.Query().Get("ref") != "rule-set" {
			http.Error(w, "wrong ref", 400)
			return
		}
		data, ok := files[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		sha := blobSHA(data)
		if shaOverride != "" {
			sha = shaOverride
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "sha": sha, "size": len(data), "download_url": srv.URL + "/raw/" + name})
	})
	mux.HandleFunc("/raw/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(files[strings.TrimPrefix(r.URL.Path, "/raw/")])
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	m, _ := NewManager(t.TempDir(), SingBoxSource)
	m.apiBase, m.client, m.allowHost = srv.URL, srv.Client(), func(string) bool { return true }
	return m, &calls
}

func TestEnsureRuleSets(t *testing.T) {
	files := map[string][]byte{"geosite-cn.srs": []byte("SRS-cn"), "geoip-ir.srs": []byte("SRS-ir")}
	m, calls := fakeRuleSets(t, files, "")
	if err := m.EnsureRuleSets(context.Background(), []string{"geosite-cn", "geoip-ir"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(m.RuleSetPath("geoip-ir")); string(b) != "SRS-ir" {
		t.Fatalf("content %q", b)
	}
	before := *calls
	if err := m.EnsureRuleSets(context.Background(), []string{"geosite-cn"}); err != nil || *calls != before {
		t.Fatalf("present rule sets must not be fetched again (calls %d -> %d, %v)", before, *calls, err)
	}
	if err := m.EnsureRuleSets(context.Background(), []string{"geosite-nope"}); err == nil || !strings.Contains(err.Error(), "geosite:nope does not exist") {
		t.Fatalf("missing: %v", err)
	}
	for _, bad := range []string{"../x", "geosite-a/b", "other-cn", "geosite-"} {
		if err := m.EnsureRuleSets(context.Background(), []string{bad}); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

func TestRuleSetChecksumMismatch(t *testing.T) {
	m, _ := fakeRuleSets(t, map[string][]byte{"geosite-cn.srs": []byte("tampered")}, strings.Repeat("a", 40))
	err := m.EnsureRuleSets(context.Background(), []string{"geosite-cn"})
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want mismatch, got %v", err)
	}
	if _, err := os.Stat(m.RuleSetPath("geosite-cn")); err == nil {
		t.Fatal("unverified rule set was kept")
	}
}
