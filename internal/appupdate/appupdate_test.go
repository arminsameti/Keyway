package appupdate

import (
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

const testDMG = "Keyway-v0.2.2-macOS.dmg"

// fixture serves a GitHub-like release API plus the release's downloads.
type fixture struct {
	ts       *httptest.Server
	dmg      []byte
	sums     string // body of SHA256SUMS.txt; built from dmg when empty
	tag      string
	noDMG    bool
	authSeen string
}

func newFixture(t *testing.T) (*fixture, *Checker) {
	t.Helper()
	f := &fixture{dmg: []byte("pretend disk image"), tag: "v0.2.2"}
	f.ts = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/arminsameti/Keyway/releases/latest":
			f.authSeen = r.Header.Get("Authorization")
			assets := fmt.Sprintf(`{"name":"SHA256SUMS.txt","browser_download_url":"%s/dl/SHA256SUMS.txt"}`, f.ts.URL)
			if !f.noDMG {
				assets += fmt.Sprintf(`,{"name":"Keyway-%s-macOS.dmg","browser_download_url":"%s/dl/dmg"}`, f.tag, f.ts.URL)
			}
			fmt.Fprintf(w, `{"tag_name":%q,"html_url":"https://github.com/arminsameti/Keyway/releases/tag/%s","draft":false,"prerelease":false,"assets":[%s]}`, f.tag, f.tag, assets)
		case "/dl/dmg":
			_, _ = w.Write(f.dmg)
		case "/dl/SHA256SUMS.txt":
			if f.sums != "" {
				_, _ = w.Write([]byte(f.sums))
				return
			}
			sum := sha256.Sum256(f.dmg)
			fmt.Fprintf(w, "%s  Keyway-v0.2.2-macOS.zip\n%s  %s\n", strings.Repeat("0", 64), hex.EncodeToString(sum[:]), testDMG)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.ts.Close)
	c := New("v0.2.1")
	c.client, c.apiBase, c.allowHost = f.ts.Client(), f.ts.URL, func(string) bool { return true }
	return f, c
}

func TestLatestReadsTheStableRelease(t *testing.T) {
	f, c := newFixture(t)
	t.Setenv("GITHUB_TOKEN", "secret")
	r, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.Tag != "v0.2.2" || r.NotesURL != "https://github.com/arminsameti/Keyway/releases/tag/v0.2.2" {
		t.Fatalf("got %+v", r)
	}
	if f.authSeen != "" {
		t.Fatalf("the update check must not send credentials, got %q", f.authSeen)
	}
}

func TestLatestRejectsMalformedTag(t *testing.T) {
	f, c := newFixture(t)
	f.tag = "v0.2.2/../../x"
	if _, err := c.Latest(context.Background()); err == nil {
		t.Fatal("expected an error for a tag that is not vMAJOR.MINOR.PATCH")
	}
}

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		current, latest string
		want            bool
	}{
		{"v0.2.1", "v0.2.2", true},
		{"v0.2.1", "v0.2.1", false},
		{"v0.2.1", "v0.2.0", false},
		{"v0.9.0", "v0.10.0", true},
		{"v0.2.1-3-gabc1234-dirty", "v0.2.1", false}, // built past the release
		{"v0.2.1-3-gabc1234", "v0.2.2", true},
		{"dev", "v9.9.9", false}, // no known version: never nag
		{"", "v9.9.9", false},
	} {
		if got := Newer(tc.current, tc.latest); got != tc.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", tc.current, tc.latest, got, tc.want)
		}
	}
}

func TestDownloadVerifiesAgainstSHA256SUMS(t *testing.T) {
	_, c := newFixture(t)
	r, err := c.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var last int64
	path, err := c.Download(context.Background(), r, dir, func(done, total int64) { last = done })
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, testDMG) {
		t.Fatalf("path %q", path)
	}
	if b, _ := os.ReadFile(path); string(b) != "pretend disk image" {
		t.Fatalf("content %q", b)
	}
	if last != int64(len("pretend disk image")) {
		t.Fatalf("progress ended at %d", last)
	}
}

func TestDownloadRefusesAChecksumMismatch(t *testing.T) {
	f, c := newFixture(t)
	f.sums = strings.Repeat("a", 64) + "  " + testDMG + "\n"
	r, _ := c.Latest(context.Background())
	dir := t.TempDir()
	if _, err := c.Download(context.Background(), r, dir, nil); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want a checksum error, got %v", err)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("an unverified download must not be left behind: %v", left)
	}
}

func TestDownloadNeedsAChecksumLine(t *testing.T) {
	f, c := newFixture(t)
	f.sums = strings.Repeat("a", 64) + "  Keyway-v0.2.2-macOS.zip\n"
	r, _ := c.Latest(context.Background())
	if _, err := c.Download(context.Background(), r, t.TempDir(), nil); err == nil {
		t.Fatal("expected an error when SHA256SUMS.txt does not list the disk image")
	}
}

func TestDownloadNeedsTheDiskImage(t *testing.T) {
	f, c := newFixture(t)
	f.noDMG = true
	r, _ := c.Latest(context.Background())
	if _, err := c.Download(context.Background(), r, t.TempDir(), nil); err == nil {
		t.Fatal("expected an error when the release has no disk image")
	}
}

func TestDownloadRefusesUnexpectedHosts(t *testing.T) {
	_, c := newFixture(t)
	c.allowHost = githubHost // the test server is 127.0.0.1
	r := Release{Tag: "v0.2.2", dmgURL: c.apiBase + "/dl/dmg", sumsURL: c.apiBase + "/dl/SHA256SUMS.txt"}
	if _, err := c.Download(context.Background(), r, t.TempDir(), nil); err == nil {
		t.Fatal("expected a refusal for a non-GitHub host")
	}
}
