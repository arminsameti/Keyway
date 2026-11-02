// Package appupdate finds out whether a newer Keyway release exists and
// downloads its disk image, checked against the release's SHA256SUMS.txt.
// It never installs anything: the user opens the verified image themselves.
package appupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"keyway/internal/core"
)

const (
	defaultAPIBase = "https://api.github.com"
	repo           = "arminsameti/Keyway"
	maxAPIBody     = 1 << 20
	maxSumsBody    = 64 << 10
	maxImageSize   = 300 << 20
)

// currentRe picks the release a build descends from out of `git describe`
// output ("v0.2.1", "v0.2.1-3-gabc1234-dirty"); "dev" builds do not match.
var currentRe = regexp.MustCompile(`^v?(\d{1,3}\.\d{1,3}\.\d{1,3})(?:-|$)`)

// Release is the newest stable Keyway release.
type Release struct {
	Tag      string // vMAJOR.MINOR.PATCH
	NotesURL string // the release page on GitHub
	dmgURL   string
	sumsURL  string
}

// DiskImage is the file name the release workflow gives the macOS disk image.
func (r Release) DiskImage() string { return "Keyway-" + r.Tag + "-macOS.dmg" }

// Checker queries GitHub for releases of Keyway.
type Checker struct {
	current   string
	apiBase   string
	client    *http.Client
	allowHost func(host string) bool
}

// New returns a Checker for a running build of the given version.
func New(current string) *Checker {
	c := &Checker{current: current, apiBase: defaultAPIBase, allowHost: githubHost}
	c.client = &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return c.checkURL(req.URL)
		},
	}
	return c
}

// Current is the version of the running build.
func (c *Checker) Current() string { return c.current }

func githubHost(h string) bool {
	h = strings.ToLower(h)
	return h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".githubusercontent.com")
}

func (c *Checker) checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return errors.New("refusing non-https download URL")
	}
	if !c.allowHost(u.Hostname()) {
		return fmt.Errorf("refusing download from unexpected host %q", u.Hostname())
	}
	return nil
}

// Newer reports whether latest is a later release than the running build.
// A build whose version is unknown (a "dev" build) is never told to update.
func Newer(current, latest string) bool {
	m := currentRe.FindStringSubmatch(strings.TrimSpace(current))
	if m == nil || !core.ValidVersion(latest) {
		return false
	}
	return core.CompareVersions(m[1], latest) < 0
}

func (c *Checker) get(ctx context.Context, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := c.checkURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// Nothing identifying goes out: no version, no token, no cookies.
	req.Header.Set("User-Agent", "keyway")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s", u.Hostname(), resp.Status)
	}
	return resp, nil
}

func (c *Checker) getBytes(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	resp, err := c.get(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("response is too large")
	}
	return b, nil
}

// Latest returns the newest stable release (GitHub's "latest" skips drafts and
// prereleases).
func (c *Checker) Latest(ctx context.Context) (Release, error) {
	b, err := c.getBytes(ctx, c.apiBase+"/repos/"+repo+"/releases/latest", maxAPIBody)
	if err != nil {
		return Release{}, fmt.Errorf("check for updates: %w", err)
	}
	var raw struct {
		Tag        string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return Release{}, fmt.Errorf("decode release: %w", err)
	}
	// The tag ends up in a file name: it must be exactly vMAJOR.MINOR.PATCH.
	if raw.Draft || raw.Prerelease || !core.ValidVersion(raw.Tag) {
		return Release{}, fmt.Errorf("unexpected release %q", raw.Tag)
	}
	r := Release{Tag: raw.Tag, NotesURL: "https://github.com/" + repo + "/releases/tag/" + raw.Tag}
	for _, a := range raw.Assets {
		switch a.Name {
		case r.DiskImage():
			r.dmgURL = a.URL
		case "SHA256SUMS.txt":
			r.sumsURL = a.URL
		}
	}
	return r, nil
}

// Download fetches the release's disk image into dir and returns its path. The
// file only appears under its real name once its SHA-256 matches the one in the
// release's SHA256SUMS.txt; anything else is deleted.
func (c *Checker) Download(ctx context.Context, r Release, dir string, progress func(done, total int64)) (string, error) {
	if !core.ValidVersion(r.Tag) || r.dmgURL == "" || r.sumsURL == "" {
		return "", fmt.Errorf("release %s has no disk image with checksums", r.Tag)
	}
	sums, err := c.getBytes(ctx, r.sumsURL, maxSumsBody)
	if err != nil {
		return "", fmt.Errorf("download checksums: %w", err)
	}
	want, err := sumFor(string(sums), r.DiskImage())
	if err != nil {
		return "", err
	}
	resp, err := c.get(ctx, r.dmgURL)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", r.DiskImage(), err)
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, ".Keyway-*.part")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name()) // gone after the rename; removes a failed download
	h := sha256.New()
	var done int64
	buf := make([]byte, 64<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			done += int64(n)
			if done > maxImageSize {
				f.Close()
				return "", errors.New("disk image is too large")
			}
			h.Write(buf[:n])
			if _, werr := f.Write(buf[:n]); werr != nil {
				f.Close()
				return "", werr
			}
			if progress != nil {
				progress(done, resp.ContentLength)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			f.Close()
			return "", rerr
		}
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("checksum mismatch for %s: the download does not match SHA256SUMS.txt and was deleted", r.DiskImage())
	}
	dst := filepath.Join(dir, r.DiskImage())
	if err := os.Rename(f.Name(), dst); err != nil {
		return "", err
	}
	return dst, nil
}

// sumFor finds name's SHA-256 in `shasum -a 256` output ("<hex>  <name>").
func sumFor(sums, name string) (string, error) {
	for _, line := range strings.Split(sums, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name && len(f[0]) == 64 {
			if _, err := hex.DecodeString(f[0]); err == nil {
				return strings.ToLower(f[0]), nil
			}
		}
	}
	return "", fmt.Errorf("SHA256SUMS.txt does not list %s", name)
}
