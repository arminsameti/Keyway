// Package core manages installed Xray-core binaries: listing, resolving,
// discovering releases and downloading them with checksum verification.
package core

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultAPIBase = "https://api.github.com"
	maxArchiveSize = 300 << 20
	maxAPIBody     = 4 << 20
)

// ErrNotInstalled is returned when no usable engine binary exists.
var ErrNotInstalled = errors.New("engine not installed")

// Archive formats and checksum sources a Source can use.
const (
	ArchiveZip   = "zip"
	ArchiveTarGz = "tar.gz"

	// ChecksumDgst: a "<asset>.dgst" file published next to the asset (Xray).
	ChecksumDgst = "dgst"
	// ChecksumDigest: the "sha256:<hex>" digest GitHub's release API reports
	// for the asset (sing-box publishes no checksum file).
	ChecksumDigest = "digest"
)

// Member is one archive entry that may be extracted, with its mode and size cap.
type Member struct {
	Mode os.FileMode
	Max  uint64
}

// Source describes where an engine's releases come from and what they contain.
type Source struct {
	Name     string // engine name, used in messages
	Repo     string // GitHub owner/name
	Binary   string // executable name inside the archive and the install dir
	Archive  string // ArchiveZip or ArchiveTarGz
	Checksum string // ChecksumDgst or ChecksumDigest
	// Files whitelists the archive members to extract (by base name). Nothing
	// else is ever written, and no archive name is used to build a path.
	Files map[string]Member
	// Assets lists release asset names for this platform, best first.
	Assets func(version string) ([]string, error)
	// Provider, when set, replaces the GitHub release channel (Repo, Assets and
	// Checksum are unused); Hosts then lists the hosts downloads may come from.
	Provider Provider
	Hosts    []string
	// Rename maps an archive member (as listed in Files) to the name it is
	// written under; members not listed keep their name.
	Rename map[string]string
	// PostInstall runs on the staged directory before it is moved into place.
	PostInstall func(dir string) error
}

// Provider is a release channel other than GitHub releases.
type Provider interface {
	// Latest returns the newest stable version tag (vMAJOR.MINOR.PATCH).
	Latest(ctx context.Context, c *http.Client) (string, error)
	// Asset returns the archive URL for this platform and its SHA-256.
	Asset(ctx context.Context, c *http.Client, version string) (url, sha256 string, err error)
}

// XraySource is the official Xray-core release channel.
var XraySource = Source{
	Name: "Xray core", Repo: "XTLS/Xray-core", Binary: "xray", Archive: ArchiveZip, Checksum: ChecksumDgst,
	Files: map[string]Member{
		"xray":        {0o755, maxBinarySize},
		"geoip.dat":   {0o644, maxDataSize},
		"geosite.dat": {0o644, maxDataSize},
	},
	Assets: xrayAssets,
}

// SingBoxSource is the official sing-box release channel.
var SingBoxSource = Source{
	Name: "sing-box", Repo: "SagerNet/sing-box", Binary: "sing-box", Archive: ArchiveTarGz, Checksum: ChecksumDigest,
	Files:  map[string]Member{"sing-box": {0o755, maxBinarySize}},
	Assets: singBoxAssets,
}

// V2RaySource is the official v2ray-core release channel.
var V2RaySource = Source{
	Name: "V2Ray core", Repo: "v2fly/v2ray-core", Binary: "v2ray", Archive: ArchiveZip, Checksum: ChecksumDgst,
	Files: map[string]Member{
		"v2ray":       {0o755, maxBinarySize},
		"geoip.dat":   {0o644, maxDataSize},
		"geosite.dat": {0o644, maxDataSize},
	},
	Assets: v2rayAssets,
}

// Release is a published Xray-core release.
type Release struct {
	Tag       string    `json:"tag_name"`
	Name      string    `json:"name"`
	Published time.Time `json:"published_at"`
	Installed bool      `json:"installed"`
}

type ghAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"` // "sha256:<hex>", computed by GitHub
}

type ghRelease struct {
	Release
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []ghAsset `json:"assets"`
}

// Manager owns one engine's install directory (~/.keyway/engines/<name>).
// It holds no mutable "active version" state: the caller (the service) owns
// that and passes the version in.
type Manager struct {
	src     Source
	dir     string
	apiBase string
	client  *http.Client
	// allowHost restricts where downloads may come from, including redirects.
	allowHost func(host string) bool
}

// NewManager creates the install directory if needed.
func NewManager(dir string, src Source) (*Manager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create engine dir: %w", err)
	}
	m := &Manager{src: src, dir: dir, apiBase: defaultAPIBase, allowHost: githubHost}
	if len(src.Hosts) > 0 {
		m.allowHost = func(h string) bool {
			h = strings.ToLower(h)
			for _, a := range src.Hosts {
				if h == a {
					return true
				}
			}
			return false
		}
	}
	m.client = &http.Client{
		Timeout: 10 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return m.checkURL(req.URL)
		},
	}
	return m, nil
}

func githubHost(h string) bool {
	h = strings.ToLower(h)
	return h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".githubusercontent.com")
}

func (m *Manager) checkURL(u *url.URL) error {
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-https download URL")
	}
	if !m.allowHost(u.Hostname()) {
		return fmt.Errorf("refusing download from unexpected host %q", u.Hostname())
	}
	return nil
}

// Dir is the cores directory.
func (m *Manager) Dir() string { return m.dir }

// Source returns the release source this manager installs from.
func (m *Manager) Source() Source { return m.src }

func (m *Manager) releasesURL() string { return m.apiBase + "/repos/" + m.src.Repo + "/releases" }

func (m *Manager) versionDir(v string) string { return filepath.Join(m.dir, v) }

// Installed lists installed versions, oldest first (numeric order).
func (m *Manager) Installed() []string {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || !ValidVersion(e.Name()) {
			continue
		}
		if st, err := os.Stat(filepath.Join(m.versionDir(e.Name()), m.src.Binary)); err == nil && !st.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Slice(out, func(i, j int) bool { return CompareVersions(out[i], out[j]) < 0 })
	return out
}

// Resolve maps a version (or "" for the newest installed) to its binary and
// asset directory. It has no side effects.
func (m *Manager) Resolve(version string) (bin, assetDir, resolved string, err error) {
	version = NormalizeVersion(version)
	if version != "" && !ValidVersion(version) {
		return "", "", "", fmt.Errorf("invalid %s version %q", m.src.Name, version)
	}
	if version != "" {
		if _, serr := os.Stat(filepath.Join(m.versionDir(version), m.src.Binary)); serr != nil {
			version = "" // requested core vanished: fall back to the newest installed
		}
	}
	if version == "" {
		inst := m.Installed()
		if len(inst) == 0 {
			return "", "", "", fmt.Errorf("%w: no %s installed; download it in Settings › Engines", ErrNotInstalled, m.src.Name)
		}
		version = inst[len(inst)-1]
	}
	dir := m.versionDir(version)
	return filepath.Join(dir, m.src.Binary), dir, version, nil
}

func (m *Manager) get(ctx context.Context, rawURL string, accept string, limit int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if err := m.checkURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "keyway")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if tok := os.Getenv("GITHUB_TOKEN"); tok != "" && u.Hostname() == "api.github.com" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u.Hostname(), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response from %s is too large", u.Hostname())
	}
	return b, nil
}

// FetchReleases lists recent stable releases (no drafts or prereleases).
func (m *Manager) FetchReleases(ctx context.Context, limit int) ([]Release, error) {
	if p := m.src.Provider; p != nil {
		v, err := p.Latest(ctx, m.client)
		if err != nil {
			return nil, fmt.Errorf("list releases: %w", err)
		}
		inst := false
		for _, i := range m.Installed() {
			inst = inst || i == v
		}
		return []Release{{Tag: v, Name: v, Installed: inst}}, nil
	}
	if limit <= 0 || limit > 50 {
		limit = 10
	}
	// Over-fetch: filtered-out prereleases must not eat into the limit.
	b, err := m.get(ctx, fmt.Sprintf("%s?per_page=%d", m.releasesURL(), limit*2), "application/vnd.github+json", maxAPIBody)
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}
	var raw []ghRelease
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode releases: %w", err)
	}
	installed := map[string]bool{}
	for _, v := range m.Installed() {
		installed[v] = true
	}
	var out []Release
	for _, r := range raw {
		if r.Draft || r.Prerelease || !ValidVersion(r.Tag) {
			continue
		}
		r.Release.Installed = installed[r.Tag]
		out = append(out, r.Release)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// singBoxAssets lists sing-box release asset names for this platform.
func singBoxAssets(version string) ([]string, error) {
	v := strings.TrimPrefix(NormalizeVersion(version), "v")
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64", "darwin/amd64", "linux/amd64", "linux/arm64":
		return []string{fmt.Sprintf("sing-box-%s-%s-%s.tar.gz", v, runtime.GOOS, runtime.GOARCH)}, nil
	}
	return nil, fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

// xrayAssets lists Xray release asset names for this platform, best first.
func xrayAssets(string) ([]string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return []string{"Xray-macos-arm64-v8a.zip", "Xray-macos-arm64.zip"}, nil
	case "darwin/amd64":
		return []string{"Xray-macos-64.zip"}, nil
	case "linux/amd64":
		return []string{"Xray-linux-64.zip"}, nil
	case "linux/arm64":
		return []string{"Xray-linux-arm64-v8a.zip"}, nil
	}
	return nil, fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

// v2rayAssets lists v2ray-core release asset names for this platform.
func v2rayAssets(string) ([]string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return []string{"v2ray-macos-arm64-v8a.zip"}, nil
	case "darwin/amd64":
		return []string{"v2ray-macos-64.zip"}, nil
	case "linux/amd64":
		return []string{"v2ray-linux-64.zip"}, nil
	case "linux/arm64":
		return []string{"v2ray-linux-arm64-v8a.zip"}, nil
	}
	return nil, fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

// Download installs a release after verifying its SHA2-256 against the .dgst asset.
func (m *Manager) Download(ctx context.Context, version string) error {
	version = NormalizeVersion(version)
	if !ValidVersion(version) {
		return fmt.Errorf("invalid %s version %q (expected like v25.1.1)", m.src.Name, version)
	}
	if p := m.src.Provider; p != nil {
		u, want, err := p.Asset(ctx, m.client, version)
		if err != nil {
			return err
		}
		zipPath, got, err := m.downloadArchive(ctx, u)
		if err != nil {
			return err
		}
		defer os.Remove(zipPath)
		if got != want {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", m.src.Name, want, got)
		}
		return m.install(zipPath, version)
	}
	candidates, err := m.src.Assets(version)
	if err != nil {
		return err
	}
	b, err := m.get(ctx, fmt.Sprintf("%s/tags/%s", m.releasesURL(), version), "application/vnd.github+json", maxAPIBody)
	if err != nil {
		return fmt.Errorf("look up release %s: %w", version, err)
	}
	var rel ghRelease
	if err := json.Unmarshal(b, &rel); err != nil {
		return fmt.Errorf("decode release: %w", err)
	}
	byName := map[string]ghAsset{}
	for _, a := range rel.Assets {
		byName[a.Name] = a
	}
	var asset ghAsset
	for _, c := range candidates {
		if a, ok := byName[c]; ok {
			asset = a
			break
		}
	}
	if asset.URL == "" {
		return fmt.Errorf("release %s has no asset for this platform (looked for %s)", version, strings.Join(candidates, ", "))
	}
	wantSum, err := m.expectedSum(ctx, version, asset, byName)
	if err != nil {
		return err
	}
	zipName, zipURL := asset.Name, asset.URL

	zipPath, gotSum, err := m.downloadArchive(ctx, zipURL)
	if err != nil {
		return err
	}
	defer os.Remove(zipPath)
	if gotSum != wantSum {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", zipName, wantSum, gotSum)
	}
	return m.install(zipPath, version)
}

// expectedSum returns the SHA-256 the archive must have, from the source's
// checksum channel. A missing checksum refuses the download.
func (m *Manager) expectedSum(ctx context.Context, version string, asset ghAsset, byName map[string]ghAsset) (string, error) {
	switch m.src.Checksum {
	case ChecksumDgst:
		dgst, ok := byName[asset.Name+".dgst"]
		if !ok {
			return "", fmt.Errorf("release %s has no checksum file for %s; refusing unverified download", version, asset.Name)
		}
		b, err := m.get(ctx, dgst.URL, "", 64<<10)
		if err != nil {
			return "", fmt.Errorf("download checksum: %w", err)
		}
		return parseSHA256(string(b))
	case ChecksumDigest:
		algo, sum, ok := strings.Cut(asset.Digest, ":")
		sum = strings.ToLower(sum)
		if !ok || algo != "sha256" || len(sum) != 64 {
			return "", fmt.Errorf("release %s reports no SHA-256 for %s; refusing unverified download", version, asset.Name)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return "", fmt.Errorf("release %s reports an invalid SHA-256 for %s", version, asset.Name)
		}
		return sum, nil
	}
	return "", fmt.Errorf("internal error: unknown checksum source %q", m.src.Checksum)
}

func (m *Manager) downloadArchive(ctx context.Context, rawURL string) (path, sum string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	if err := m.checkURL(u); err != nil {
		return "", "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "keyway")
	resp, err := m.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download: %s", resp.Status)
	}
	tmp, err := os.CreateTemp(m.dir, ".dl-*")
	if err != nil {
		return "", "", err
	}
	h := sha256.New()
	var dst io.Writer = io.MultiWriter(tmp, h)
	if fn, ok := ctx.Value(progressKey{}).(ProgressFunc); ok {
		dst = &progressWriter{w: dst, total: resp.ContentLength, fn: fn}
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, maxArchiveSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxArchiveSize {
		err = errors.New("archive exceeds the size limit")
	}
	if err != nil {
		os.Remove(tmp.Name())
		return "", "", fmt.Errorf("download: %w", err)
	}
	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// install extracts into a staging directory, then atomically swaps it into place.
func (m *Manager) install(zipPath, version string) error {
	stage, err := os.MkdirTemp(m.dir, ".stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	extract := extractWhitelisted
	if m.src.Archive == ArchiveTarGz {
		extract = extractTarGz
	}
	if err := extract(zipPath, stage, m.src); err != nil {
		return err
	}
	if m.src.PostInstall != nil {
		if err := m.src.PostInstall(stage); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(stage, "VERSION"), []byte(version), 0o644); err != nil {
		return err
	}
	final := m.versionDir(version) // version already matched versionRe: no separators possible
	if filepath.Dir(final) != filepath.Clean(m.dir) {
		return fmt.Errorf("internal error: unexpected install path")
	}
	old := final + ".old"
	_ = os.RemoveAll(old)
	if _, err := os.Stat(final); err == nil {
		if err := os.Rename(final, old); err != nil {
			return fmt.Errorf("replace existing core: %w", err)
		}
	}
	if err := os.Rename(stage, final); err != nil {
		_ = os.Rename(old, final) // roll back
		return fmt.Errorf("install core: %w", err)
	}
	_ = os.RemoveAll(old)
	return nil
}

// parseSHA256 extracts the SHA2-256 value from an Xray ".dgst" file
// (lines such as "SHA2-256= <hex>").
func parseSHA256(dgst string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(dgst))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		key := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(k), "-", ""))
		if key != "SHA256" && key != "SHA2256" {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if len(v) == 64 {
			if _, err := hex.DecodeString(v); err == nil {
				return v, nil
			}
		}
	}
	return "", errors.New("checksum file has no valid SHA2-256 entry")
}

// VersionOf runs "xray version" and returns its first line ("" on failure).
func VersionOf(binaryPath string) string {
	if binaryPath == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryPath, "version").Output()
	if err != nil { // Tor takes --version
		if out, err = exec.CommandContext(ctx, binaryPath, "--version").Output(); err != nil {
			return ""
		}
	}
	first, _, _ := strings.Cut(string(out), "\n")
	return strings.TrimSpace(first)
}

// TagsOf reads the build tags from "sing-box version" ("Tags: with_quic,...").
// It returns nil when the binary does not report any.
func TagsOf(binaryPath string) map[string]bool {
	if binaryPath == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binaryPath, "version").Output()
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Tags:"); ok {
			tags := map[string]bool{}
			for _, t := range strings.Split(v, ",") {
				if t = strings.TrimSpace(t); t != "" {
					tags[t] = true
				}
			}
			return tags
		}
	}
	return nil
}

// ProgressFunc receives download progress; total is -1 when unknown.
type ProgressFunc func(done, total int64)

type progressKey struct{}

// WithProgress makes downloads under ctx report their progress to fn.
func WithProgress(ctx context.Context, fn ProgressFunc) context.Context {
	return context.WithValue(ctx, progressKey{}, fn)
}

type progressWriter struct {
	w     io.Writer
	done  int64
	total int64
	fn    ProgressFunc
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.done += int64(n)
	p.fn(p.done, p.total)
	return n, err
}
