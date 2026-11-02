package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mihomo's geodata files, as it looks for them in its home directory.
const (
	GeoSiteFile = "GeoSite.dat"
	GeoIPFile   = "geoip.metadb"

	geoRepo       = "MetaCubeX/meta-rules-dat"
	geoReleaseTag = "latest" // the repository's one rolling release
	maxGeoSize    = 64 << 20
	geoRefreshAge = 30 * 24 * time.Hour
)

// geoAssets maps the local file to the release asset it comes from.
var geoAssets = map[string]string{GeoSiteFile: "geosite.dat", GeoIPFile: "geoip.metadb"}

// GeoDataDir is Mihomo's home directory (-d): its geodata and caches live
// there, next to the version directories, so an engine update keeps them.
func (m *Manager) GeoDataDir() string { return filepath.Join(m.dir, "data") }

// EnsureGeoData makes the named Mihomo geodata files exist. Mihomo would
// download a missing one itself, unverified, at startup; its config points the
// download URLs nowhere, so the files are fetched here instead, verified against
// the SHA-256 GitHub's release API reports for the asset (the same trust root
// as the engine download). A file older than 30 days is fetched again; if that
// fails the old copy is kept, since stale geodata still routes.
func (m *Manager) EnsureGeoData(ctx context.Context, files []string) error {
	for _, f := range files {
		if _, ok := geoAssets[f]; !ok {
			return fmt.Errorf("unknown geodata file %q", f)
		}
	}
	if len(files) == 0 {
		return nil
	}
	if err := os.MkdirAll(m.GeoDataDir(), 0o700); err != nil {
		return err
	}
	var release *ghRelease
	for _, f := range files {
		path := filepath.Join(m.GeoDataDir(), f)
		st, err := os.Stat(path)
		have := err == nil && st.Mode().IsRegular() && st.Size() > 0
		if have && time.Since(st.ModTime()) < geoRefreshAge {
			continue
		}
		if release == nil {
			r, err := m.geoRelease(ctx)
			if err != nil {
				if have {
					continue
				}
				return err
			}
			release = r
		}
		if err := m.fetchGeoFile(ctx, release, f, path); err != nil && !have {
			return err
		}
	}
	return nil
}

func (m *Manager) geoRelease(ctx context.Context) (*ghRelease, error) {
	b, err := m.get(ctx, fmt.Sprintf("%s/repos/%s/releases/tags/%s", m.apiBase, geoRepo, geoReleaseTag), "application/vnd.github+json", maxAPIBody)
	if err != nil {
		return nil, fmt.Errorf("look up the geodata release: %w", err)
	}
	var rel ghRelease
	if err := json.Unmarshal(b, &rel); err != nil {
		return nil, fmt.Errorf("decode the geodata release: %w", err)
	}
	return &rel, nil
}

func (m *Manager) fetchGeoFile(ctx context.Context, rel *ghRelease, file, path string) error {
	name := geoAssets[file]
	var asset ghAsset
	for _, a := range rel.Assets {
		if a.Name == name {
			asset = a
		}
	}
	if asset.URL == "" {
		return fmt.Errorf("the geodata release has no %s", name)
	}
	algo, want, ok := strings.Cut(asset.Digest, ":")
	want = strings.ToLower(want)
	if _, err := hex.DecodeString(want); !ok || algo != "sha256" || len(want) != 64 || err != nil {
		return fmt.Errorf("the geodata release reports no SHA-256 for %s; refusing unverified download", name)
	}
	data, err := m.get(ctx, asset.URL, "", maxGeoSize)
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", name, want, got)
	}
	tmp, err := os.CreateTemp(m.GeoDataDir(), ".geo-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	_ = os.Chmod(tmp.Name(), 0o644)
	if err := os.Rename(tmp.Name(), path); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}
