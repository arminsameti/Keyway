package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// TorSource is the Tor Project's Expert Bundle (the tor daemon and its
// pluggable transports), published on dist.torproject.org.
var TorSource = Source{
	Name: "Tor", Binary: "tor", Archive: ArchiveTarGz,
	// The bundle has no top-level folder; extractTarGz drops the first path
	// component, so "tor/tor" is "tor" here. Snowflake is part of lyrebird.
	Files: map[string]Member{
		"tor":                                 {0o755, maxBinarySize},
		"libevent-2.1.7.dylib":                {0o755, maxDataSize},
		"pluggable_transports/lyrebird":       {0o755, maxBinarySize},
		"pluggable_transports/pt_config.json": {0o644, 1 << 20},
		"geoip":                               {0o644, maxDataSize},
		"geoip6":                              {0o644, maxDataSize},
	},
	Rename: map[string]string{
		"pluggable_transports/lyrebird":       "lyrebird",
		"pluggable_transports/pt_config.json": "pt_config.json",
	},
	PostInstall: torSign,
	Provider:    torProvider{},
	Hosts:       []string{"dist.torproject.org", "aus1.torproject.org"},
}

// torSign re-signs the extracted programs ad hoc. The Tor Project's arm64
// builds ship with a signature that no longer matches the file, and macOS kills
// such a program on launch.
func torSign(dir string) error {
	for _, f := range []string{"libevent-2.1.7.dylib", "tor", "lyrebird"} {
		if out, err := exec.Command("codesign", "--force", "--sign", "-", filepath.Join(dir, f)).CombinedOutput(); err != nil {
			return fmt.Errorf("sign %s: %v: %s", f, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

const (
	torUpdateURL = "https://aus1.torproject.org/torbrowser/update_3/release/download-macos.json"
	torDistURL   = "https://dist.torproject.org/torbrowser/"
)

type torProvider struct{}

// torVersion maps a Tor Browser version ("16.0") to the three-part tag used for
// install directories ("v16.0.0"), and back.
func torTag(v string) string {
	for strings.Count(v, ".") < 2 {
		v += ".0"
	}
	return "v" + v
}

func torVersion(tag string) string {
	v := strings.TrimSuffix(strings.TrimPrefix(tag, "v"), ".0")
	return v
}

func torGet(ctx context.Context, c *http.Client, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "keyway")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (torProvider) Latest(ctx context.Context, c *http.Client) (string, error) {
	b, err := torGet(ctx, c, torUpdateURL, 1<<16)
	if err != nil {
		return "", err
	}
	var d struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return "", fmt.Errorf("decode Tor release info: %w", err)
	}
	tag := torTag(d.Version)
	if !ValidVersion(tag) {
		return "", fmt.Errorf("unexpected Tor version %q", d.Version)
	}
	return tag, nil
}

func (torProvider) Asset(ctx context.Context, c *http.Client, tag string) (string, string, error) {
	if !ValidVersion(tag) {
		return "", "", fmt.Errorf("invalid Tor version %q", tag)
	}
	var arch string
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		arch = "aarch64"
	case "darwin/amd64":
		arch = "x86_64"
	default:
		return "", "", fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	v := torVersion(tag)
	name := fmt.Sprintf("tor-expert-bundle-macos-%s-%s.tar.gz", arch, v)
	base := torDistURL + v + "/"
	sums, err := torGet(ctx, c, base+"sha256sums-signed-build.txt", 1<<20)
	if err != nil {
		return "", "", fmt.Errorf("download Tor checksums: %w", err)
	}
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name && len(f[0]) == 64 {
			return base + name, strings.ToLower(f[0]), nil
		}
	}
	return "", "", fmt.Errorf("no published checksum for %s; refusing unverified download", name)
}
