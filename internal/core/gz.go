package core

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// extractGz installs a release that is one gzip-compressed executable (Mihomo
// publishes "mihomo-darwin-arm64-vX.Y.Z.gz" and nothing else). The archive has
// no member names, so the file is written as src.Binary and nothing in the
// archive picks a path. The output is capped by src.Files[src.Binary].Max, a
// second gzip member or any bytes after the first are refused, and an empty
// result is refused.
func extractGz(path, dest string, src Source) error {
	w, ok := src.Files[src.Binary]
	if !ok {
		return fmt.Errorf("internal error: no size limit for %s", src.Binary)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()
	br := bufio.NewReader(f) // a ByteReader, so gzip reads exactly one member
	gz, err := gzip.NewReader(br)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	gz.Multistream(false)

	target := filepath.Join(dest, src.Binary)
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, w.Mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", src.Binary, err)
	}
	n, err := io.Copy(out, io.LimitReader(gz, int64(w.Max)+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return fmt.Errorf("extract %s: %w", src.Binary, err)
	case uint64(n) > w.Max:
		return fmt.Errorf("%s exceeds the size limit", src.Binary)
	case n == 0:
		return fmt.Errorf("archive holds an empty %s", src.Binary)
	}
	if _, perr := br.Peek(1); !errors.Is(perr, io.EOF) {
		return errors.New("archive has data after the compressed file; refusing it")
	}
	return os.Chmod(target, w.Mode)
}

// mihomoAssets lists the Mihomo release asset for this platform. The amd64
// builds named "compatible" are GOAMD64=v1: the unsuffixed ones are v3 and
// crash on Intel Macs without AVX2.
func mihomoAssets(version string) ([]string, error) {
	return mihomoAssetsFor(runtime.GOOS+"/"+runtime.GOARCH, version)
}

func mihomoAssetsFor(platform, version string) ([]string, error) {
	v := NormalizeVersion(version)
	switch platform {
	case "darwin/arm64":
		return []string{fmt.Sprintf("mihomo-darwin-arm64-%s.gz", v)}, nil
	case "darwin/amd64":
		return []string{fmt.Sprintf("mihomo-darwin-amd64-compatible-%s.gz", v)}, nil
	case "linux/amd64":
		return []string{fmt.Sprintf("mihomo-linux-amd64-compatible-%s.gz", v)}, nil
	case "linux/arm64":
		return []string{fmt.Sprintf("mihomo-linux-arm64-%s.gz", v)}, nil
	}
	return nil, fmt.Errorf("unsupported platform %s", platform)
}
