package core

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	maxBinarySize = 300 << 20 // generous cap for the xray executable
	maxDataSize   = 100 << 20 // geoip.dat / geosite.dat
)

// extractWhitelisted copies the whitelisted root-level members of zipPath into
// dest. Names are only looked up in src.Files, never joined into a path, which
// makes path traversal ("zip slip"), symlink and device-file tricks impossible.
func extractWhitelisted(zipPath, dest string, src Source) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		w, ok := src.Files[f.Name]
		if !ok || f.FileInfo().IsDir() || f.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if f.UncompressedSize64 > w.Max {
			return fmt.Errorf("archive member %s is too large", f.Name)
		}
		if err := copyMember(f, filepath.Join(dest, f.Name), w.Mode, w.Max); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(dest, src.Binary)); err != nil {
		return fmt.Errorf("archive does not contain a %s binary", src.Binary)
	}
	return nil
}

func copyMember(f *zip.File, target string, mode os.FileMode, max uint64) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open %s: %w", f.Name, err)
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", f.Name, err)
	}
	n, err := io.Copy(out, io.LimitReader(rc, int64(max)+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("extract %s: %w", f.Name, err)
	}
	if uint64(n) > max {
		return fmt.Errorf("archive member %s exceeds its size limit", f.Name)
	}
	return os.Chmod(target, mode)
}
