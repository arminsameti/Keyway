package core

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractTarGz copies whitelisted members of a .tar.gz into dest. sing-box
// archives keep everything in one top-level folder ("sing-box-1.14.4-darwin-arm64/"),
// so a member may sit at the root or exactly one level down. Only regular files
// are taken; the destination name always comes from src.Files.
func extractTarGz(path, dest string, src Source) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	done := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		name := strings.TrimPrefix(h.Name, "./")
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		w, ok := src.Files[name]
		if !ok || h.Typeflag != tar.TypeReg || done[name] {
			continue
		}
		if h.Size < 0 || uint64(h.Size) > w.Max {
			return fmt.Errorf("archive member %s is too large", name)
		}
		if err := writeMember(tr, filepath.Join(dest, name), name, w); err != nil {
			return err
		}
		done[name] = true
	}
	if !done[src.Binary] {
		return fmt.Errorf("archive does not contain a %s binary", src.Binary)
	}
	return nil
}

func writeMember(r io.Reader, target, name string, w Member) error {
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, w.Mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	n, err := io.Copy(out, io.LimitReader(r, int64(w.Max)+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("extract %s: %w", name, err)
	}
	if uint64(n) > w.Max {
		return fmt.Errorf("archive member %s exceeds its size limit", name)
	}
	return os.Chmod(target, w.Mode)
}
