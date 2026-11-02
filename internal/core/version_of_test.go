package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Mihomo binary given the argument "version" does not print a version: it
// takes it for nothing and starts a proxy in its default directory. It must be
// asked with -v, and nothing else.
func TestVersionOfAsksMihomoWithDashV(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "args")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nif [ \"$1\" = \"-v\" ]; then echo 'Mihomo Meta v1.19.33 darwin arm64'; fi\n"
	bin := filepath.Join(dir, "mihomo")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := VersionOf(bin); got != "Mihomo Meta v1.19.33 darwin arm64" {
		t.Fatalf("version = %q", got)
	}
	b, _ := os.ReadFile(log)
	if strings.TrimSpace(string(b)) != "-v" {
		t.Fatalf("mihomo was run with %q", b)
	}
}

func TestVersionOfKeepsAskingOtherEnginesWithVersion(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "xray")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo 'Xray 1.2.3'; fi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := VersionOf(bin); got != "Xray 1.2.3" {
		t.Fatalf("version = %q", got)
	}
}
