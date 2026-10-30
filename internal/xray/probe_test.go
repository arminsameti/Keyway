package xray

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-xray")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTestExplainsRemovedAllowInsecure(t *testing.T) {
	bin := script(t, `echo "A unified platform for anti-censorship."
echo 'Failed to start: main: failed to load config files > common/errors: The feature "allowInsecure" has been removed and migrated to "pinnedPeerCertSha256". Please update your config(s)'
exit 23`)
	err := Test(context.Background(), bin, "/dev/null", os.TempDir())
	if !errors.Is(err, ErrInsecureUnsupported) {
		t.Fatalf("want ErrInsecureUnsupported, got %v", err)
	}
}

func TestTestErrorStartsAtLineBoundary(t *testing.T) {
	bin := script(t, `i=0; while [ $i -lt 40 ]; do echo "noise line number $i padding padding"; i=$((i+1)); done
echo "Failed to start: real cause"
exit 1`)
	err := Test(context.Background(), bin, "/dev/null", os.TempDir())
	if err == nil || !strings.HasPrefix(err.Error(), "noise line number") || !strings.HasSuffix(err.Error(), "real cause") {
		t.Fatalf("truncated mid-line or lost the cause: %q", err)
	}
}
