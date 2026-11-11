package service

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/store"
)

func newTestServiceWithSingBox(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	xmgr, err := core.NewManager(filepath.Join(dir, "engines", engine.NameXray), core.XraySource)
	if err != nil {
		t.Fatal(err)
	}
	smgr, err := core.NewManager(filepath.Join(dir, "engines", engine.NameSingBox), core.SingBoxSource)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{
		Store: st,
		Engines: []EngineSlot{
			{Engine: engine.Xray{}, Manager: xmgr},
			{Engine: &engine.SingBox{}, Manager: smgr},
		},
		Runner: engine.NewRunner(""), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func makeOVPNZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const zipOVPN = `client
dev tun
proto udp
remote v.example 1194
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
`

func TestPreviewZipResolvesExternalFiles(t *testing.T) {
	svc := newTestServiceWithSingBox(t)
	data := makeOVPNZip(t, map[string]string{
		"client.ovpn": zipOVPN,
		"ca.crt":      "ZIP-CA",
		"client.crt":  "ZIP-CERT",
		"client.key":  "ZIP-KEY",
	})
	p := svc.PreviewZip(data)
	if p.Ready != 1 {
		t.Fatalf("ready = %d, skipped = %d items = %+v", p.Ready, p.Skipped, p.Items)
	}
}

func TestImportZipAddsNodes(t *testing.T) {
	svc := newTestService(t)
	data := makeOVPNZip(t, map[string]string{
		"a.ovpn":     zipOVPN,
		"ca.crt":     "ZIP-CA",
		"client.crt": "ZIP-CERT",
		"client.key": "ZIP-KEY",
	})
	res, err := svc.ImportZip(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 1 {
		t.Fatalf("added = %d errs = %v", res.Added, res.Errors)
	}
	nodes := svc.Nodes()
	if len(nodes) != 1 || nodes[0].Protocol != "openvpn" {
		t.Fatalf("nodes = %+v", nodes)
	}
	if nodes[0].Profile == nil {
		t.Fatal("expected stored profile")
	}
}

func TestImportZipMissingFileReportsError(t *testing.T) {
	svc := newTestService(t)
	data := makeOVPNZip(t, map[string]string{"a.ovpn": zipOVPN})
	res, err := svc.ImportZip(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added != 0 || len(res.Errors) == 0 {
		t.Fatalf("expected error, got %+v", res)
	}
}
