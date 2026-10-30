package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/models"
	"xray-friendly/internal/store"
	"xray-friendly/internal/sysproxy"
)

// fake sing-box: reports QUIC/uTLS/WireGuard tags (no NaiveProxy), passes
// "check", and otherwise runs like a proxy.
const fakeSingBox = `#!/bin/sh
case "$1" in
  version) printf 'sing-box version 1.14.4\n\nTags: with_quic,with_utls,with_wireguard,with_openvpn\n'; exit 0;;
  check) [ -f "$(dirname "$0")/reject" ] && { echo "bad config: simulated" >&2; exit 1; }; exit 0;;
esac
echo "fake sing-box started"
[ -f "$(dirname "$0")/crash" ] && { sleep 2.4; exit 1; }
exec sleep 30
`

type twoEnv struct {
	*env
	sbDir string
}

func newTwoEngines(t *testing.T, withSingBox bool) *twoEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	xm, _ := core.NewManager(filepath.Join(dir, "engines", "xray"), core.XraySource)
	sm, _ := core.NewManager(filepath.Join(dir, "engines", "sing-box"), core.SingBoxSource)
	xdir := filepath.Join(dir, "engines", "xray", "v1.0.0")
	sbDir := filepath.Join(dir, "engines", "sing-box", "v1.14.4")
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(xdir, "xray"), fakeXray, 0o755)
	if withSingBox {
		write(filepath.Join(sbDir, "sing-box"), fakeSingBox, 0o755)
	}
	// default routing needs these rule sets; present files are never re-downloaded
	for _, n := range []string{"geosite-category-ads-all", "geosite-cn", "geosite-private"} {
		write(sm.RuleSetPath(n), "srs", 0o644)
	}
	e := &env{st: st, sys: &fakeSys{}, dir: dir, core: xdir}
	runner := engine.NewRunner(filepath.Join(dir, "xray.pid"))
	svc, err := New(Config{
		Store: st, EnginesDir: filepath.Join(dir, "engines"), Runner: runner, Sys: sysproxy.NewWithRunner("darwin", e.sys.run),
		Engines: []EngineSlot{
			{Engine: engine.Xray{}, Manager: xm},
			{Engine: &engine.SingBox{RuleSetPath: sm.RuleSetPath}, Manager: sm},
		},
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	t.Cleanup(func() { _ = runner.Stop() })
	return &twoEnv{env: e, sbDir: sbDir}
}

func (e *twoEnv) connectTo(t *testing.T, raw string) (Status, string, error) {
	t.Helper()
	n := e.addNode(t, raw)
	if err := e.svc.SetActive(n.ID); err != nil {
		t.Fatal(err)
	}
	_, err := e.svc.Connect(context.Background())
	cfg, _ := os.ReadFile(filepath.Join(e.dir, "config.json"))
	return e.svc.Status(), string(cfg), err
}

func TestConnectRunsTheRightEngine(t *testing.T) {
	e := newTwoEngines(t, true)
	st, cfg, err := e.connectTo(t, "tuic://u:p@t.example.net:443?sni=t.example.net&congestion_control=bbr#TUIC")
	if err != nil {
		t.Fatal(err)
	}
	if st.Engine != "sing-box" || st.EngineVersion != "v1.14.4" || !st.Running || st.Protocol != "TUIC" {
		t.Fatalf("status: %+v", st)
	}
	rules := filepath.Join(e.dir, "engines", "sing-box", "rules", "geosite-cn.srs")
	if !strings.Contains(cfg, `"type": "tuic"`) || !strings.Contains(cfg, rules) {
		t.Fatalf("sing-box config: %s", cfg)
	}

	// a server both engines run follows the preference
	st, _, err = e.connectTo(t, "trojan://p@tr.example.net:443?sni=tr.example.net#T")
	if err != nil || st.Engine != "xray" {
		t.Fatalf("default preference: %+v %v", st, err)
	}
	s := e.st.Get().Settings
	s.EnginePreference = "sing-box"
	if _, err := e.svc.UpdateSettings(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Connect(context.Background()); err != nil || e.svc.Status().Engine != "sing-box" {
		t.Fatalf("preferred sing-box: %+v %v", e.svc.Status(), err)
	}
}

func TestBuildTagsLimitWhatSingBoxRuns(t *testing.T) {
	e := newTwoEngines(t, true)
	n := e.addNode(t, "naive+https://u:p@n.example.net:443#Naive")
	var v NodeView
	for _, nv := range e.svc.Nodes() {
		if nv.ID == n.ID {
			v = nv
		}
	}
	if v.Engine != "" || !strings.Contains(v.EngineReason, "no NaiveProxy support") {
		t.Fatalf("naive view: %+v", v)
	}
	_ = e.svc.SetActive(n.ID)
	var ve *models.ValidationError
	if _, err := e.svc.Connect(context.Background()); !errors.As(err, &ve) {
		t.Fatalf("connect: %v", err)
	}
}

func TestMissingSingBoxIsReported(t *testing.T) {
	e := newTwoEngines(t, false)
	_, _, err := e.connectTo(t, "tuic://u:p@t.example.net:443#TUIC")
	var ni *engine.NotInstalledError
	if !errors.Is(err, core.ErrNotInstalled) || !errors.As(err, &ni) || ni.Engine.Name() != "sing-box" {
		t.Fatalf("want sing-box not installed, got %v", err)
	}
	// insecure TLS is sing-box only now; Xray must not be picked for it
	_, _, err = e.connectTo(t, "trojan://p@tr.example.net:443?allowInsecure=1#Insecure")
	if !errors.As(err, &ni) || ni.Engine.Name() != "sing-box" {
		t.Fatalf("insecure trojan: %v", err)
	}
}
