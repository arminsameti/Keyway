package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/link"
	"xray-friendly/internal/models"
	"xray-friendly/internal/store"
	"xray-friendly/internal/sysproxy"
)

// ---- fakes ----

type fakeSys struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeSys) run(_ context.Context, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	joined := strings.Join(args, " ")
	f.calls = append(f.calls, name+" "+joined)
	switch {
	case joined == "-listallnetworkservices":
		return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n", nil
	case joined == "-listnetworkserviceorder":
		return "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n", nil
	case name == "route":
		return "interface: en0\n", nil
	case strings.HasPrefix(joined, "-get"):
		return "Enabled: No", nil
	}
	return "", nil
}

func (f *fakeSys) count(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// fake xray: `-test` succeeds unless a file named "reject" sits next to the binary;
// otherwise it behaves like a long-running proxy (or crashes if "crash" exists).
const fakeXray = `#!/bin/sh
dir=$(dirname "$0")
for a in "$@"; do
  if [ "$a" = "-test" ]; then
    [ -f "$dir/reject" ] && { echo "bad config: simulated" >&2; exit 1; }
    exit 0
  fi
done
echo "fake xray started"
[ -f "$dir/crash" ] && { sleep 1.2; exit 1; }
exec sleep 30
`

type env struct {
	svc  *Service
	st   *store.Store
	sys  *fakeSys
	dir  string
	core string // dir of the fake core
}

func newEnv(t *testing.T, withCore bool) *env {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cores, err := core.NewManager(filepath.Join(dir, "engines", "xray"), core.XraySource)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, sys: &fakeSys{}, dir: dir, core: filepath.Join(dir, "engines", "xray", "v1.0.0")}
	if withCore {
		if err := os.MkdirAll(e.core, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(e.core, "xray"), []byte(fakeXray), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	runner := engine.NewRunner(filepath.Join(dir, "xray.pid"))
	svc, err := New(Config{
		Store: st, Engines: []EngineSlot{{Engine: engine.Xray{}, Manager: cores}}, EnginesDir: filepath.Join(dir, "engines"),
		Runner: runner, Sys: sysproxy.NewWithRunner("darwin", e.sys.run),
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})), Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	t.Cleanup(func() { _ = runner.Stop() })
	return e
}

func (e *env) addNode(t *testing.T, raw string) models.Node {
	t.Helper()
	res, err := link.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Update(func(d *models.AppData) error {
		mergeNodes(d, []models.Node{res.Node}, "")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return res.Node
}

func vless(host string, port int, name string) string {
	return fmt.Sprintf("vless://u@%s:%d?security=none&type=tcp#%s", host, port, name)
}

// ---- lifecycle ----

func TestConnectDisconnect(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()

	if _, err := e.svc.Connect(ctx); !errors.Is(err, ErrNoActiveNode) {
		t.Fatalf("want ErrNoActiveNode, got %v", err)
	}
	n := e.addNode(t, vless("1.2.3.4", 443, "A"))
	if err := e.svc.SetActive(n.ID); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.Connect(ctx)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !e.svc.State().Running {
		t.Fatal("not running after connect")
	}
	st, err := os.Stat(res.Config)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config perms: %v %v", st, err)
	}
	if got := e.st.Get().Engines["xray"]; got != "v1.0.0" {
		t.Fatalf("active core not remembered: %q", got)
	}
	if err := e.svc.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if e.svc.State().Running {
		t.Fatal("still running after disconnect")
	}
}

func TestConnectWithoutCore(t *testing.T) {
	e := newEnv(t, false)
	n := e.addNode(t, vless("1.2.3.4", 443, "A"))
	_ = e.svc.SetActive(n.ID)
	if _, err := e.svc.Connect(context.Background()); !errors.Is(err, core.ErrNotInstalled) {
		t.Fatalf("want ErrNotInstalled, got %v", err)
	}
}

// A rejected config must not take down a working connection.
func TestRejectedConfigKeepsRunningConnection(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	a := e.addNode(t, vless("1.2.3.4", 443, "A"))
	b := e.addNode(t, vless("5.6.7.8", 443, "B"))
	_ = e.svc.SetActive(a.ID)
	if _, err := e.svc.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	pid := e.svc.Status().PID

	if err := os.WriteFile(filepath.Join(e.core, "reject"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = e.svc.SetActive(b.ID)
	_, err := e.svc.Connect(ctx)
	if err == nil || !strings.Contains(err.Error(), "simulated") {
		t.Fatalf("want rejection, got %v", err)
	}
	if !e.svc.State().Running || e.svc.Status().PID != pid {
		t.Fatal("the working instance was disturbed by a bad config")
	}
	_ = e.svc.Disconnect(ctx)
}

func TestSystemProxyFollowsConnection(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	s := e.st.Get().Settings
	s.AutoSystemProxy = true
	if _, err := e.svc.UpdateSettings(ctx, s); err != nil {
		t.Fatal(err)
	}
	n := e.addNode(t, vless("1.2.3.4", 443, "A"))
	_ = e.svc.SetActive(n.ID)
	if _, err := e.svc.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if e.sys.count("-setsocksfirewallproxystate Wi-Fi on") != 1 || e.sys.count("-setsecurewebproxystate Wi-Fi on") != 1 {
		t.Fatalf("system proxy not enabled: %v", e.sys.calls)
	}
	if _, err := os.Stat(filepath.Join(e.dir, sysStateFile)); err != nil {
		t.Fatal("state file for crash recovery missing")
	}
	if err := e.svc.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if e.sys.count("-setsocksfirewallproxystate Wi-Fi off") == 0 {
		t.Fatal("system proxy not restored on disconnect")
	}
	if _, err := os.Stat(filepath.Join(e.dir, sysStateFile)); err == nil {
		t.Fatal("state file should be removed")
	}
}

func TestCrashClearsSystemProxy(t *testing.T) {
	e := newEnv(t, true)
	if err := os.WriteFile(filepath.Join(e.core, "crash"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := e.st.Get().Settings
	s.AutoSystemProxy = true
	_, _ = e.svc.UpdateSettings(ctx, s)
	n := e.addNode(t, vless("1.2.3.4", 443, "A"))
	_ = e.svc.SetActive(n.ID)
	if _, err := e.svc.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.sys.count("-setsocksfirewallproxystate Wi-Fi off") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("system proxy still pointing at a dead xray after a crash")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRecoverRestoresLeftoverSystemProxy(t *testing.T) {
	e := newEnv(t, true)
	_ = os.WriteFile(filepath.Join(e.dir, sysStateFile), []byte(`["Wi-Fi"]`), 0o600)
	e.svc.Recover(context.Background())
	if e.sys.count("-setsocksfirewallproxystate Wi-Fi off") == 0 {
		t.Fatal("leftover proxy not cleared")
	}
	if _, err := os.Stat(filepath.Join(e.dir, sysStateFile)); err == nil {
		t.Fatal("state file should be gone")
	}
}

func TestProxyPortsSkipAuthenticatedInbounds(t *testing.T) {
	s := models.DefaultSettings()
	s.Inbounds[0].Username, s.Inbounds[0].Password = "u", "p" // first socks needs auth
	socks, http, err := proxyPorts(s)
	if err != nil || socks != 10810 || http != 10809 {
		t.Fatalf("socks=%d http=%d err=%v", socks, http, err)
	}
	for i := range s.Inbounds {
		s.Inbounds[i].Enabled = false
	}
	if _, _, err := proxyPorts(s); err == nil {
		t.Fatal("expected error without usable socks inbound")
	}
}

// ---- settings ----

func TestUpdateSettings(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	s := e.st.Get().Settings

	bad := s.Clone()
	bad.AllowLAN = true
	var ve *models.ValidationError
	if _, err := e.svc.UpdateSettings(ctx, bad); !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	if e.st.Get().Settings.AllowLAN {
		t.Fatal("invalid settings were persisted")
	}

	n := e.addNode(t, vless("1.2.3.4", 443, "A"))
	_ = e.svc.SetActive(n.ID)
	if _, err := e.svc.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer e.svc.Disconnect(ctx)

	same := s.Clone()
	same.AutoPick = true // does not influence the xray config
	res, err := e.svc.UpdateSettings(ctx, same)
	if err != nil || res.ReconnectRequired {
		t.Fatalf("autoPick change: %+v %v", res, err)
	}
	changed := same.Clone()
	changed.RoutingMode = "global"
	res, err = e.svc.UpdateSettings(ctx, changed)
	if err != nil || !res.ReconnectRequired {
		t.Fatalf("routing change should require reconnect: %+v %v", res, err)
	}
	changed.APIPort = 23456
	res, _ = e.svc.UpdateSettings(ctx, changed)
	if !res.RestartRequired {
		t.Fatal("API port change should require restart")
	}
}

// ---- latency / selection ----

func TestChooseBestAndShouldSwitch(t *testing.T) {
	nodes := []models.Node{{ID: "a"}, {ID: "b"}, {ID: "c"}, {ID: "d"}}
	lat := map[string]int64{"a": models.LatencyFailed, "b": 120, "c": 80, "d": models.LatencyNA}
	if id, ms := chooseBest(nodes, lat); id != "c" || ms != 80 {
		t.Fatalf("best = %s %d", id, ms)
	}
	if id, _ := chooseBest(nodes, map[string]int64{"a": -2}); id != "" {
		t.Fatal("no reachable node should give empty")
	}
	cases := []struct {
		cur   int64
		known bool
		best  int64
		want  bool
	}{
		{-2, true, 300, true},   // current dead
		{0, false, 300, true},   // current unknown
		{200, true, 190, false}, // marginal gain: stay (no flapping)
		{200, true, 160, false}, // 20% faster but under threshold
		{200, true, 140, true},  // 30% and 60ms faster
		{100, true, 60, false},  // 40% faster but only 40ms: stay
		{400, true, 100, true},
	}
	for _, c := range cases {
		if got := shouldSwitch(c.cur, c.known, c.best); got != c.want {
			t.Errorf("shouldSwitch(%d,%v,%d)=%v want %v", c.cur, c.known, c.best, got, c.want)
		}
	}
}

func listener(t *testing.T) (port int, closeFn func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func TestPickFastestTCP(t *testing.T) {
	e := newEnv(t, false) // no core: auto mode falls back to tcp
	ctx := context.Background()
	p1, c1 := listener(t)
	defer c1()
	dead, cd := listener(t)
	cd() // closed port
	a := e.addNode(t, vless("127.0.0.1", dead, "dead"))
	b := e.addNode(t, vless("127.0.0.1", p1, "alive"))
	h := e.addNode(t, "hy2://pw@127.0.0.1:9?sni=x")

	res, err := e.svc.PickFastest(ctx, false, ModeAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.ID != b.ID || res.Mode != ModeTCP {
		t.Fatalf("picked %s (%s) mode=%s", res.ID, res.Name, res.Mode)
	}
	d := e.st.Get()
	if d.ActiveNodeID != b.ID {
		t.Fatal("active node not updated")
	}
	byID := map[string]int64{}
	for _, n := range d.Nodes {
		byID[n.ID] = n.LatencyMs
	}
	if byID[a.ID] != models.LatencyFailed || byID[h.ID] != models.LatencyNA || byID[b.ID] < 0 {
		t.Fatalf("stored latencies: %v", byID)
	}

	// everything dead -> ErrAllFailed but latencies still returned
	if _, err := e.svc.DeleteNodes(b.ID, h.ID); err != nil {
		t.Fatal(err)
	}
	res, err = e.svc.PickFastest(ctx, false, ModeTCP)
	if !errors.Is(err, ErrAllFailed) || res.Latency[a.ID] != models.LatencyFailed {
		t.Fatalf("err=%v res=%+v", err, res)
	}
}

func TestProxyModeNeedsCore(t *testing.T) {
	e := newEnv(t, false)
	n := e.addNode(t, vless("127.0.0.1", 1, "x"))
	_, _, err := e.svc.Measure(context.Background(), []models.Node{n}, ModeProxy)
	if !errors.Is(err, core.ErrNotInstalled) {
		t.Fatalf("got %v", err)
	}
	if _, _, err := e.svc.Measure(context.Background(), nil, "bogus"); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}

// ---- nodes / subscriptions ----

func TestDeleteActiveNodeClearsSelection(t *testing.T) {
	e := newEnv(t, false)
	n := e.addNode(t, vless("1.1.1.1", 1, "a"))
	_ = e.svc.SetActive(n.ID)
	if c, _ := e.svc.DeleteNodes(n.ID); c != 1 {
		t.Fatal("not removed")
	}
	if e.st.Get().ActiveNodeID != "" {
		t.Fatal("selection should be cleared")
	}
	if err := e.svc.SetActive("nope"); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("got %v", err)
	}
}

func subBody(links ...string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}

func TestSubscriptionLifecycle(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	body := subBody(vless("1.1.1.1", 1, "one"), vless("2.2.2.2", 2, "two"))
	var mu sync.Mutex
	e.svc.fetch = func(context.Context, string) (string, error) { mu.Lock(); defer mu.Unlock(); return body, nil }

	// a pasted https URL becomes a subscription, not a node
	res, err := e.svc.Import(ctx, "https://sub.example.com/feed\n"+vless("9.9.9.9", 9, "manual"), "")
	if err != nil || res.Added != 3 || len(res.Errors) != 0 {
		t.Fatalf("import: %+v %v", res, err)
	}
	d := e.st.Get()
	if len(d.Subscriptions) != 1 || d.Subscriptions[0].NodeCount != 2 || len(d.Nodes) != 3 {
		t.Fatalf("state: subs=%+v nodes=%d", d.Subscriptions, len(d.Nodes))
	}
	subID := d.Subscriptions[0].ID

	// the same URL again must not duplicate the subscription
	if _, _, _, err := e.svc.AddSubscription(ctx, "x", "https://sub.example.com/feed"); err != nil {
		t.Fatal(err)
	}
	if len(e.st.Get().Subscriptions) != 1 {
		t.Fatal("duplicate subscription created")
	}

	// give "one" a latency and make it active; server drops "two", adds "three", renames "one"
	var oneID string
	for _, n := range d.Nodes {
		if n.Name == "one" {
			oneID = n.ID
		}
	}
	e.svc.applyLatencies(map[string]int64{oneID: 77})
	_ = e.svc.SetActive(oneID)
	mu.Lock()
	body = subBody(vless("1.1.1.1", 1, "one-renamed"), vless("3.3.3.3", 3, "three"))
	mu.Unlock()
	added, removed, _, err := e.svc.RefreshSubscription(ctx, subID)
	if err != nil || added != 1 || removed != 1 {
		t.Fatalf("refresh: +%d -%d %v", added, removed, err)
	}
	d = e.st.Get()
	names := map[string]models.Node{}
	for _, n := range d.Nodes {
		names[n.Name] = n
	}
	if _, ok := names["two"]; ok {
		t.Fatal("vanished node kept")
	}
	if r, ok := names["one-renamed"]; !ok || r.LatencyMs != 77 || r.ID != oneID {
		t.Fatalf("surviving node lost identity/latency: %+v", names)
	}
	if _, ok := names["manual"]; !ok {
		t.Fatal("manual node must survive refresh")
	}
	if d.ActiveNodeID != oneID {
		t.Fatal("active node should survive a rename")
	}

	if err := e.svc.RemoveSubscription(subID); err != nil {
		t.Fatal(err)
	}
	d = e.st.Get()
	if len(d.Subscriptions) != 0 || len(d.Nodes) != 1 || d.Nodes[0].Name != "manual" {
		t.Fatalf("after remove: %+v", d.Nodes)
	}
	if d.ActiveNodeID != "" {
		t.Fatal("active node from removed subscription must be cleared")
	}
}

func TestSubscriptionFailureIsRecordedAndKeepsNodes(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	e.svc.fetch = func(context.Context, string) (string, error) { return subBody(vless("1.1.1.1", 1, "one")), nil }
	sub, _, _, err := e.svc.AddSubscription(ctx, "s", "https://sub.example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	e.svc.fetch = func(context.Context, string) (string, error) { return "", errors.New("server down") }
	if _, _, _, err := e.svc.RefreshSubscription(ctx, sub.ID); err == nil {
		t.Fatal("expected error")
	}
	d := e.st.Get()
	if len(d.Nodes) != 1 || !strings.Contains(d.Subscriptions[0].LastError, "server down") {
		t.Fatalf("nodes=%d sub=%+v", len(d.Nodes), d.Subscriptions[0])
	}
	// garbage body must not wipe the node list either
	e.svc.fetch = func(context.Context, string) (string, error) { return "<html>login</html>", nil }
	if _, _, _, err := e.svc.RefreshSubscription(ctx, sub.ID); err == nil {
		t.Fatal("body without nodes must be an error")
	}
	if len(e.st.Get().Nodes) != 1 {
		t.Fatal("nodes wiped by a bad subscription body")
	}
}

func TestMigrateNodeIDs(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	raw := vless("1.2.3.4", 443, "old")
	_, _ = st.Update(func(d *models.AppData) error {
		d.Version = 1
		d.Nodes = []models.Node{{ID: "legacy-sha1-id", Name: "old", RawLink: raw}, {ID: "dup", Name: "dup", RawLink: raw + "#other"}}
		d.ActiveNodeID = "legacy-sha1-id"
		return nil
	})
	newBare(t, st, dir)
	d := st.Get()
	want := link.NodeID(raw)
	if len(d.Nodes) != 1 || d.Nodes[0].ID != want || d.ActiveNodeID != want || d.Version != models.SchemaVersion {
		t.Fatalf("migration: %+v active=%s", d.Nodes, d.ActiveNodeID)
	}
}

func newBare(t *testing.T, st *store.Store, dir string) *Service {
	t.Helper()
	cores, _ := core.NewManager(filepath.Join(dir, "engines", "xray"), core.XraySource)
	svc, err := New(Config{Store: st, Engines: []EngineSlot{{Engine: engine.Xray{}, Manager: cores}},
		Runner: engine.NewRunner(""), Sys: sysproxy.New(), Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestMigrateV2ToV3(t *testing.T) {
	dir := t.TempDir()
	st, _ := store.Open(dir)
	_, _ = st.Update(func(d *models.AppData) error {
		d.Version = 2
		d.ActiveCore = "v25.1.1"
		d.Settings.AutoDownloadEngines = false // how a v2 document decodes
		d.Settings.LatencyMethod = ""
		return nil
	})
	newBare(t, st, dir)
	d := st.Get()
	if d.Version != 3 || d.Engines["xray"] != "v25.1.1" || d.ActiveCore != "" {
		t.Fatalf("engines: %+v version %d active %q", d.Engines, d.Version, d.ActiveCore)
	}
	if !d.Settings.AutoDownloadEngines || d.Settings.LatencyMethod != "real" || d.Settings.EnginePreference != "xray" {
		t.Fatalf("settings: %+v", d.Settings)
	}
	// idempotent: a second start changes nothing
	before := st.Get()
	newBare(t, st, dir)
	if after := st.Get(); after.Engines["xray"] != before.Engines["xray"] || after.Version != before.Version {
		t.Fatal("migration is not idempotent")
	}
}

// ---- SSRF guard ----

func TestSafeFetchRefusesLocalTargets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "secret") }))
	defer srv.Close()
	if _, err := safeFetch(context.Background(), srv.URL); err == nil {
		t.Fatal("loopback target must be refused")
	}
	for _, u := range []string{"file:///etc/passwd", "ftp://x.com/a", "gopher://x", "http://", "not a url"} {
		if _, err := safeFetch(context.Background(), u); err == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fd00::1", "0.0.0.0", "224.0.0.1"} {
		if !blockedIP(net.ParseIP(ip)) {
			t.Errorf("%s must be blocked", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700::1111"} {
		if blockedIP(net.ParseIP(ip)) {
			t.Errorf("%s must be allowed", ip)
		}
	}
}

func TestDownloadCoreValidatesVersion(t *testing.T) {
	e := newEnv(t, false)
	var ve *models.ValidationError
	if _, err := e.svc.DownloadCore(context.Background(), "../../x"); !errors.As(err, &ve) {
		t.Fatalf("got %v", err)
	}
	if _, err := e.svc.UseCore("v9.9.9"); !errors.As(err, &ve) {
		t.Fatalf("not-installed core: %v", err)
	}
}

func TestClashSubscription(t *testing.T) {
	e := newEnv(t, false)
	body := `proxies:
  - {name: "🇳🇱 Amsterdam", type: trojan, server: ams.example.net, port: 443, password: pw, sni: ams.example.net}
  - {name: TUIC, type: tuic, server: t.example.net, port: 443, uuid: u, password: p}
  - {name: Old, type: ssr, server: r.example.net, port: 1}
`
	e.svc.fetch = func(context.Context, string) (string, error) { return body, nil }
	sub, added, errs, err := e.svc.AddSubscription(context.Background(), "", "https://sub.example.com/clash")
	if err != nil || added != 2 {
		t.Fatalf("added=%d err=%v errs=%v", added, err, errs)
	}
	if sub.Format != "clash" || sub.NodeCount != 2 {
		t.Fatalf("sub: %+v", sub)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "Old (ssr)") || !strings.Contains(errs[0], "retired") {
		t.Fatalf("errs: %v", errs)
	}
	views := map[string]NodeView{}
	for _, v := range e.svc.Nodes() {
		views[v.DisplayName] = v
	}
	if v := views["Amsterdam"]; v.CountryCode != "NL" || v.Engine != "xray" || v.Source != sub.ID {
		t.Fatalf("trojan view: %+v", v)
	}
	// TUIC needs sing-box, which this build does not have yet: the reason is shown
	if v := views["TUIC"]; v.Engine != "" || !strings.Contains(v.EngineReason, "sing-box") || !v.UDP {
		t.Fatalf("tuic view: %+v", v)
	}
}
