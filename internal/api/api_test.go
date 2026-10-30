package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/service"
	"xray-friendly/internal/store"
	"xray-friendly/internal/sysproxy"
)

const (
	testToken = "s3cret-token"
	testPort  = 12345
	vlessLink = "vless://u@1.2.3.4:443?security=none&type=tcp#Node%20A"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cores, _ := core.NewManager(filepath.Join(dir, "engines", "xray"), core.XraySource)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := service.New(service.Config{
		Store: st, Engines: []service.EngineSlot{{Engine: engine.Xray{}, Manager: cores}},
		Runner: engine.NewRunner(""), Sys: sysproxy.New(), Logger: log, Dir: dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(svc, Config{Token: testToken, Port: testPort, Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	return srv.Handler()
}

type opt func(*http.Request)

func withHeader(k, v string) opt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withHost(h string) opt      { return func(r *http.Request) { r.Host = h } }
func noToken() opt               { return func(r *http.Request) { r.Header.Del(TokenHeader) } }

func do(h http.Handler, method, path string, body any, opts ...opt) *httptest.ResponseRecorder {
	var rd io.Reader
	if s, ok := body.(string); ok {
		rd = strings.NewReader(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r := httptest.NewRequest(method, path, rd)
	r.Host = "127.0.0.1:12345"
	r.Header.Set(TokenHeader, testToken)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not JSON: %q", w.Body.String())
	}
	return m
}

func TestNoUIAndStrictHeaders(t *testing.T) {
	h := newServer(t)
	for _, path := range []string{"/", "/app.js", "/index.html"} {
		if w := do(h, "GET", path, nil); w.Code != http.StatusNotFound {
			t.Errorf("%s -> %d: the web UI was removed", path, w.Code)
		}
	}
	w := do(h, "GET", "/api/status", nil)
	if csp := w.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Fatalf("csp = %q", csp)
	}
	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if w.Header().Get(hdr) == "" {
			t.Errorf("missing %s", hdr)
		}
	}
}

func TestNewRoutesAreGuarded(t *testing.T) {
	h := newServer(t)
	routes := []struct{ method, path string }{
		{"POST", "/api/import/preview"}, {"POST", "/api/nodes"}, {"PUT", "/api/nodes/x"}, {"POST", "/api/nodes/test"},
		{"GET", "/api/engines"}, {"GET", "/api/engines/xray/releases"}, {"POST", "/api/engines/xray/download"},
		{"POST", "/api/engines/xray/use"}, {"POST", "/api/engines/xray/check"},
		{"POST", "/api/links/parse"}, {"POST", "/api/chains/plan"}, {"GET", "/api/nodes/x/profile"}, {"GET", "/api/jobs"}, {"GET", "/api/jobs/1"},
	}
	for _, rt := range routes {
		if w := do(h, rt.method, rt.path, "{}", noToken()); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without token -> %d", rt.method, rt.path, w.Code)
		}
		if w := do(h, rt.method, rt.path, "{}", withHost("evil.example.com:12345")); w.Code != http.StatusForbidden {
			t.Errorf("%s %s with foreign Host -> %d", rt.method, rt.path, w.Code)
		}
		if w := do(h, rt.method, rt.path, "{}", withHeader("Origin", "http://evil.example.com")); w.Code != http.StatusForbidden {
			t.Errorf("%s %s cross-origin -> %d", rt.method, rt.path, w.Code)
		}
	}
}

func TestImportPreviewSavesNothing(t *testing.T) {
	h := newServer(t)
	text := vlessLink + "\nhttps://sub.example.net/TOKEN\nssr://abc\nhello"
	w := do(h, "POST", "/api/import/preview", map[string]string{"text": text})
	m := decodeBody(t, w)
	if w.Code != 200 || m["ready"].(float64) != 1 || m["subscriptions"].(float64) != 1 || m["skipped"].(float64) != 2 {
		t.Fatalf("preview: %d %v", w.Code, m)
	}
	items := m["items"].([]any)
	first := items[0].(map[string]any)
	if first["status"] != "ready" || first["name"] != "Node A" || first["protocol"] != "VLESS" || first["engine"] != "xray" {
		t.Fatalf("ready item: %v", first)
	}
	if sub := items[1].(map[string]any); sub["status"] != "subscription" || sub["name"] != "sub.example.net" {
		t.Fatalf("subscription item: %v", sub)
	}
	if ssr := items[2].(map[string]any); ssr["reason"] != "ShadowsocksR is retired — skipped" || ssr["name"] != "Line 3 · ssr://" {
		t.Fatalf("ssr item: %v", ssr)
	}
	state := decodeBody(t, do(h, "GET", "/api/state", nil))
	if len(state["nodes"].([]any)) != 0 || len(state["subscriptions"].([]any)) != 0 {
		t.Fatal("preview must not save anything")
	}
}

func TestCreateEditNode(t *testing.T) {
	h := newServer(t)
	// manual HTTP proxy: no share link, stored as a profile
	w := do(h, "POST", "/api/nodes", map[string]any{"name": "Office proxy", "profile": map[string]any{
		"protocol": "http", "server": "proxy.example.com", "port": 3128, "username": "u", "password": "p"}})
	m := decodeBody(t, w)
	if w.Code != 200 {
		t.Fatalf("create: %d %v", w.Code, m)
	}
	n := m["node"].(map[string]any)
	if n["hasLink"] != false || n["protocolName"] != "HTTP" || n["engine"] != "xray" || n["transport"] != "TCP" {
		t.Fatalf("node: %v", n)
	}
	id := n["id"].(string)
	if w := do(h, "POST", "/api/nodes", map[string]any{"name": "again", "profile": map[string]any{
		"protocol": "http", "server": "proxy.example.com", "port": 3128, "username": "u", "password": "p"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("duplicate -> %d", w.Code)
	}
	if w := do(h, "GET", "/api/qr?id="+id, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("qr for a link-less node -> %d", w.Code)
	}
	// edit: switch it to a share link, keeping the ID
	w = do(h, "PUT", "/api/nodes/"+id, map[string]any{"name": "Renamed", "link": vlessLink})
	m = decodeBody(t, w)
	if w.Code != 200 || m["node"].(map[string]any)["id"] != id || m["node"].(map[string]any)["name"] != "Renamed" {
		t.Fatalf("edit: %d %v", w.Code, m)
	}
	if w := do(h, "PUT", "/api/nodes/nope", map[string]any{"link": vlessLink}); w.Code != http.StatusNotFound {
		t.Fatalf("edit unknown -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/nodes", map[string]any{"profile": map[string]any{"protocol": "vless", "server": "a.com", "port": 1}}); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid profile -> %d", w.Code)
	}
}

func TestEnginesAndStatus(t *testing.T) {
	h := newServer(t)
	m := decodeBody(t, do(h, "GET", "/api/engines", nil))
	es := m["engines"].([]any)
	x := es[0].(map[string]any)
	if len(es) != 1 || x["name"] != "xray" || x["displayName"] != "Xray core" || len(x["protocols"].([]any)) == 0 {
		t.Fatalf("engines: %v", m)
	}
	if w := do(h, "POST", "/api/engines/v2ray/check", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown engine -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/engines/xray/download", map[string]string{"version": "../../etc"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad version -> %d", w.Code)
	}
	st := decodeBody(t, do(h, "GET", "/api/status", nil))
	for _, k := range []string{"running", "uptimeSec", "activeLatencyMs", "routingMode", "systemProxyOn"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status lacks %s: %v", k, st)
		}
	}
}

func TestDNSRebindingBlockedByHostCheck(t *testing.T) {
	h := newServer(t)
	for _, host := range []string{"evil.example.com", "evil.example.com:12345", "127.0.0.1", "127.0.0.1:9999", "localhost.evil.com:12345", ""} {
		for _, path := range []string{"/api/status", "/api/state"} {
			if w := do(h, "GET", path, nil, withHost(host)); w.Code != http.StatusForbidden {
				t.Errorf("Host=%q %s -> %d", host, path, w.Code)
			}
		}
	}
	for _, host := range []string{"127.0.0.1:12345", "localhost:12345", "[::1]:12345", "LOCALHOST:12345"} {
		if w := do(h, "GET", "/api/state", nil, withHost(host)); w.Code != 200 {
			t.Errorf("Host=%q -> %d", host, w.Code)
		}
	}
}

func TestTokenRequiredOnAPI(t *testing.T) {
	h := newServer(t)
	if w := do(h, "GET", "/api/state", nil, noToken()); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token -> %d", w.Code)
	}
	if w := do(h, "GET", "/api/state", nil, withHeader(TokenHeader, "wrong")); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/connect", nil, noToken()); w.Code != http.StatusUnauthorized {
		t.Fatalf("POST no token -> %d", w.Code)
	}
}

func TestCSRFBlocked(t *testing.T) {
	h := newServer(t)
	// a malicious page cannot read the token, but even with one it is cross-origin
	if w := do(h, "POST", "/api/import", map[string]string{"text": vlessLink}, withHeader("Origin", "https://evil.example.com")); w.Code != 403 {
		t.Fatalf("cross-origin POST -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/import", map[string]string{"text": vlessLink}, withHeader("Sec-Fetch-Site", "cross-site")); w.Code != 403 {
		t.Fatalf("cross-site POST -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/import", map[string]string{"text": vlessLink}, withHeader("Origin", "http://127.0.0.1:12345")); w.Code != 200 {
		t.Fatalf("same-origin POST -> %d", w.Code)
	}
}

func TestJSONContentTypeRequired(t *testing.T) {
	h := newServer(t)
	// the classic CSRF vector: a "simple" cross-site form/text POST
	w := do(h, "POST", "/api/import", `{"text":"x"}`, withHeader("Content-Type", "text/plain"))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain -> %d", w.Code)
	}
	w = do(h, "POST", "/api/import", `{"text":"x"}`, withHeader("Content-Type", "application/x-www-form-urlencoded"))
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form -> %d", w.Code)
	}
}

func TestBodyLimit(t *testing.T) {
	h := newServer(t)
	big := `{"text":"` + strings.Repeat("a", maxBody+10) + `"}`
	w := do(h, "POST", "/api/import", big)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body -> %d", w.Code)
	}
}

func TestImportAndStateFlow(t *testing.T) {
	h := newServer(t)
	w := do(h, "POST", "/api/import", map[string]string{"text": vlessLink + "\nbogus://x"})
	m := decodeBody(t, w)
	if w.Code != 200 || m["ok"] != true || m["added"].(float64) != 1 || len(m["errors"].([]any)) != 1 {
		t.Fatalf("import: %d %v", w.Code, m)
	}
	state := decodeBody(t, do(h, "GET", "/api/state", nil))
	nodes := state["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("nodes: %v", nodes)
	}
	n := nodes[0].(map[string]any)
	if n["name"] != "Node A" {
		t.Fatalf("name = %v", n["name"])
	}
	if _, leaked := n["outbound"]; leaked {
		t.Fatal("outbound must no longer be persisted/served")
	}
	id := n["id"].(string)

	if w := do(h, "POST", "/api/active", map[string]string{"id": "nope"}); w.Code != http.StatusNotFound {
		t.Fatalf("unknown active -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/active", map[string]string{"id": id}); w.Code != 200 {
		t.Fatalf("set active -> %d", w.Code)
	}
	// QR works and is a PNG
	w = do(h, "GET", "/api/qr?id="+id+"&size=300", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("qr: %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	if w := do(h, "GET", "/api/qr?id=missing", nil); w.Code != 404 {
		t.Fatalf("qr missing -> %d", w.Code)
	}
	if w := do(h, "DELETE", "/api/nodes/"+id, nil); w.Code != 200 {
		t.Fatalf("delete -> %d", w.Code)
	}
}

func TestErrorStatusMapping(t *testing.T) {
	h := newServer(t)
	cases := []struct {
		method, path string
		body         any
		want         int
	}{
		{"POST", "/api/connect", nil, http.StatusConflict},                                              // no active node
		{"POST", "/api/pick-fastest", map[string]any{}, http.StatusConflict},                            // no nodes
		{"POST", "/api/cores/download", map[string]string{"version": "../../x"}, http.StatusBadRequest}, // validation
		{"POST", "/api/cores/use", map[string]string{"version": "v1.2.3"}, http.StatusBadRequest},
		{"POST", "/api/import", "{not json", http.StatusBadRequest},
		{"POST", "/api/subscriptions", map[string]string{"url": "ftp://x"}, http.StatusBadRequest},
		{"GET", "/api/config", nil, http.StatusNotFound},
		{"GET", "/api/nope", nil, http.StatusNotFound},
		{"DELETE", "/api/subscriptions/none", nil, http.StatusNotFound},
	}
	for _, c := range cases {
		w := do(h, c.method, c.path, c.body)
		if w.Code != c.want {
			t.Errorf("%s %s -> %d (want %d): %s", c.method, c.path, w.Code, c.want, w.Body.String())
		}
		if m := decodeBody(t, w); m["ok"] != false || m["error"] == "" {
			t.Errorf("%s %s: error envelope = %v", c.method, c.path, m)
		}
	}
}

func TestSettingsValidationOverHTTP(t *testing.T) {
	h := newServer(t)
	state := decodeBody(t, do(h, "GET", "/api/state", nil))
	settings := state["settings"].(map[string]any)

	settings["allowLan"] = true // no credentials -> open proxy -> refused
	w := do(h, "POST", "/api/settings", settings)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "network") {
		t.Fatalf("open proxy accepted: %d %s", w.Code, w.Body.String())
	}
	settings["allowLan"] = false
	settings["logLevel"] = "debug"
	if w := do(h, "POST", "/api/settings", settings); w.Code != 200 {
		t.Fatalf("valid settings -> %d %s", w.Code, w.Body.String())
	}
	if got := decodeBody(t, do(h, "GET", "/api/settings", nil))["logLevel"]; got != "debug" {
		t.Fatalf("not persisted: %v", got)
	}
}

func TestMethodsAreEnforced(t *testing.T) {
	h := newServer(t)
	if w := do(h, "GET", "/api/nodes/abc", nil); w.Code == 200 {
		t.Fatalf("GET on a DELETE route -> %d", w.Code)
	}
	if w := do(h, "PUT", "/api/state", nil); w.Code == 200 {
		t.Fatalf("PUT /api/state -> %d", w.Code)
	}
}

func TestLogsIncremental(t *testing.T) {
	h := newServer(t)
	m := decodeBody(t, do(h, "GET", "/api/logs?since=0", nil))
	if m["ok"] != true || m["next"].(float64) != 0 || len(m["logs"].([]any)) != 0 {
		t.Fatalf("logs: %v", m)
	}
}

func TestPanicIsContained(t *testing.T) {
	h := recoverer(slog.New(slog.NewTextHandler(io.Discard, nil)))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 500 {
		t.Fatalf("panic -> %d", w.Code)
	}
}

func TestNewRequiresToken(t *testing.T) {
	if _, err := New(nil, Config{}); err == nil {
		t.Fatal("empty token must be refused")
	}
}

func TestParseLinkAndNodeProfile(t *testing.T) {
	h := newServer(t)
	m := decodeBody(t, do(h, "POST", "/api/links/parse", map[string]string{"link": vlessLink}))
	p := m["profile"].(map[string]any)
	if m["name"] != "Node A" || p["protocol"] != "vless" || p["server"] != "1.2.3.4" {
		t.Fatalf("parse: %v", m)
	}
	if w := do(h, "POST", "/api/links/parse", map[string]string{"link": "ssr://x"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad link -> %d", w.Code)
	}
	n := decodeBody(t, do(h, "POST", "/api/nodes", map[string]string{"link": vlessLink}))["node"].(map[string]any)
	m = decodeBody(t, do(h, "GET", "/api/nodes/"+n["id"].(string)+"/profile", nil))
	if m["profile"].(map[string]any)["uuid"] != "u" {
		t.Fatalf("node profile: %v", m)
	}
	if w := do(h, "GET", "/api/jobs/999", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown job -> %d", w.Code)
	}
}

func TestChainEndpoints(t *testing.T) {
	h := newServer(t)
	id := func(link string) string {
		n := decodeBody(t, do(h, "POST", "/api/nodes", map[string]string{"link": link}))["node"].(map[string]any)
		return n["id"].(string)
	}
	a := id("vless://u@a.example.net:443?security=tls#A")
	b := id("trojan://p@b.example.net:443#B")

	m := decodeBody(t, do(h, "POST", "/api/chains/plan", map[string]any{"chain": []string{a, b}}))
	plan, _ := m["plan"].(map[string]any)
	if m["ok"] != true || plan["engine"] != "xray" || plan["processes"].(float64) != 1 || plan["engineName"] != "Xray core" {
		t.Fatalf("plan: %v", m)
	}
	if w := do(h, "POST", "/api/chains/plan", map[string]any{"chain": []string{a}}); w.Code != http.StatusBadRequest {
		t.Fatalf("one server is not a chain -> %d", w.Code)
	}
	w := do(h, "POST", "/api/nodes", map[string]any{"name": "Pair", "chain": []string{a, b}})
	n := decodeBody(t, w)["node"].(map[string]any)
	if w.Code != 200 || n["chain"] != true || n["protocolName"] != "Chain" || len(n["hops"].([]any)) != 2 {
		t.Fatalf("create chain: %d %v", w.Code, n)
	}
	e := decodeBody(t, do(h, "GET", "/api/nodes/"+n["id"].(string)+"/profile", nil))
	if _, has := e["profile"]; has || len(e["chain"].([]any)) != 2 {
		t.Fatalf("edit view of a chain: %v", e)
	}
	if w := do(h, "PUT", "/api/nodes/"+n["id"].(string), map[string]any{"name": "Renamed", "chain": []string{b, a}}); w.Code != 200 {
		t.Fatalf("update chain -> %d", w.Code)
	}
	if w := do(h, "POST", "/api/nodes", map[string]any{"chain": []string{a, "missing"}}); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown hop -> %d", w.Code)
	}
}
