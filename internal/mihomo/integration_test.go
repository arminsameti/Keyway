package mihomo

// These tests run the real Mihomo binary and are skipped unless KEYWAY_MIHOMO_BIN
// points at one. KEYWAY_XRAY_BIN and KEYWAY_SINGBOX_BIN add independent servers
// (a server written by someone else is the only proof that a client setting
// works on the wire, not just in Mihomo's own parser):
//
//	KEYWAY_MIHOMO_BIN=/path/mihomo KEYWAY_XRAY_BIN=/path/xray KEYWAY_SINGBOX_BIN=/path/sing-box \
//	  go test ./internal/mihomo -run Integration -v

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func needBin(t *testing.T, env string) string {
	t.Helper()
	bin := os.Getenv(env)
	if bin == "" {
		t.Skip(env + " is not set")
	}
	return bin
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// testCert is a self-signed certificate for a.example.
type testCert struct {
	cert, key string // PEM files
	pin       string // SHA-256 of the certificate, hex
	tlsCert   tls.Certificate
}

func newCert(t *testing.T, dir string) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a.example"},
		DNSNames: []string{"a.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	c := testCert{cert: filepath.Join(dir, "c.pem"), key: filepath.Join(dir, "k.pem")}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(c.cert, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.key, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	c.pin = hex.EncodeToString(sum[:])
	if c.tlsCert, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	return c
}

// relay is a TCP forwarder that counts the bytes passing through, so a test can
// see which hop a connection really took.
type relay struct {
	port  int
	bytes atomic.Int64
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

func newRelay(t *testing.T, to int) *relay {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{port: l.Addr().(*net.TCPAddr).Port}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(to)))
				if err != nil {
					return
				}
				defer up.Close()
				done := make(chan struct{}, 2)
				cp := func(dst, src net.Conn) {
					io.Copy(countWriter{dst, &r.bytes}, src)
					done <- struct{}{}
				}
				go cp(up, c)
				go cp(c, up)
				<-done
			}()
		}
	}()
	return r
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

type proc struct{ out *bytes.Buffer }

// start runs a process until the test ends. tcpPort > 0 waits for it to listen;
// 0 waits a moment (UDP servers).
func start(t *testing.T, tcpPort int, bin string, args ...string) *proc {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		if t.Failed() {
			defer func() { t.Logf("%s said:\n%s", filepath.Base(bin), out.String()) }()
		}
		cmd.Process.Kill()
		<-exited
	})
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			t.Fatalf("%s exited: %s", filepath.Base(bin), out.String())
		default:
		}
		if tcpPort == 0 {
			time.Sleep(1200 * time.Millisecond)
			return &proc{out}
		}
		if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tcpPort)), 100*time.Millisecond); err == nil {
			c.Close()
			return &proc{out}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never listened on %d: %s", filepath.Base(bin), tcpPort, out.String())
	return nil
}

func startMihomo(t *testing.T, cfg []byte, port int) *proc {
	t.Helper()
	bin := needBin(t, "KEYWAY_MIHOMO_BIN")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json") // Keyway's file name: the content decides, not the extension
	if err := os.WriteFile(path, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	// KEYWAY_MIHOMO_GEODIR holds GeoSite.dat and geoip.metadb for configs that use them
	if geo := os.Getenv("KEYWAY_MIHOMO_GEODIR"); geo != "" {
		for _, f := range []string{"GeoSite.dat", "geoip.metadb"} {
			if b, err := os.ReadFile(filepath.Join(geo, f)); err == nil {
				if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if out, err := exec.Command(bin, "-t", "-d", dir, "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("mihomo -t: %v\n%s\n%s", err, out, cfg)
	}
	return start(t, port, bin, "-d", dir, "-f", path)
}

// target is a local web server that answers "probe-ok".
func webTarget(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "probe-ok") }))
	t.Cleanup(ts.Close)
	return ts
}

func viaSocks(t *testing.T, port int, user, pass, target string) (string, error) {
	t.Helper()
	u := &url.URL{Scheme: "socks5h", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true}, Timeout: 8 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func globalSettings(socks int) models.Settings {
	s := models.DefaultSettings()
	s.RoutingMode = "global" // the target is on loopback, which the default mode sends direct
	s.BlockAds = false
	s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: socks, Listen: "127.0.0.1", UDP: true, Enabled: true}}
	return s
}

// runClient builds the segment, starts Mihomo with it and fetches target.
func runClient(t *testing.T, seg profile.Segment, s models.Settings, tgt string) (string, error) {
	t.Helper()
	socks := s.Inbounds[0].Port
	b, err := BuildConfig(seg, s)
	if err != nil {
		t.Fatal(err)
	}
	p := startMihomo(t, b, socks)
	body, err := viaSocks(t, socks, s.Inbounds[0].Username, s.Inbounds[0].Password, tgt)
	if err != nil {
		t.Logf("mihomo said:\n%s", p.out.String())
	}
	return body, err
}

// ---- Mihomo against Mihomo: a real two-hop chain ----

func yamlFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// mihomoServer runs a Mihomo that only listens as the given inbound and sends
// everything out directly.
func mihomoServer(t *testing.T, name string, port int, listener map[string]any) {
	t.Helper()
	bin := needBin(t, "KEYWAY_MIHOMO_BIN")
	dir := t.TempDir()
	// Mihomo reads certificates only from inside its home directory
	for _, k := range []string{"certificate", "private-key"} {
		if p, ok := listener[k].(string); ok {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			listener[k] = filepath.Join(dir, k+".pem")
			if err := os.WriteFile(listener[k].(string), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	listener["name"], listener["listen"], listener["port"] = name, "127.0.0.1", port
	cfg := filepath.Join(dir, "server.yaml")
	yamlFile(t, cfg, map[string]any{"mode": "direct", "log-level": "error", "listeners": []any{listener}})
	start(t, port, bin, "-d", dir, "-f", cfg)
}

func TestIntegrationChainPassesTrafficThroughEveryHop(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	cert := newCert(t, t.TempDir())
	tgt := webTarget(t)
	hopPort, midPort, exitPort := freePort(t), freePort(t), freePort(t)
	mihomoServer(t, "hop", hopPort, map[string]any{"type": "vmess", "users": []any{map[string]any{"username": "u", "uuid": testUUID, "alterId": 0}}})
	mihomoServer(t, "mid", midPort, map[string]any{"type": "shadowsocks", "password": "ss-pw", "cipher": "aes-256-gcm"})
	mihomoServer(t, "exit", exitPort, map[string]any{"type": "trojan", "users": []any{map[string]any{"username": "u", "password": "pw"}},
		"certificate": cert.cert, "private-key": cert.key})
	hopRelay, midRelay, exitRelay := newRelay(t, hopPort), newRelay(t, midPort), newRelay(t, exitPort)

	hop := profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: hopRelay.port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
	mid := profile.Profile{Protocol: profile.Shadowsocks, Server: "127.0.0.1", Port: midRelay.port, Cipher: "aes-256-gcm", Password: "ss-pw"}
	exit := profile.Profile{Protocol: profile.Trojan, Server: "127.0.0.1", Port: exitRelay.port, Password: "pw", Transport: profile.Transport{Type: "tcp"},
		Security: profile.Security{Kind: "tls", SNI: "a.example", PinSHA256: cert.pin}}

	socks, stats := freePort(t), freePort(t)
	s := globalSettings(socks)
	seg := profile.Segment{Hops: []profile.Profile{hop, mid, exit}, Stats: &profile.StatsAPI{Port: stats, Secret: "integration-secret"}}
	body, err := runClient(t, seg, s, tgt.URL)
	if err != nil || body != "probe-ok" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
	// Every server is only reachable through the one before it: each relay sees
	// its own protocol's bytes, and the earlier ones carry the later ones wrapped.
	h, m, e := hopRelay.bytes.Load(), midRelay.bytes.Load(), exitRelay.bytes.Load()
	if h == 0 || m == 0 || e == 0 {
		t.Errorf("bytes through hop = %d, mid = %d, exit = %d: the chain was not used", h, m, e)
	}
	if h < m || m < e {
		t.Errorf("hop saw %d, mid %d, exit %d bytes: each hop must carry the ones after it", h, m, e)
	}

	// traffic counters: Bearer secret required, totals non-zero
	api := fmt.Sprintf("http://127.0.0.1:%d/connections", stats)
	resp, err := http.Get(api)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("controller without the secret: %s", resp.Status)
	}
	req, _ := http.NewRequest(http.MethodGet, api, nil)
	req.Header.Set("Authorization", "Bearer integration-secret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc struct{ Up, Down int64 }
	var raw map[string]any
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("connections: %v\n%s", err, b)
	}
	doc.Up, doc.Down = int64(raw["uploadTotal"].(float64)), int64(raw["downloadTotal"].(float64))
	if doc.Up == 0 || doc.Down == 0 {
		t.Errorf("stats up = %d down = %d", doc.Up, doc.Down)
	}
}

// Two Mihomo processes, as the planner builds them when another engine sits in
// between or follows: the first exposes its exit on a password-protected
// bridge, the second dials its server through that bridge.
func TestIntegrationBridgeJoinsTwoProcesses(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	tgt := webTarget(t)
	vmessUser := []any{map[string]any{"username": "u", "uuid": testUUID, "alterId": 0}}
	s1, s2 := freePort(t), freePort(t)
	mihomoServer(t, "first", s1, map[string]any{"type": "vmess", "users": vmessUser})
	mihomoServer(t, "second", s2, map[string]any{"type": "vmess", "users": vmessUser})
	r1, r2 := newRelay(t, s1), newRelay(t, s2)
	hop := func(port int) profile.Profile {
		return profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
	}

	bridge := profile.Bridge{Port: freePort(t), User: "bu", Pass: "bp"}
	mid, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hop(r1.port)}, Listen: &bridge}, models.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, mid, bridge.Port)
	if _, err := viaSocks(t, bridge.Port, "bu", "wrong", tgt.URL); err == nil {
		t.Error("the bridge accepted a wrong password")
	}
	if _, err := viaSocks(t, bridge.Port, "", "", tgt.URL); err == nil {
		t.Error("the bridge accepted no password")
	}

	socks := freePort(t)
	s := globalSettings(socks)
	s.Inbounds[0].Username, s.Inbounds[0].Password = "me", "secret"
	front, err := BuildConfig(profile.Segment{Hops: []profile.Profile{hop(r2.port)}, Upstream: &bridge}, s)
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, front, socks)
	if _, err := viaSocks(t, socks, "me", "wrong", tgt.URL); err == nil {
		t.Error("the inbound accepted a wrong password")
	}
	if _, err := viaSocks(t, socks, "", "", tgt.URL); err == nil {
		t.Error("the inbound accepted no password")
	}
	if body, err := viaSocks(t, socks, "me", "secret", tgt.URL); err != nil || body != "probe-ok" {
		t.Fatalf("through both processes: %q, %v", body, err)
	}
	// the second server is only reachable through the first
	if r1.bytes.Load() == 0 || r2.bytes.Load() == 0 {
		t.Errorf("bytes through the first = %d, the second = %d", r1.bytes.Load(), r2.bytes.Load())
	}
}

// socksUDP sends one datagram to dst through a SOCKS5 UDP association and
// returns the reply.
func socksUDP(t *testing.T, socksPort int, dst *net.UDPAddr, payload []byte) []byte {
	t.Helper()
	ctrl, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort)), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(6 * time.Second))
	ctrl.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(ctrl, greeting); err != nil || greeting[1] != 0 {
		t.Fatalf("greeting %v, %v", greeting, err)
	}
	ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(ctrl, reply); err != nil || reply[1] != 0 {
		t.Fatalf("udp associate: %v, %v", reply, err)
	}
	relayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(reply[8])<<8 | int(reply[9])}
	c, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	pkt := append([]byte{0, 0, 0, 1}, dst.IP.To4()...)
	pkt = append(pkt, byte(dst.Port>>8), byte(dst.Port))
	if _, err := c.Write(append(pkt, payload...)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("no UDP reply: %v", err)
	}
	return buf[10:n]
}

func TestIntegrationUDPPassesThroughTheProxy(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("echo:"), buf[:n]...), from)
		}
	}()
	exitPort := freePort(t)
	mihomoServer(t, "exit", exitPort, map[string]any{"type": "vmess", "users": []any{map[string]any{"username": "u", "uuid": testUUID, "alterId": 0}}})
	relayed := newRelay(t, exitPort)
	exit := profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: relayed.port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
	socks := freePort(t)
	b, err := BuildConfig(profile.Single(exit), globalSettings(socks))
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, b, socks)
	got := socksUDP(t, socks, echo.LocalAddr().(*net.UDPAddr), []byte("ping"))
	if string(got) != "echo:ping" {
		t.Fatalf("reply = %q", got)
	}
	if relayed.bytes.Load() == 0 {
		t.Error("the datagram did not go through the proxy")
	}
}

// ---- routing: which rules really send traffic where ----

func TestIntegrationRoutingRules(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	tgt := webTarget(t)
	tp := tgt.Listener.Addr().(*net.TCPAddr).Port
	exitPort := freePort(t)
	mihomoServer(t, "exit", exitPort, map[string]any{"type": "vmess", "users": []any{map[string]any{"username": "u", "uuid": testUUID, "alterId": 0}}})
	relayed := newRelay(t, exitPort)
	exit := profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: relayed.port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}

	run := func(t *testing.T, s models.Settings, host string) (via bool) {
		t.Helper()
		socks := freePort(t)
		s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: socks, Listen: "127.0.0.1", UDP: true, Enabled: true}}
		b, err := BuildConfig(profile.Single(exit), s)
		if err != nil {
			t.Fatal(err)
		}
		startMihomo(t, b, socks)
		before := relayed.bytes.Load()
		body, err := viaSocks(t, socks, "", "", fmt.Sprintf("http://%s:%d/", host, tp))
		if err != nil || body != "probe-ok" {
			t.Fatalf("%s: %q, %v", host, body, err)
		}
		return relayed.bytes.Load() > before
	}

	t.Run("bypass-private sends loopback and private names direct", func(t *testing.T) {
		s := models.DefaultSettings()
		s.DirectSites = "full:never-matches.example" // no geodata needed
		s.BlockAds = false
		if run(t, s, "127.0.0.1") {
			t.Error("a loopback address went through the proxy")
		}
		// a name that resolves to loopback is caught by the second, resolving pass
		if run(t, s, "localhost") {
			t.Error("localhost went through the proxy")
		}
	})
	t.Run("global sends everything through the proxy", func(t *testing.T) {
		if !run(t, globalSettings(0), "127.0.0.1") {
			t.Error("the loopback address did not go through the proxy")
		}
	})
	t.Run("port rule", func(t *testing.T) {
		s := models.DefaultSettings()
		s.RoutingMode, s.BlockAds = "rules", false
		s.RuleSets = []models.RuleSet{{ID: "a", Name: "a", Rules: []models.RouteRule{
			{ID: "1", Enabled: true, Entries: []string{"port:1,2,3," + strconv.Itoa(tp-1) + "-" + strconv.Itoa(tp+1)}, Outbound: "direct"}}}}
		s.ActiveRuleSet = "a"
		if run(t, s, "127.0.0.1") {
			t.Error("the port range did not match")
		}
	})
	t.Run("cidr and domain rules", func(t *testing.T) {
		s := models.DefaultSettings()
		s.RoutingMode, s.BlockAds = "rules", false
		s.RuleSets = []models.RuleSet{{ID: "a", Name: "a", Rules: []models.RouteRule{
			{ID: "1", Enabled: true, Entries: []string{"127.0.0.0/8"}, Outbound: "direct"}}}}
		s.ActiveRuleSet = "a"
		if run(t, s, "127.0.0.1") {
			t.Error("the CIDR rule did not match")
		}
		s.RuleSets[0].Rules[0].Entries = []string{"full:localhost"}
		if run(t, s, "localhost") {
			t.Error("the domain rule did not match")
		}
		s.RuleSets[0].Rules[0].Entries = []string{"full:other.example"}
		if !run(t, s, "127.0.0.1") {
			t.Error("an unrelated rule sent traffic direct")
		}
	})
	t.Run("block rule rejects", func(t *testing.T) {
		s := models.DefaultSettings()
		s.RoutingMode, s.BlockAds = "rules", false
		s.RuleSets = []models.RuleSet{{ID: "a", Name: "a", Rules: []models.RouteRule{
			{ID: "1", Enabled: true, Entries: []string{"127.0.0.0/8"}, Outbound: "block"}}}}
		s.ActiveRuleSet = "a"
		socks := freePort(t)
		s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: socks, Listen: "127.0.0.1", Enabled: true}}
		b, err := BuildConfig(profile.Single(exit), s)
		if err != nil {
			t.Fatal(err)
		}
		startMihomo(t, b, socks)
		if body, err := viaSocks(t, socks, "", "", tgt.URL); err == nil {
			t.Errorf("a blocked destination answered %q", body)
		}
	})
}

// ---- independent servers: Xray ----

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func xrayServer(t *testing.T, inbound map[string]any) {
	t.Helper()
	bin := needBin(t, "KEYWAY_XRAY_BIN")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "x.json")
	writeJSON(t, cfg, map[string]any{"log": map[string]any{"loglevel": "warning"},
		"inbounds":  []any{inbound},
		"outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}}}}})
	port := inbound["port"].(int)
	start(t, port, bin, "run", "-c", cfg)
}

func certStream(network, security string, cert testCert, extra map[string]any) map[string]any {
	st := map[string]any{"network": network, "security": security}
	if security == "tls" {
		st["tlsSettings"] = map[string]any{"serverName": "a.example",
			"certificates": []any{map[string]any{"certificateFile": cert.cert, "keyFile": cert.key}}}
	}
	for k, v := range extra {
		st[k] = v
	}
	return st
}

type matrixCase struct {
	name   string
	server func(t *testing.T, port int, c testCert) // starts the server
	p      func(port int, c testCert) profile.Profile
}

func tlsPinned(c testCert) profile.Security {
	return profile.Security{Kind: "tls", SNI: "a.example", PinSHA256: c.pin}
}

func TestIntegrationXrayServers(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	needBin(t, "KEYWAY_XRAY_BIN")
	vlessClients := []any{map[string]any{"id": testUUID, "flow": ""}}
	visionClients := []any{map[string]any{"id": testUUID, "flow": "xtls-rprx-vision"}}
	cases := []matrixCase{
		{"vless tcp tls pinned", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"clients": vlessClients, "decryption": "none"}, "streamSettings": certStream("tcp", "tls", c, nil)})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: port, UUID: testUUID, Transport: profile.Transport{Type: "tcp"}, Security: tlsPinned(c)}
		}},
		{"vless tcp tls insecure", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"clients": vlessClients, "decryption": "none"}, "streamSettings": certStream("tcp", "tls", c, nil)})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: port, UUID: testUUID, Transport: profile.Transport{Type: "tcp"},
				Security: profile.Security{Kind: "tls", SNI: "a.example", Insecure: true}}
		}},
		{"vless tcp plain", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"clients": vlessClients, "decryption": "none"}, "streamSettings": map[string]any{"network": "tcp"}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: port, UUID: testUUID, Transport: profile.Transport{Type: "tcp"}}
		}},
		{"vless ws tls", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": port,
				"settings":       map[string]any{"clients": vlessClients, "decryption": "none"},
				"streamSettings": certStream("ws", "tls", c, map[string]any{"wsSettings": map[string]any{"path": "/ray"}})})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: port, UUID: testUUID,
				Transport: profile.Transport{Type: "ws", Path: "/ray", Host: "a.example"}, Security: tlsPinned(c)}
		}},
		{"vless grpc tls", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": port,
				"settings":       map[string]any{"clients": vlessClients, "decryption": "none"},
				"streamSettings": certStream("grpc", "tls", c, map[string]any{"grpcSettings": map[string]any{"serviceName": "svc"}})})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: port, UUID: testUUID,
				Transport: profile.Transport{Type: "grpc", ServiceName: "svc"}, Security: tlsPinned(c)}
		}},
		{"vmess tcp", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vmess", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"clients": []any{map[string]any{"id": testUUID}}}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
		}},
		{"vmess ws tls", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vmess", "listen": "127.0.0.1", "port": port,
				"settings":       map[string]any{"clients": []any{map[string]any{"id": testUUID}}},
				"streamSettings": certStream("ws", "tls", c, map[string]any{"wsSettings": map[string]any{"path": "/w"}})})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: port, UUID: testUUID, Cipher: "aes-128-gcm",
				Transport: profile.Transport{Type: "ws", Path: "/w"}, Security: tlsPinned(c)}
		}},
		{"vmess httpupgrade", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "vmess", "listen": "127.0.0.1", "port": port,
				"settings":       map[string]any{"clients": []any{map[string]any{"id": testUUID}}},
				"streamSettings": certStream("httpupgrade", "none", c, map[string]any{"httpupgradeSettings": map[string]any{"path": "/hu"}})})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: port, UUID: testUUID, Cipher: "auto",
				Transport: profile.Transport{Type: "httpupgrade", Path: "/hu"}}
		}},
		{"trojan tcp tls", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "trojan", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"clients": []any{map[string]any{"password": "pw"}}}, "streamSettings": certStream("tcp", "tls", c, nil)})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.Trojan, Server: "127.0.0.1", Port: port, Password: "pw", Transport: profile.Transport{Type: "tcp"}, Security: tlsPinned(c)}
		}},
		{"trojan ws tls", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "trojan", "listen": "127.0.0.1", "port": port,
				"settings":       map[string]any{"clients": []any{map[string]any{"password": "pw"}}},
				"streamSettings": certStream("ws", "tls", c, map[string]any{"wsSettings": map[string]any{"path": "/t"}})})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.Trojan, Server: "127.0.0.1", Port: port, Password: "pw",
				Transport: profile.Transport{Type: "ws", Path: "/t"}, Security: tlsPinned(c)}
		}},
		{"trojan grpc tls", func(t *testing.T, port int, c testCert) {
			xrayServer(t, map[string]any{"protocol": "trojan", "listen": "127.0.0.1", "port": port,
				"settings":       map[string]any{"clients": []any{map[string]any{"password": "pw"}}},
				"streamSettings": certStream("grpc", "tls", c, map[string]any{"grpcSettings": map[string]any{"serviceName": "svc"}})})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.Trojan, Server: "127.0.0.1", Port: port, Password: "pw",
				Transport: profile.Transport{Type: "grpc", ServiceName: "svc"}, Security: tlsPinned(c)}
		}},
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "chacha20-poly1305"} {
		cases = append(cases, ssCase(method, "pw"))
	}
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		key := b64Std(bytes.Repeat([]byte{7}, 32))
		if method == "2022-blake3-aes-128-gcm" {
			key = b64Std(bytes.Repeat([]byte{7}, 16))
		}
		cases = append(cases, ssCase(method, key))
	}
	cases = append(cases, realityCases(t, vlessClients, visionClients)...)
	runMatrix(t, cases)
}

func b64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func ssCase(method, password string) matrixCase {
	xrayMethod := method
	if method == "chacha20-ietf-poly1305" {
		xrayMethod = "chacha20-ietf-poly1305"
	}
	return matrixCase{"shadowsocks " + method, func(t *testing.T, port int, c testCert) {
		xrayServer(t, map[string]any{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": port,
			"settings": map[string]any{"method": xrayMethod, "password": password, "network": "tcp,udp"}})
	}, func(port int, c testCert) profile.Profile {
		return profile.Profile{Protocol: profile.Shadowsocks, Server: "127.0.0.1", Port: port, Cipher: method, Password: password}
	}}
}

// realityCases: Reality needs a TLS 1.3 site to borrow; a local one stands in.
func realityCases(t *testing.T, vlessClients, visionClients []any) []matrixCase {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverCase := func(name string, clients []any, flow string) matrixCase {
		return matrixCase{name, func(t *testing.T, port int, c testCert) {
			site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "site") }))
			site.TLS = &tls.Config{Certificates: []tls.Certificate{c.tlsCert}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
			site.StartTLS()
			t.Cleanup(site.Close)
			xrayServer(t, map[string]any{"protocol": "vless", "listen": "127.0.0.1", "port": port,
				"settings": map[string]any{"clients": clients, "decryption": "none"},
				"streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{
					"dest": site.Listener.Addr().String(), "serverNames": []any{"a.example"},
					"privateKey": b64(priv.Bytes()), "shortIds": []any{"ab12"}}}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: port, UUID: testUUID, Flow: flow, Transport: profile.Transport{Type: "tcp"},
				Security: profile.Security{Kind: "reality", SNI: "a.example", PublicKey: b64(priv.PublicKey().Bytes()), ShortID: "ab12", Fingerprint: "chrome"}}
		}}
	}
	return []matrixCase{serverCase("vless reality", vlessClients, ""), serverCase("vless reality vision", visionClients, "xtls-rprx-vision")}
}

// lanTarget serves "probe-ok" on this machine's non-loopback address: a
// WireGuard tunnel cannot carry loopback traffic, so its test needs one.
func lanTarget(t *testing.T) string {
	t.Helper()
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			l, err := net.Listen("tcp", net.JoinHostPort(n.IP.String(), "0"))
			if err != nil {
				continue
			}
			ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "probe-ok") }))
			ts.Listener.Close()
			ts.Listener = l
			ts.Start()
			t.Cleanup(ts.Close)
			return ts.URL
		}
	}
	t.Skip("no non-loopback IPv4 address to test through a WireGuard tunnel")
	return ""
}

func runMatrix(t *testing.T, cases []matrixCase) {
	t.Helper()
	tgt := webTarget(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			url := tgt.URL
			if strings.HasPrefix(c.name, "wireguard") {
				url = lanTarget(t)
			}
			dir := t.TempDir()
			cert := newCert(t, dir)
			port := freePort(t)
			c.server(t, port, cert)
			p := c.p(port, cert)
			if err := Supports(p); err != nil {
				t.Fatalf("Supports: %v", err)
			}
			body, err := runClient(t, profile.Single(p), globalSettings(freePort(t)), url)
			if err != nil || body != "probe-ok" {
				t.Fatalf("body = %q, err = %v", body, err)
			}
		})
	}
}

// Certificate checks must really happen: no pin and no insecure flag fails on a
// self-signed certificate, and a wrong pin fails too.
func TestIntegrationCertificateChecksAreEnforced(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	needBin(t, "KEYWAY_XRAY_BIN")
	tgt := webTarget(t)
	cert := newCert(t, t.TempDir())
	port := freePort(t)
	xrayServer(t, map[string]any{"protocol": "trojan", "listen": "127.0.0.1", "port": port,
		"settings": map[string]any{"clients": []any{map[string]any{"password": "pw"}}}, "streamSettings": certStream("tcp", "tls", cert, nil)})
	mk := func(sec profile.Security) profile.Profile {
		return profile.Profile{Protocol: profile.Trojan, Server: "127.0.0.1", Port: port, Password: "pw", Transport: profile.Transport{Type: "tcp"}, Security: sec}
	}
	for name, sec := range map[string]profile.Security{
		"self-signed, no pin": {Kind: "tls", SNI: "a.example"},
		"wrong pin":           {Kind: "tls", SNI: "a.example", PinSHA256: strings.Repeat("00", 32)},
		"wrong server name":   {Kind: "tls", SNI: "other.example"},
	} {
		if body, err := runClient(t, profile.Single(mk(sec)), globalSettings(freePort(t)), tgt.URL); err == nil && body == "probe-ok" {
			t.Errorf("%s: the connection went through", name)
		}
	}
	if body, err := runClient(t, profile.Single(mk(profile.Security{Kind: "tls", SNI: "a.example", PinSHA256: strings.ToUpper(cert.pin)})), globalSettings(freePort(t)), tgt.URL); err != nil || body != "probe-ok" {
		t.Errorf("an upper-case pin: %q, %v", body, err)
	}
}

// ---- independent servers: sing-box ----

func singboxServer(t *testing.T, tcpPort int, inbound map[string]any, endpoints ...any) {
	t.Helper()
	bin := needBin(t, "KEYWAY_SINGBOX_BIN")
	dir := t.TempDir()
	cfg := filepath.Join(dir, "s.json")
	doc := map[string]any{"log": map[string]any{"level": "warn"}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route": map[string]any{"final": "direct"}}
	if inbound != nil {
		doc["inbounds"] = []any{inbound}
	}
	if len(endpoints) > 0 {
		doc["endpoints"] = endpoints
	}
	writeJSON(t, cfg, doc)
	start(t, tcpPort, bin, "run", "-c", cfg)
}

func TestIntegrationSingBoxServers(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	needBin(t, "KEYWAY_SINGBOX_BIN")
	tlsServer := func(c testCert, alpn ...string) map[string]any {
		m := map[string]any{"enabled": true, "server_name": "a.example", "certificate_path": c.cert, "key_path": c.key}
		if len(alpn) > 0 {
			m["alpn"] = alpn
		}
		return m
	}
	wgServerKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wgClientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	cases := []matrixCase{
		{"hysteria2", func(t *testing.T, port int, c testCert) {
			singboxServer(t, 0, map[string]any{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
				"users": []any{map[string]any{"password": "pw"}}, "tls": tlsServer(c, "h3")})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.Hysteria2, Server: "127.0.0.1", Port: port, Password: "pw", Security: tlsPinned(c)}
		}},
		{"hysteria2 salamander obfs", func(t *testing.T, port int, c testCert) {
			singboxServer(t, 0, map[string]any{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
				"obfs":  map[string]any{"type": "salamander", "password": "obfs-pw"},
				"users": []any{map[string]any{"password": "pw"}}, "tls": tlsServer(c, "h3")})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.Hysteria2, Server: "127.0.0.1", Port: port, Password: "pw", Security: tlsPinned(c),
				Hysteria: &profile.HysteriaOpts{Obfs: "salamander", ObfsPassword: "obfs-pw", UpMbps: 50, DownMbps: 100}}
		}},
		{"tuic", func(t *testing.T, port int, c testCert) {
			singboxServer(t, 0, map[string]any{"type": "tuic", "listen": "127.0.0.1", "listen_port": port,
				"users": []any{map[string]any{"uuid": testUUID, "password": "pw"}}, "congestion_control": "bbr", "tls": tlsServer(c, "h3")})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.TUIC, Server: "127.0.0.1", Port: port, UUID: testUUID, Password: "pw", Security: tlsPinned(c),
				TUIC: &profile.TUICOpts{CongestionControl: "bbr", UDPRelayMode: "native"}}
		}},
		{"anytls", func(t *testing.T, port int, c testCert) {
			singboxServer(t, port, map[string]any{"type": "anytls", "listen": "127.0.0.1", "listen_port": port,
				"users": []any{map[string]any{"password": "pw"}}, "tls": tlsServer(c)})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.AnyTLS, Server: "127.0.0.1", Port: port, Password: "pw", Security: tlsPinned(c)}
		}},
		{"vmess h2 tls", func(t *testing.T, port int, c testCert) {
			// Xray 26 removed the plain HTTP/2 transport, so sing-box is the independent server for it
			singboxServer(t, port, map[string]any{"type": "vmess", "listen": "127.0.0.1", "listen_port": port,
				"users": []any{map[string]any{"uuid": testUUID}}, "tls": tlsServer(c),
				"transport": map[string]any{"type": "http", "host": []any{"a.example"}, "path": "/h2"}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: port, UUID: testUUID, Cipher: "auto",
				Transport: profile.Transport{Type: "h2", Path: "/h2", Host: "a.example"}, Security: tlsPinned(c)}
		}},
		{"socks", func(t *testing.T, port int, c testCert) {
			singboxServer(t, port, map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": port,
				"users": []any{map[string]any{"username": "u", "password": "pw"}}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.SOCKS, Server: "127.0.0.1", Port: port, Username: "u", Password: "pw"}
		}},
		{"http", func(t *testing.T, port int, c testCert) {
			singboxServer(t, port, map[string]any{"type": "http", "listen": "127.0.0.1", "listen_port": port,
				"users": []any{map[string]any{"username": "u", "password": "pw"}}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.HTTP, Server: "127.0.0.1", Port: port, Username: "u", Password: "pw"}
		}},
		{"wireguard", func(t *testing.T, port int, c testCert) {
			singboxServer(t, 0, nil, map[string]any{"type": "wireguard", "tag": "wg", "address": []any{"10.7.0.1/24"},
				"private_key": b64Std(wgServerKey.Bytes()), "listen_port": port,
				"peers": []any{map[string]any{"public_key": b64Std(wgClientKey.PublicKey().Bytes()), "pre_shared_key": b64Std(bytes.Repeat([]byte{9}, 32)), "allowed_ips": []any{"10.7.0.2/32"}}}})
		}, func(port int, c testCert) profile.Profile {
			return profile.Profile{Protocol: profile.WireGuard, Server: "127.0.0.1", Port: port,
				WireGuard: &profile.WireGuardOpts{PrivateKey: b64Std(wgClientKey.Bytes()), PeerPublicKey: b64Std(wgServerKey.PublicKey().Bytes()),
					LocalAddress: []string{"10.7.0.2/32"}, PreSharedKey: b64Std(bytes.Repeat([]byte{9}, 32)), Keepalive: 25}}
		}},
	}
	runMatrix(t, cases)
}
