package v2ray

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"testing"
	"time"

	"keyway/internal/models"
	"keyway/internal/profile"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeCert writes a self-signed certificate and key, returning their paths.
func writeCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "a.example"},
		DNSNames: []string{"a.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, keyPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, keyPath
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

// startV2Ray runs a config and waits for port to accept connections.
func startV2Ray(t *testing.T, bin, cfg string, port int) {
	t.Helper()
	cmd := exec.Command(bin, "run", "-c", cfg)
	cmd.Dir = filepath.Dir(cfg)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never opened port %d", cfg, port)
}

func vmessServer(t *testing.T, bin, dir, name string, port int, stream map[string]any) string {
	t.Helper()
	access := filepath.Join(dir, name+".access")
	in := map[string]any{"protocol": "vmess", "listen": "127.0.0.1", "port": port,
		"settings": map[string]any{"clients": []map[string]any{{"id": testUUID, "alterId": 0}}}}
	if stream != nil {
		in["streamSettings"] = stream
	}
	cfg := filepath.Join(dir, name+".json")
	writeJSON(t, cfg, map[string]any{
		"log":       map[string]any{"loglevel": "warning", "access": access},
		"inbounds":  []any{in},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	})
	startV2Ray(t, bin, cfg, port)
	return access
}

// allowSelfSigned marks the exit's TLS as trusting the test certificate. Keyway
// never generates this: Supports refuses insecure servers.
func allowSelfSigned(t *testing.T, cfg []byte) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(cfg, &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc["outbounds"].([]any) {
		ob := o.(map[string]any)
		if ob["tag"] == "proxy" {
			ob["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["allowInsecure"] = true
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChainEndToEnd(t *testing.T) {
	bin := os.Getenv("KEYWAY_V2RAY_BIN")
	if bin == "" {
		t.Skip("KEYWAY_V2RAY_BIN is not set")
	}
	t.Setenv("V2RAY_LOCATION_ASSET", filepath.Dir(bin))
	dir := t.TempDir()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "probe-ok") }))
	defer target.Close()

	cert, key := writeCert(t, dir)
	hopPort, exitPort := freePort(t), freePort(t)
	hopLog := vmessServer(t, bin, dir, "hop", hopPort, nil)
	exitLog := vmessServer(t, bin, dir, "exit", exitPort, map[string]any{"network": "tcp", "security": "tls",
		"tlsSettings": map[string]any{"certificates": []map[string]any{{"certificateFile": cert, "keyFile": key}}}})

	hop := vmess("tcp")
	hop.Server, hop.Port = "127.0.0.1", hopPort
	exit := vmess("tcp")
	exit.Server, exit.Port, exit.Security = "127.0.0.1", exitPort, tlsSec()

	socks, stats := freePort(t), freePort(t)
	s := models.DefaultSettings()
	s.RoutingMode = "global" // the target is on loopback, which the default mode sends direct
	s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: socks, Listen: "127.0.0.1", UDP: true, Enabled: true}}
	seg := profile.Segment{Hops: []profile.Profile{hop, exit}, Stats: &profile.StatsAPI{Port: stats}}
	b, err := BuildConfig(seg, s)
	if err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cfg, allowSelfSigned(t, b), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "test", "-c", cfg).CombinedOutput(); err != nil {
		t.Fatalf("v2ray test: %v\n%s", err, out)
	}
	startV2Ray(t, bin, cfg, socks)

	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", socks))
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 10 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "probe-ok" {
		t.Fatalf("body = %q", body)
	}

	for name, path := range map[string]string{"hop": hopLog, "exit": exitLog} {
		log, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(log), "accepted") {
			t.Errorf("%s access log has no connection:\n%s", name, log)
		}
	}
	out, err := exec.Command(bin, "api", "stats", "-json", "--server="+net.JoinHostPort("127.0.0.1", strconv.Itoa(stats))).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"outbound>>>proxy>>>traffic>>>uplink", "value"`) {
		t.Errorf("no proxy traffic in stats: %s", out)
	}
}
