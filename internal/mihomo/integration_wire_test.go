package mihomo

// Settings that must take effect on the wire, not only in Mihomo's parser (see
// integration_test.go for how to run these).

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"keyway/internal/models"
	"keyway/internal/profile"
)

// helloShape reads a TLS ClientHello and returns its cipher suites and sorted
// extension types, which differ between browser fingerprints.
func helloShape(t *testing.T, hello []byte) string {
	t.Helper()
	if len(hello) < 44 || hello[0] != 0x16 || hello[5] != 0x01 {
		t.Fatalf("not a ClientHello: % x", hello[:min(len(hello), 16)])
	}
	b := hello[43:] // record(5) + handshake(4) + version(2) + random(32)
	b = b[1+int(b[0]):]
	cs := int(b[0])<<8 | int(b[1])
	suites := b[2 : 2+cs]
	b = b[2+cs:]
	b = b[1+int(b[0]):] // compression
	extLen := int(b[0])<<8 | int(b[1])
	b = b[2:]
	if extLen < len(b) {
		b = b[:extLen]
	}
	var types []string
	for len(b) >= 4 {
		typ, n := int(b[0])<<8|int(b[1]), int(b[2])<<8|int(b[3])
		if typ&0x0f0f != 0x0a0a { // GREASE values change on every connection
			types = append(types, fmt.Sprintf("%04x", typ))
		}
		if 4+n > len(b) {
			break
		}
		b = b[4+n:]
	}
	sort.Strings(types)
	var sb strings.Builder
	for i := 0; i+1 < len(suites); i += 2 {
		if v := int(suites[i])<<8 | int(suites[i+1]); v&0x0f0f != 0x0a0a {
			fmt.Fprintf(&sb, "%04x,", v)
		}
	}
	return sb.String() + "|" + strings.Join(types, ",")
}

// capturedHello runs Mihomo against a listener that records the first bytes a
// client sends, and returns the shape of that ClientHello.
func capturedHello(t *testing.T, fingerprint string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	p := profile.Profile{Protocol: profile.VLESS, Server: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, UUID: testUUID,
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "tls", SNI: "a.example", Fingerprint: fingerprint}}
	socks := freePort(t)
	b, err := BuildConfig(profile.Single(p), globalSettings(socks))
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, b, socks)
	go viaSocks(t, socks, "", "", "http://127.0.0.1:9/")
	select {
	case h := <-got:
		return helloShape(t, h)
	case <-time.After(8 * time.Second):
		t.Fatal("Mihomo never sent a ClientHello")
	}
	return ""
}

func TestIntegrationFingerprintChangesTheClientHello(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	none, chrome, firefox := capturedHello(t, ""), capturedHello(t, "chrome"), capturedHello(t, "firefox")
	if chrome == none || firefox == none || chrome == firefox {
		t.Fatalf("the fingerprint did not change the ClientHello:\nnone    %s\nchrome  %s\nfirefox %s", none, chrome, firefox)
	}
}

// The default settings (private and Chinese addresses direct, ads blocked) with
// the real geodata: the configuration loads, and a private destination is not
// sent through the proxy.
func TestIntegrationDefaultRoutingWithGeodata(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	if os.Getenv("KEYWAY_MIHOMO_GEODIR") == "" {
		t.Skip("KEYWAY_MIHOMO_GEODIR is not set")
	}
	tgt := webTarget(t)
	exitPort := freePort(t)
	mihomoServer(t, "exit", exitPort, map[string]any{"type": "vmess", "users": []any{map[string]any{"username": "u", "uuid": testUUID, "alterId": 0}}})
	relayed := newRelay(t, exitPort)
	exit := profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: relayed.port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
	s := models.DefaultSettings()
	s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: freePort(t), Listen: "127.0.0.1", Enabled: true}}
	s.RoutingMode = "rules"
	s.RuleSets = []models.RuleSet{{ID: "a", Name: "a", Rules: []models.RouteRule{
		{ID: "1", Enabled: true, Entries: []string{"geosite:cn", "geoip:cn", "geosite:private"}, Outbound: "direct"}}}}
	s.ActiveRuleSet = "a"
	for _, mode := range []string{"bypass-private", "rules"} {
		s.RoutingMode = mode
		s.Inbounds[0].Port = freePort(t)
		b, err := BuildConfig(profile.Single(exit), s)
		if err != nil {
			t.Fatal(err)
		}
		startMihomo(t, b, s.Inbounds[0].Port)
		before := relayed.bytes.Load()
		if body, err := viaSocks(t, s.Inbounds[0].Port, "", "", tgt.URL); err != nil || body != "probe-ok" {
			t.Fatalf("%s: %q, %v", mode, body, err)
		}
		// bypass-private keeps loopback direct; in "rules" mode nothing matches it, so it is proxied
		if via := relayed.bytes.Load() != before; via != (mode == "rules") {
			t.Errorf("%s: loopback went through the proxy = %v", mode, via)
		}
	}
}

// With sniffing on, a domain rule applies to a connection made by IP address: the
// name is read from the TLS ClientHello. With it off, the rule cannot match.
func TestIntegrationSniffingFeedsDomainRules(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	cert := newCert(t, t.TempDir())
	site := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "site") }))
	site.TLS = &tls.Config{Certificates: []tls.Certificate{cert.tlsCert}}
	site.StartTLS()
	t.Cleanup(site.Close)
	addr := site.Listener.Addr().String()

	s := models.DefaultSettings()
	s.RoutingMode, s.BlockAds = "rules", false
	s.RuleSets = []models.RuleSet{{ID: "a", Name: "a", Rules: []models.RouteRule{
		{ID: "1", Enabled: true, Entries: []string{"full:blocked.example"}, Outbound: "block"}}}}
	s.ActiveRuleSet = "a"
	// the proxy is never reached: everything that is not blocked goes direct
	dead := profile.Profile{Protocol: profile.SOCKS, Server: "127.0.0.1", Port: 1}
	reachable := func(sniffing bool) bool {
		s.Sniffing = sniffing
		socks := freePort(t)
		s.Inbounds = []models.Inbound{{Tag: "socks-in", Protocol: "socks", Port: socks, Listen: "127.0.0.1", Enabled: true}}
		s.RuleSets[0].Rules = append(s.RuleSets[0].Rules[:1:1], models.RouteRule{ID: "2", Enabled: true, Entries: []string{"127.0.0.0/8"}, Outbound: "direct"})
		b, err := BuildConfig(profile.Single(dead), s)
		if err != nil {
			t.Fatal(err)
		}
		startMihomo(t, b, socks)
		u := &url.URL{Scheme: "socks5h", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(socks))}
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{ServerName: "blocked.example", InsecureSkipVerify: true}}}
		resp, err := client.Get("https://" + addr + "/")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return true
	}
	if reachable(true) {
		t.Error("with sniffing on, the server name in the ClientHello did not trigger the block rule")
	}
	if !reachable(false) {
		t.Error("with sniffing off, the connection should not have been blocked")
	}
}

// The minimal config used for latency tests and "Test Connection".
func TestIntegrationProbeConfigCarriesTraffic(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	tgt := webTarget(t)
	exitPort := freePort(t)
	mihomoServer(t, "exit", exitPort, map[string]any{"type": "vmess", "users": []any{map[string]any{"username": "u", "uuid": testUUID, "alterId": 0}}})
	exit := profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: exitPort, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
	port := freePort(t)
	b, err := ProbeConfig(profile.Single(exit), port)
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, b, port)
	if body, err := viaSocks(t, port, "", "", tgt.URL); err != nil || body != "probe-ok" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}

// Mux is sing-mux: a sing-box server that offers it carries the connections, and
// one that does not refuses them, which shows the setting is really on the wire.
func TestIntegrationMuxIsSingMux(t *testing.T) {
	needBin(t, "KEYWAY_MIHOMO_BIN")
	needBin(t, "KEYWAY_SINGBOX_BIN")
	tgt := webTarget(t)
	exit := func(port int) profile.Profile {
		return profile.Profile{Protocol: profile.VMess, Server: "127.0.0.1", Port: port, UUID: testUUID, Cipher: "auto", Transport: profile.Transport{Type: "tcp"}}
	}
	server := func(mux bool) int {
		port := freePort(t)
		in := map[string]any{"type": "vmess", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]any{"uuid": testUUID}}}
		if mux {
			in["multiplex"] = map[string]any{"enabled": true}
		}
		singboxServer(t, port, in)
		return port
	}
	s := globalSettings(freePort(t))
	s.Mux, s.MuxConcurrency = true, 4
	b, err := BuildConfig(profile.Single(exit(server(true))), s)
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, b, s.Inbounds[0].Port)
	for i := 0; i < 3; i++ {
		if body, err := viaSocks(t, s.Inbounds[0].Port, "", "", tgt.URL); err != nil || body != "probe-ok" {
			t.Fatalf("request %d with a multiplexing server: %q, %v", i, body, err)
		}
	}
	s2 := globalSettings(freePort(t))
	s2.Mux, s2.MuxConcurrency = true, 4
	b, err = BuildConfig(profile.Single(exit(server(false))), s2)
	if err != nil {
		t.Fatal(err)
	}
	startMihomo(t, b, s2.Inbounds[0].Port)
	if body, err := viaSocks(t, s2.Inbounds[0].Port, "", "", tgt.URL); err == nil && body == "probe-ok" {
		t.Error("a server without multiplexing answered: the mux setting was dropped")
	}
}
