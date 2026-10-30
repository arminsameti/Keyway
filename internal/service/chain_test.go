package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

func ovpnProfile() profile.Profile {
	return profile.Profile{Protocol: profile.OpenVPN, Server: "vpn.example.com", Port: 1194, Transport: profile.Transport{Type: "udp"},
		OpenVPN: &profile.OpenVPNOpts{CA: "CA", Cert: "CERT", Key: "KEY"}}
}

func (e *twoEnv) server(t *testing.T, name string, p profile.Profile) string {
	t.Helper()
	v, err := e.svc.CreateNode(NodeInput{Name: name, Profile: &p})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v.ID
}

func (e *twoEnv) link(t *testing.T, raw string) string {
	t.Helper()
	return e.addNode(t, raw).ID
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestChainValidation(t *testing.T) {
	e := newTwoEngines(t, true)
	vless := e.link(t, "vless://u@a.example.net:443?security=tls#A")
	trojan := e.link(t, "trojan://p@b.example.net:443#B")
	ssh := e.server(t, "Jump", profile.Profile{Protocol: profile.SSH, Server: "j.example.net", Port: 22, Username: "root", Password: "pw"})
	wg := e.server(t, "Home WG", profile.Profile{Protocol: profile.WireGuard, Server: "wg.example.net", Port: 51820,
		WireGuard: &profile.WireGuardOpts{PrivateKey: "k", PeerPublicKey: "p", LocalAddress: []string{"10.7.0.2/32"}}})
	chain, err := e.svc.CreateNode(NodeInput{Chain: []string{vless, trojan}})
	if err != nil {
		t.Fatal(err)
	}

	bad := map[string]struct {
		in   NodeInput
		want string
	}{
		"one server":    {NodeInput{Chain: []string{vless}}, "at least two"},
		"unknown hop":   {NodeInput{Chain: []string{vless, "nope"}}, "no longer in your server list"},
		"nested chain":  {NodeInput{Chain: []string{vless, chain.ID}}, "itself a chain"},
		"udp after tcp": {NodeInput{Chain: []string{vless, ssh, wg}}, "cannot carry UDP"},
		"too long":      {NodeInput{Chain: append(make([]string, 0), strings.Split(strings.Repeat(vless+",", 17), ",")[:17]...)}, "at most"},
	}
	for name, c := range bad {
		_, err := e.svc.CreateNode(c.in)
		var ve *models.ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want a validation error containing %q, got %v", name, c.want, err)
		}
	}
	// the message names the offending hops
	_, err = e.svc.CreateNode(NodeInput{Chain: []string{vless, ssh, wg}})
	if err == nil || !strings.Contains(err.Error(), "Jump") || !strings.Contains(err.Error(), "Home WG") {
		t.Errorf("message must name the hops: %v", err)
	}
	// but a TCP-only hop may follow anything, and UDP may follow UDP-capable hops
	if _, err := e.svc.CreateNode(NodeInput{Chain: []string{wg, ssh, vless}}); err != nil {
		t.Errorf("wireguard -> ssh -> vless is fine: %v", err)
	}
	if _, err := e.svc.CreateNode(NodeInput{Chain: []string{vless, wg}}); err != nil {
		t.Errorf("vless -> wireguard is fine: %v", err)
	}
}

func TestChainNodeViewAndEditing(t *testing.T) {
	e := newTwoEngines(t, true)
	ovpn := e.server(t, "🇩🇪 Office VPN", ovpnProfile())
	vless := e.link(t, "vless://u@a.example.net:443?security=tls#Frankfurt")
	trojan := e.link(t, "trojan://p@b.example.net:443#Helsinki")

	v, err := e.svc.CreateNode(NodeInput{Chain: []string{ovpn, vless, trojan}})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Chain || v.Protocol != "chain" || v.ProtocolName != "Chain" || v.Transport != "3 hops" || v.Name != "🇩🇪 Office VPN → Helsinki" || v.CountryCode != "DE" {
		t.Fatalf("view: %+v", v)
	}
	if len(v.Hops) != 3 || v.Hops[0].Name != "Office VPN" || v.Hops[0].ProtocolName != "OpenVPN" || v.Hops[0].Transport != "UDP" || v.Hops[2].ProtocolName != "Trojan" {
		t.Fatalf("hops: %+v", v.Hops)
	}
	if v.Engine != "sing-box" || v.EngineName != "sing-box" || !v.EngineInstalled || v.Error != "" || v.HasLink {
		t.Fatalf("engine: %+v", v)
	}
	if _, err := e.svc.RawLink(v.ID); err == nil {
		t.Error("a chain has no share link")
	}

	// edit: reorder and rename, keeping the ID
	up, err := e.svc.UpdateNode(v.ID, NodeInput{Name: "Work", Chain: []string{ovpn, trojan}})
	if err != nil || up.ID != v.ID || up.Name != "Work" || len(up.Hops) != 2 {
		t.Fatalf("update: %v %+v", err, up)
	}
	if _, err := e.svc.UpdateNode(v.ID, NodeInput{Chain: []string{ovpn, v.ID}}); err == nil {
		t.Error("a chain cannot contain itself")
	}
	if _, err := e.svc.UpdateNode(vless, NodeInput{Chain: []string{ovpn, trojan}}); err == nil {
		t.Error("a plain server cannot be turned into a chain")
	}
	ed, err := e.svc.NodeForEdit(v.ID)
	if err != nil || ed.Profile != nil || strings.Join(ed.Chain, ",") != ovpn+","+trojan || ed.Name != "Work" {
		t.Fatalf("edit view: %+v %v", ed, err)
	}
	ed, err = e.svc.NodeForEdit(ovpn)
	if err != nil || ed.Profile == nil || ed.Profile.OpenVPN == nil || ed.Chain != nil {
		t.Fatalf("server edit view: %+v %v", ed, err)
	}

	// a deleted hop breaks the chain visibly instead of silently
	if _, err := e.svc.DeleteNodes(trojan); err != nil {
		t.Fatal(err)
	}
	for _, nv := range e.svc.Nodes() {
		if nv.ID == v.ID {
			if nv.Error == "" || !nv.Hops[1].Missing || !strings.Contains(nv.Error, "hop 2") {
				t.Fatalf("broken chain: %+v", nv)
			}
		}
	}
	_ = e.svc.SetActive(v.ID)
	if _, err := e.svc.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "hop 2") {
		t.Fatalf("connecting a broken chain must say which hop: %v", err)
	}
}

func TestChainOnOneEngine(t *testing.T) {
	e := newTwoEngines(t, true)
	a := e.link(t, "vless://u@a.example.net:443?security=tls#A")
	b := e.link(t, "trojan://p@b.example.net:443#B")
	c, err := e.svc.CreateNode(NodeInput{Name: "Two", Chain: []string{a, b}})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.svc.SetActive(c.ID)
	if _, err := e.svc.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := e.svc.Status()
	if !st.Running || st.Engine != "xray" || st.EngineLabel != "Xray core" || st.ActiveNode != "Two" || st.Protocol != "Chain" || st.Transport != "2 hops" {
		t.Fatalf("status: %+v", st)
	}
	cfg, _ := os.ReadFile(filepath.Join(e.dir, "config.json"))
	for _, w := range []string{`"dialerProxy": "hop-0"`, `"tag": "proxy"`, `"tag": "hop-0"`} {
		if !strings.Contains(string(cfg), w) {
			t.Errorf("config lacks %s:\n%s", w, cfg)
		}
	}
	if left, _ := filepath.Glob(filepath.Join(e.dir, "config-segment-*.json")); len(left) != 0 {
		t.Errorf("a one-process chain writes no segment configs: %v", left)
	}
	if err := e.svc.Disconnect(context.Background()); err != nil || e.svc.Status().Running {
		t.Fatalf("disconnect: %v", err)
	}
}

// OpenVPN only runs on sing-box, XHTTP only on Xray: two processes, joined by a bridge.
func TestChainAcrossEngines(t *testing.T) {
	e := newTwoEngines(t, true)
	ovpn := e.server(t, "Office", ovpnProfile())
	xh := e.link(t, "vless://u@x.example.net:443?type=xhttp&path=/x&security=tls#XHTTP")
	exit := e.link(t, "trojan://p@t.example.net:443#Exit")
	c, err := e.svc.CreateNode(NodeInput{Name: "Mixed", Chain: []string{ovpn, xh, exit}})
	if err != nil {
		t.Fatal(err)
	}
	if c.EngineName != "sing-box + Xray core" || c.Engine != "xray" {
		t.Fatalf("plan: engine=%q name=%q", c.Engine, c.EngineName)
	}
	_ = e.svc.SetActive(c.ID)
	if _, err := e.svc.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	st := e.svc.Status()
	if !st.Running || st.Engine != "xray" || st.EngineLabel != "sing-box + Xray core" {
		t.Fatalf("status: %+v", st)
	}

	// the entry process listens on a password-protected loopback bridge; the exit process dials it
	seg, err := os.ReadFile(filepath.Join(e.dir, "config-segment-0.json"))
	if err != nil {
		t.Fatal("the entry segment's config must exist:", err)
	}
	last, _ := os.ReadFile(filepath.Join(e.dir, "config.json"))
	for _, w := range []string{`"type": "openvpn-client"`, `"tag": "bridge-in"`, `"listen": "127.0.0.1"`, `"username"`} {
		if !strings.Contains(string(seg), w) {
			t.Errorf("entry segment lacks %s:\n%s", w, seg)
		}
	}
	for _, w := range []string{`"dialerProxy": "bridge"`, `"protocol": "socks"`, `"address": "127.0.0.1"`, `"tag": "socks-in"`} {
		if !strings.Contains(string(last), w) {
			t.Errorf("last segment lacks %s:\n%s", w, last)
		}
	}
	if strings.Contains(string(seg), "socks-in") {
		t.Error("the entry segment must not serve the user's ports")
	}
	logs, _, _ := e.svc.Logs(0)
	var sawSegment bool
	for _, l := range logs {
		sawSegment = sawSegment || strings.Contains(l, "[hop 1–1 · sing-box]")
	}
	if !sawSegment {
		t.Errorf("the entry segment's output must be in the activity log, prefixed: %v", logs)
	}

	e.svc.extraMu.Lock()
	n := len(e.svc.extra)
	e.svc.extraMu.Unlock()
	if n != 1 {
		t.Fatalf("one earlier process, got %d", n)
	}
	if err := e.svc.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.svc.extraMu.Lock()
	n = len(e.svc.extra)
	e.svc.extraMu.Unlock()
	if e.svc.Status().Running || n != 0 {
		t.Fatalf("disconnect must stop every process (running=%v extra=%d)", e.svc.Status().Running, n)
	}
	// reconnecting must not leave the old segment config behind or reuse a stale bridge
	if _, err := e.svc.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	seg2, _ := os.ReadFile(filepath.Join(e.dir, "config-segment-0.json"))
	if string(seg2) == string(seg) {
		t.Error("a new connection must use new bridge credentials")
	}
}

func TestDeadSegmentTakesTheChainDown(t *testing.T) {
	e := newTwoEngines(t, true)
	ovpn := e.server(t, "Office", ovpnProfile())
	xh := e.link(t, "vless://u@x.example.net:443?type=xhttp&path=/x&security=tls#XHTTP")
	c, err := e.svc.CreateNode(NodeInput{Chain: []string{ovpn, xh}})
	if err != nil {
		t.Fatal(err)
	}
	_ = e.svc.SetActive(c.ID)
	if err := os.WriteFile(filepath.Join(e.sbDir, "crash"), nil, 0o644); err != nil { // sing-box dies 2.4 s after start, after Connect has returned
		t.Fatal(err)
	}
	if _, err := e.svc.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the chain to stop after its entry segment died", func() bool { return !e.svc.Status().Running })
	waitUntil(t, "the system proxy to be dropped", func() bool { return len(e.svc.Status().SystemProxy) == 0 })
}

func TestChainPreflightFailureKeepsTheRunningConnection(t *testing.T) {
	e := newTwoEngines(t, true)
	good := e.link(t, "trojan://p@b.example.net:443#Good")
	_ = e.svc.SetActive(good)
	if _, err := e.svc.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	ovpn := e.server(t, "Office", ovpnProfile())
	exit := e.link(t, "vless://u@a.example.net:443?security=tls#Exit")
	c, _ := e.svc.CreateNode(NodeInput{Chain: []string{ovpn, exit}})
	_ = e.svc.SetActive(c.ID)
	if err := os.WriteFile(filepath.Join(e.sbDir, "reject"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "sing-box rejected the configuration") {
		t.Fatalf("want the preflight error, got %v", err)
	}
	if st := e.svc.Status(); !st.Running || st.ActiveNode != "Good" && st.Engine != "xray" {
		t.Fatalf("the working connection must survive a bad chain: %+v", st)
	}
}

func TestOpenVPNImportPreview(t *testing.T) {
	e := newTwoEngines(t, true)
	text := "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nremote-cert-tls server\n<ca>\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n</ca>\n" +
		"<cert>\n-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\nCCC\n-----END PRIVATE KEY-----\n</key>\n"
	pv := e.svc.PreviewImport(text)
	if pv.Ready != 1 || len(pv.Items) != 1 {
		t.Fatalf("preview: %+v", pv)
	}
	it := pv.Items[0]
	if it.Protocol != "OpenVPN" || it.Transport != "UDP" || it.Engine != "sing-box" || it.Name != "OpenVPN vpn.example.com" {
		t.Fatalf("item: %+v", it)
	}
	res, err := e.svc.Import(context.Background(), text, "")
	if err != nil || res.Added != 1 {
		t.Fatalf("import: %+v %v", res, err)
	}
	var v NodeView
	for _, nv := range e.svc.Nodes() {
		v = nv
	}
	if v.Protocol != "openvpn" || v.HasLink || v.Engine != "sing-box" || !v.UDP {
		t.Fatalf("node: %+v", v)
	}
	// Xray is not offered OpenVPN, and a sing-box build without it says so
	if err := (&twoEnv{env: e.env}).svc.engines[0].Engine.Supports(ovpnProfile()); err == nil {
		t.Error("Xray cannot run OpenVPN")
	}
}

func TestChainProbeTimeoutGrowsWithHops(t *testing.T) {
	if chainProbeTimeout(2) <= proxyTimeout || chainProbeTimeout(3) <= chainProbeTimeout(2) {
		t.Fatalf("each extra hop needs more time: %v %v", chainProbeTimeout(2), chainProbeTimeout(3))
	}
	if chainProbeTimeout(profile.MaxChainHops) != 45*time.Second {
		t.Fatalf("capped: %v", chainProbeTimeout(profile.MaxChainHops))
	}
}

func TestOverridesAreSavedValidatedAndReachTheConfig(t *testing.T) {
	e := newTwoEngines(t, true)
	yes := true
	p := profile.Profile{Protocol: profile.Trojan, Server: "b.example.net", Port: 443, Password: "p", Transport: profile.Transport{Type: "tcp"},
		Security: profile.Security{Kind: "tls", SNI: "b.example.net"}}
	v, err := e.svc.CreateNode(NodeInput{Name: "T", Profile: &p, Overrides: &profile.Overrides{Mux: &yes, SNI: "front.example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Overrides == nil || v.Overrides.SNI != "front.example.net" {
		t.Fatalf("overrides not stored: %+v", v.Overrides)
	}
	ev, err := e.svc.NodeForEdit(v.ID)
	if err != nil || ev.Overrides == nil || ev.Overrides.Mux == nil || !*ev.Overrides.Mux {
		t.Fatalf("edit view lost the overrides: %+v %v", ev, err)
	}
	d := e.svc.store.Get()
	hops, _, err := e.svc.resolveHops(d, d.Nodes[0])
	if err != nil || hops[0].Security.SNI != "front.example.net" || hops[0].Overrides == nil {
		t.Fatalf("connect must see the overridden server name: %+v %v", hops, err)
	}

	// refused: fragmentation on a plain server
	plain := profile.Profile{Protocol: profile.Shadowsocks, Server: "s.example.net", Port: 8388, Cipher: "aes-128-gcm", Password: "pw"}
	if _, err := e.svc.CreateNode(NodeInput{Name: "S", Profile: &plain, Overrides: &profile.Overrides{Fragment: &profile.Fragment{}}}); err == nil {
		t.Error("fragmentation needs TLS")
	}
	// clearing: an update with no overrides removes them
	up, err := e.svc.UpdateNode(v.ID, NodeInput{Name: "T", Profile: &p})
	if err != nil || up.Overrides != nil {
		t.Errorf("update without overrides must clear them: %+v %v", up.Overrides, err)
	}
}

func TestCustomServerIsSavedPlannedAndNeverChained(t *testing.T) {
	e := newTwoEngines(t, true)
	cfg := `{"tag":"x","protocol":"trojan","settings":{"servers":[{"address":"c.example.net","port":8443,"password":"pw"}]}}`
	v, err := e.svc.CreateNode(NodeInput{Name: "Mine", Profile: &profile.Profile{Protocol: profile.Custom, Custom: &profile.CustomOpts{Engine: "xray", Config: cfg}}})
	if err != nil {
		t.Fatal(err)
	}
	if v.Protocol != profile.Custom || v.ProtocolName != "Custom" || v.Server != "c.example.net" || v.Port != 8443 || v.Engine != "xray" {
		t.Fatalf("view = %+v", v)
	}
	ev, err := e.svc.NodeForEdit(v.ID)
	if err != nil || ev.Profile == nil || ev.Profile.Custom == nil || ev.Profile.Custom.Config != cfg {
		t.Fatalf("edit view: %+v %v", ev, err)
	}
	other := e.link(t, "vless://u@a.example.net:443?security=tls#A")
	if _, err := e.svc.CreateNode(NodeInput{Chain: []string{other, v.ID}}); err == nil || !strings.Contains(err.Error(), "cannot be part of a chain") {
		t.Errorf("custom in a chain: %v", err)
	}
	if _, err := e.svc.CreateNode(NodeInput{Name: "Bad", Profile: &profile.Profile{Protocol: profile.Custom, Custom: &profile.CustomOpts{Engine: "xray", Config: "nope"}}}); err == nil {
		t.Error("invalid JSON must be refused")
	}
}
