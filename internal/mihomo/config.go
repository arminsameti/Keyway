package mihomo

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"keyway/internal/models"
	"keyway/internal/profile"
)

var defaultDNS = []string{"1.1.1.1", "8.8.8.8", "localhost"}

// bridgeTag is the proxy that reaches the previous segment's bridge.
const bridgeTag = "bridge"

func hopTag(i, n int) string {
	if i == n-1 {
		return "proxy" // the exit hop: the routing rules' target
	}
	return fmt.Sprintf("hop-%d", i)
}

// BuildConfig renders the Mihomo configuration of one segment. The last segment
// of a chain carries the user's inbounds and routing; a segment with Listen set
// is a middle segment and only exposes its exit on that bridge.
func BuildConfig(seg profile.Segment, s models.Settings) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if seg.TUN != nil {
		return nil, fmt.Errorf("a TUN interface needs sing-box")
	}
	proxies, err := segmentProxies(seg)
	if err != nil {
		return nil, err
	}
	cfg := base(logLevel(s.LogLevel))
	cfg.Proxies = proxies
	if seg.Listen != nil {
		cfg.Listeners = []Listener{bridgeListener(*seg.Listen)}
		cfg.Rules = []string{"MATCH,proxy"}
		return render(cfg)
	}
	exit := seg.Hops[len(seg.Hops)-1]
	if on, conc := muxFor(s, exit); on && muxCapable(exit) {
		last := &cfg.Proxies[len(cfg.Proxies)-1]
		last.SMux = &SMux{Enabled: true, Protocol: "h2mux", MaxStreams: conc}
	}
	servers, err := dnsServers(s)
	if err != nil {
		return nil, err
	}
	if cfg.DNS, err = dnsConfig(servers); err != nil {
		return nil, err
	}
	if s.Sniffing {
		cfg.Sniffer = &Sniffer{Enable: true, Sniff: map[string]SniffProtocol{
			"HTTP": {Ports: []string{"1-65535"}}, "TLS": {Ports: []string{"1-65535"}}, "QUIC": {Ports: []string{"1-65535"}},
		}}
	}
	for _, ib := range s.Inbounds {
		if !ib.Enabled {
			continue
		}
		l := Listener{Name: ib.Tag, Type: ib.Protocol, Listen: s.EffectiveListen(ib), Port: ib.Port}
		if ib.Protocol == "socks" {
			l.UDP = ib.UDP
		}
		if ib.Username != "" {
			l.Users = []User{{Username: ib.Username, Password: ib.Password}}
		}
		cfg.Listeners = append(cfg.Listeners, l)
	}
	if cfg.Rules, err = buildRules(s); err != nil {
		return nil, err
	}
	if st := seg.Stats; st != nil {
		if st.Secret == "" {
			return nil, fmt.Errorf("internal error: the Mihomo controller needs a secret")
		}
		cfg.ExternalController = net.JoinHostPort("127.0.0.1", strconv.Itoa(st.Port))
		cfg.Secret = st.Secret
	}
	return render(cfg)
}

// ProbeConfig renders a minimal config for measuring: a middle segment exposes
// its bridge, the last segment a SOCKS inbound on 127.0.0.1:port.
func ProbeConfig(seg profile.Segment, port int) ([]byte, error) {
	proxies, err := segmentProxies(seg)
	if err != nil {
		return nil, err
	}
	cfg := base("silent")
	cfg.Proxies = proxies
	cfg.Rules = []string{"MATCH,proxy"}
	if seg.Listen != nil {
		cfg.Listeners = []Listener{bridgeListener(*seg.Listen)}
	} else {
		cfg.Listeners = []Listener{{Name: "probe", Type: "socks", Listen: "127.0.0.1", Port: port}}
	}
	return render(cfg)
}

func render(cfg *Config) ([]byte, error) {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return b, nil
}

// base is everything a configuration has in common. Geodata downloads are
// pointed at a closed port: Keyway fetches and verifies the files itself, so a
// file that is missing fails the check instead of being fetched unverified.
func base(level string) *Config {
	dead := "http://127.0.0.1:1/"
	return &Config{
		Mode: "rule", LogLevel: level, IPv6: true, FindProcess: "off",
		GeoAutoUpdate: false, GeodataMode: false,
		GeoxURL: GeoxURL{GeoIP: dead + "geoip.metadb", MMDB: dead + "country.mmdb", GeoSite: dead + "geosite.dat", ASN: dead + "asn.mmdb"},
	}
}

func logLevel(l string) string {
	if l == "none" {
		return "silent"
	}
	return l
}

func bridgeListener(b profile.Bridge) Listener {
	return Listener{Name: "bridge-in", Type: "socks", Listen: "127.0.0.1", Port: b.Port, Users: []User{{Username: b.User, Password: b.Pass}}}
}

// muxFor resolves multiplexing for the exit server: its own override, else the global setting.
func muxFor(s models.Settings, exit profile.Profile) (bool, int) {
	on, conc := s.Mux, s.MuxConcurrency
	if o := exit.Overrides; o != nil {
		if o.Mux != nil {
			on = *o.Mux
		}
		if o.MuxConcurrency > 0 {
			conc = o.MuxConcurrency
		}
	}
	return on, conc
}

func muxCapable(p profile.Profile) bool {
	switch p.Protocol {
	case profile.VLESS, profile.VMess, profile.Trojan, profile.Shadowsocks:
	default:
		return false
	}
	return p.Flow == "" && p.Transport.Type != "grpc" && p.Transport.Type != "h2"
}

// dnsServers is the resolver list the DNS settings amount to. Mihomo cannot keep
// a separate direct resolver for the bypassed domains, and refuses it rather
// than run with the setting dropped.
func dnsServers(s models.Settings) ([]string, error) {
	plan, err := s.DNSPlan()
	if err != nil {
		return nil, err
	}
	if plan.Direct != nil {
		return nil, fmt.Errorf("Mihomo cannot keep a separate direct DNS server; Xray core or sing-box can")
	}
	if plan.Mode == models.DNSModeDefault {
		return s.DNS, nil
	}
	out := make([]string, 0, len(plan.Servers))
	for _, d := range plan.Servers {
		out = append(out, d.String())
	}
	return out, nil
}

// dnsConfig maps Keyway's resolver list onto Mihomo's. Plain addresses and
// udp/tcp/tls/https URLs carry over, "localhost" is the system resolver; the
// bootstrap resolvers (they must be addresses) are the plain addresses of the
// list, or the system resolver when there are none.
func dnsConfig(servers []string) (*DNS, error) {
	if len(servers) == 0 {
		servers = defaultDNS
	}
	d := &DNS{Enable: true, IPv6: true}
	for _, sv := range servers {
		switch {
		case sv == "localhost":
			d.Nameserver = append(d.Nameserver, "system")
		case isAddr(sv):
			d.Nameserver = append(d.Nameserver, sv)
			d.DefaultNameserver = append(d.DefaultNameserver, sv)
		default:
			scheme, _, ok := strings.Cut(sv, "://")
			switch scheme {
			case "udp", "tcp", "tls", "https":
			default:
				ok = false
			}
			if !ok {
				return nil, fmt.Errorf("the DNS server %q is not one Mihomo runs here (use an address or a udp://, tcp://, tls:// or https:// URL)", sv)
			}
			d.Nameserver = append(d.Nameserver, sv)
		}
	}
	if len(d.DefaultNameserver) == 0 {
		d.DefaultNameserver = []string{"system"}
	}
	return d, nil
}

func isAddr(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// ---- proxies ----

// segmentProxies renders the hops of a segment, each dialing through the one
// before it; the first dials through the upstream bridge when there is one.
func segmentProxies(seg profile.Segment) ([]Proxy, error) {
	if len(seg.Hops) == 0 {
		return nil, fmt.Errorf("a segment needs at least one hop")
	}
	if err := SupportsSegment(seg.Hops, seg.Upstream != nil); err != nil {
		return nil, err
	}
	var out []Proxy
	dialer := ""
	if u := seg.Upstream; u != nil {
		out = append(out, Proxy{Name: bridgeTag, Type: "socks5", Server: "127.0.0.1", Port: u.Port, Username: u.User, Password: u.Pass})
		dialer = bridgeTag
	}
	n := len(seg.Hops)
	for i, h := range seg.Hops {
		if err := h.Validate(); err != nil {
			return nil, err
		}
		tag := hopTag(i, n)
		px, err := proxyFor(h, tag)
		if err != nil {
			return nil, err
		}
		px.DialerProxy = dialer
		out = append(out, px)
		dialer = tag
	}
	return out, nil
}

func tlsOn(p profile.Profile) bool { return p.Security.Kind == "tls" || p.Security.Kind == "reality" }

// tlsFields fills the certificate checks every TLS-capable proxy shares.
func tlsFields(px *Proxy, p profile.Profile) {
	px.ALPN = p.Security.ALPN
	px.Insecure = p.Security.Insecure
	if pin := p.Security.PinSHA256; pin != "" {
		px.Pin = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
	}
}

func proxyFor(p profile.Profile, name string) (Proxy, error) {
	px := Proxy{Name: name, Server: p.Server, Port: p.Port}
	switch p.Protocol {
	case profile.VLESS:
		px.Type, px.UUID, px.Flow, px.UDP = "vless", p.UUID, p.Flow, true
		streamFields(&px, p)
	case profile.VMess:
		zero := p.AlterID
		cipher := p.Cipher
		if cipher == "" {
			cipher = "auto"
		}
		px.Type, px.UUID, px.AlterID, px.Cipher, px.UDP = "vmess", p.UUID, &zero, cipher, true
		streamFields(&px, p)
	case profile.Trojan:
		px.Type, px.Password, px.UDP = "trojan", p.Password, true
		streamFields(&px, p)
	case profile.Shadowsocks:
		px.Type, px.Cipher, px.Password, px.UDP = "ss", ssCiphers[p.Cipher], p.Password, true
	case profile.SOCKS:
		px.Type, px.Username, px.Password, px.UDP = "socks5", p.Username, p.Password, true
		if tlsOn(p) {
			px.TLS = true
			tlsFields(&px, p)
		}
	case profile.HTTP:
		px.Type, px.Username, px.Password = "http", p.Username, p.Password
		if tlsOn(p) {
			px.TLS, px.SNI = true, p.Security.SNI
			tlsFields(&px, p)
		}
	case profile.Hysteria2:
		px.Type, px.Password, px.SNI = "hysteria2", p.Password, p.Security.SNI
		tlsFields(&px, p)
		if h := p.Hysteria; h != nil {
			if h.UpMbps > 0 {
				px.Up = fmt.Sprintf("%d Mbps", h.UpMbps)
			}
			if h.DownMbps > 0 {
				px.Down = fmt.Sprintf("%d Mbps", h.DownMbps)
			}
			px.Obfs, px.ObfsPassword = h.Obfs, h.ObfsPassword
		}
	case profile.TUIC:
		px.Type, px.UUID, px.Password, px.SNI = "tuic", p.UUID, p.Password, p.Security.SNI
		tlsFields(&px, p)
		if t := p.TUIC; t != nil {
			px.Congestion, px.UDPRelay, px.ReduceRTT = t.CongestionControl, t.UDPRelayMode, t.ZeroRTT
		}
	case profile.AnyTLS:
		px.Type, px.Password, px.SNI, px.UDP = "anytls", p.Password, p.Security.SNI, true
		tlsFields(&px, p)
		px.ClientFP = p.Security.Fingerprint
		if a := p.AnyTLS; a != nil {
			px.IdleTimeout = a.IdleTimeoutSec
		}
	case profile.WireGuard:
		w := p.WireGuard
		px.Type, px.UDP = "wireguard", true
		px.IP, px.IPv6 = localAddresses(w.LocalAddress)
		px.PrivateKey, px.PublicKey, px.PreSharedKey = w.PrivateKey, w.PeerPublicKey, w.PreSharedKey
		px.AllowedIPs = w.AllowedIPs
		if len(px.AllowedIPs) == 0 {
			px.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
		}
		px.MTU, px.Keepalive = w.MTU, w.Keepalive
	default:
		return px, fmt.Errorf("%s needs Xray core or sing-box", profile.ProtocolName(p.Protocol))
	}
	return px, nil
}

// streamFields sets the transport and TLS of VLESS, VMess and Trojan.
func streamFields(px *Proxy, p profile.Profile) {
	t := p.Transport
	switch t.Type {
	case "ws":
		px.Network = "ws"
		px.WS = &WSOpts{Path: orDefault(t.Path, "/")}
		if t.Host != "" {
			px.WS.Headers = map[string]string{"Host": t.Host}
		}
	case "httpupgrade":
		px.Network = "ws"
		px.WS = &WSOpts{Path: orDefault(t.Path, "/"), Upgrade: true}
		if t.Host != "" {
			px.WS.Headers = map[string]string{"Host": t.Host}
		}
	case "grpc":
		px.Network = "grpc"
		px.GRPC = &GRPCOpts{ServiceName: t.ServiceName}
	case "h2":
		px.Network = "h2"
		px.H2 = &H2Opts{Path: orDefault(t.Path, "/")}
		for _, h := range strings.Split(t.Host, ",") {
			if h = strings.TrimSpace(h); h != "" {
				px.H2.Host = append(px.H2.Host, h)
			}
		}
	}
	if p.Protocol == profile.Trojan { // always TLS
		px.SNI = p.Security.SNI
		tlsFields(px, p)
		px.ClientFP = p.Security.Fingerprint
		return
	}
	if !tlsOn(p) {
		return
	}
	px.TLS, px.ServerName = true, p.Security.SNI
	tlsFields(px, p)
	px.ClientFP = p.Security.Fingerprint
	if p.Security.Kind == "reality" {
		px.Reality = &RealityOpts{PublicKey: p.Security.PublicKey, ShortID: p.Security.ShortID, MLKEM: true}
		px.Insecure, px.Pin, px.ALPN = false, "", nil
		if px.ClientFP == "" {
			px.ClientFP = "chrome" // Reality needs a browser hello
		}
	}
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
