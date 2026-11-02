package mihomo

// Config is the Mihomo configuration file. Mihomo skips keys it does not know
// without a word, so every key here was checked against the field tags of
// Mihomo v1.19.33 and TestOnlyKnownKeysAreEmitted lists them.
type Config struct {
	Mode          string  `yaml:"mode"`
	LogLevel      string  `yaml:"log-level"`
	IPv6          bool    `yaml:"ipv6"`
	FindProcess   string  `yaml:"find-process-mode"`
	GeodataMode   bool    `yaml:"geodata-mode"`
	GeoAutoUpdate bool    `yaml:"geo-auto-update"`
	GeoxURL       GeoxURL `yaml:"geox-url"`

	ExternalController string `yaml:"external-controller,omitempty"`
	Secret             string `yaml:"secret,omitempty"`

	DNS       *DNS       `yaml:"dns,omitempty"`
	Sniffer   *Sniffer   `yaml:"sniffer,omitempty"`
	Listeners []Listener `yaml:"listeners"`
	Proxies   []Proxy    `yaml:"proxies"`
	Rules     []string   `yaml:"rules"`
}

// GeoxURL are the places Mihomo downloads geodata from when a file is missing.
// They all point at a closed loopback port: Keyway fetches the files itself,
// verified, and a missing one must fail the check instead of reaching out.
type GeoxURL struct {
	GeoIP   string `yaml:"geoip"`
	MMDB    string `yaml:"mmdb"`
	GeoSite string `yaml:"geosite"`
	ASN     string `yaml:"asn"`
}

// DNS is the resolver Mihomo uses for rule matching and for its own dialing. It
// opens no listener.
type DNS struct {
	Enable            bool     `yaml:"enable"`
	IPv6              bool     `yaml:"ipv6"`
	DefaultNameserver []string `yaml:"default-nameserver"`
	Nameserver        []string `yaml:"nameserver"`
}

// Sniffer reads the destination name out of the first bytes of a connection,
// for routing rules.
type Sniffer struct {
	Enable bool                     `yaml:"enable"`
	Sniff  map[string]SniffProtocol `yaml:"sniff"`
}

// SniffProtocol is one protocol the sniffer looks for.
type SniffProtocol struct {
	Ports []string `yaml:"ports"`
}

// Listener is one inbound.
type Listener struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Listen string `yaml:"listen"`
	Port   int    `yaml:"port"`
	UDP    bool   `yaml:"udp,omitempty"`
	Users  []User `yaml:"users,omitempty"`
}

// User is one inbound account.
type User struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// Proxy is one outbound. Mihomo reads the fields that fit its type.
type Proxy struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`

	Server string `yaml:"server,omitempty"`
	Port   int    `yaml:"port,omitempty"`

	UUID     string `yaml:"uuid,omitempty"`
	AlterID  *int   `yaml:"alterId,omitempty"` // VMess requires the key, even at 0
	Cipher   string `yaml:"cipher,omitempty"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	Flow     string `yaml:"flow,omitempty"`
	Encrypt  string `yaml:"encryption,omitempty"`
	UDP      bool   `yaml:"udp,omitempty"`

	Network    string   `yaml:"network,omitempty"`
	TLS        bool     `yaml:"tls,omitempty"`
	ServerName string   `yaml:"servername,omitempty"` // vless, vmess
	SNI        string   `yaml:"sni,omitempty"`        // trojan, http, hysteria2, tuic, anytls
	ALPN       []string `yaml:"alpn,omitempty"`
	Insecure   bool     `yaml:"skip-cert-verify,omitempty"`
	Pin        string   `yaml:"fingerprint,omitempty"`        // certificate SHA-256
	ClientFP   string   `yaml:"client-fingerprint,omitempty"` // uTLS browser hello

	Reality *RealityOpts `yaml:"reality-opts,omitempty"`
	WS      *WSOpts      `yaml:"ws-opts,omitempty"`
	GRPC    *GRPCOpts    `yaml:"grpc-opts,omitempty"`
	H2      *H2Opts      `yaml:"h2-opts,omitempty"`
	SMux    *SMux        `yaml:"smux,omitempty"`

	DialerProxy string `yaml:"dialer-proxy,omitempty"`

	// Hysteria2
	Up           string `yaml:"up,omitempty"`
	Down         string `yaml:"down,omitempty"`
	Obfs         string `yaml:"obfs,omitempty"`
	ObfsPassword string `yaml:"obfs-password,omitempty"`

	// TUIC
	Congestion string `yaml:"congestion-controller,omitempty"`
	UDPRelay   string `yaml:"udp-relay-mode,omitempty"`
	ReduceRTT  bool   `yaml:"reduce-rtt,omitempty"`

	// AnyTLS
	IdleTimeout int `yaml:"idle-session-timeout,omitempty"`

	// WireGuard
	IP           string   `yaml:"ip,omitempty"`
	IPv6         string   `yaml:"ipv6,omitempty"`
	PrivateKey   string   `yaml:"private-key,omitempty"`
	PublicKey    string   `yaml:"public-key,omitempty"`
	PreSharedKey string   `yaml:"pre-shared-key,omitempty"`
	AllowedIPs   []string `yaml:"allowed-ips,omitempty"`
	MTU          int      `yaml:"mtu,omitempty"`
	Keepalive    int      `yaml:"persistent-keepalive,omitempty"`
}

// RealityOpts are the Reality parameters of a VLESS server.
type RealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id,omitempty"`
	MLKEM     bool   `yaml:"support-x25519mlkem768,omitempty"`
}

// WSOpts is the WebSocket transport (and HTTPUpgrade, which Mihomo runs as a
// flavour of it).
type WSOpts struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
	Upgrade bool              `yaml:"v2ray-http-upgrade,omitempty"`
}

// GRPCOpts is the gRPC transport.
type GRPCOpts struct {
	ServiceName string `yaml:"grpc-service-name"`
}

// H2Opts is the HTTP/2 transport.
type H2Opts struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

// SMux is sing-mux multiplexing, the protocol sing-box servers speak. It is not
// Xray's mux.
type SMux struct {
	Enabled    bool   `yaml:"enabled"`
	Protocol   string `yaml:"protocol"`
	MaxStreams int    `yaml:"max-streams,omitempty"`
}
