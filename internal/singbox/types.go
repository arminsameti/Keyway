// Package singbox builds sing-box (1.12+) configurations from engine-neutral
// profiles. Like package xray it only produces data; running the binary is the
// engine package's job.
package singbox

import "encoding/json"

// Config is the subset of the sing-box configuration this app generates.
type Config struct {
	Log       Log        `json:"log"`
	DNS       *DNS       `json:"dns,omitempty"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Endpoints []any      `json:"endpoints,omitempty"` // Endpoint (WireGuard) or OpenVPNEndpoint
	Route     Route      `json:"route"`

	Experimental *Experimental `json:"experimental,omitempty"`
}

// Experimental carries the Clash-compatible API used to read traffic counters.
type Experimental struct {
	ClashAPI *ClashAPI `json:"clash_api,omitempty"`
}

type ClashAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret,omitempty"`
}

type Log struct {
	Disabled bool   `json:"disabled,omitempty"`
	Level    string `json:"level,omitempty"`
}

type DNS struct {
	Servers []DNSServer `json:"servers"`
	Final   string      `json:"final,omitempty"`
}

type DNSServer struct {
	Type       string `json:"type"` // udp tcp tls https local
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Path       string `json:"path,omitempty"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Inbound struct {
	Type       string `json:"type"` // socks http
	Tag        string `json:"tag"`
	Listen     string `json:"listen,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	Users      []User `json:"users,omitempty"`

	// tun
	Address     []string `json:"address,omitempty"`
	AutoRoute   bool     `json:"auto_route,omitempty"`
	StrictRoute bool     `json:"strict_route,omitempty"`
	Stack       string   `json:"stack,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
}

// Outbound is the union of the outbound fields this app uses; unused ones are omitted.
type Outbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Detour     string `json:"detour,omitempty"`

	UUID        string `json:"uuid,omitempty"`
	Flow        string `json:"flow,omitempty"`
	Security    string `json:"security,omitempty"` // vmess cipher
	AlterID     int    `json:"alter_id,omitempty"`
	Method      string `json:"method,omitempty"`
	Username    string `json:"username,omitempty"`
	User        string `json:"user,omitempty"` // ssh
	Password    string `json:"password,omitempty"`
	AuthStr     string `json:"auth_str,omitempty"`
	Version     any    `json:"version,omitempty"` // socks "5", shadowtls 3
	UpMbps      int    `json:"up_mbps,omitempty"`
	DownMbps    int    `json:"down_mbps,omitempty"`
	Obfs        any    `json:"obfs,omitempty"` // hysteria2 {type,password}; hysteria string
	Congestion  string `json:"congestion_control,omitempty"`
	UDPRelay    string `json:"udp_relay_mode,omitempty"`
	ZeroRTT     bool   `json:"zero_rtt_handshake,omitempty"`
	IdleTimeout string `json:"idle_session_timeout,omitempty"`

	PrivateKeyPath string            `json:"private_key_path,omitempty"`
	PrivateKey     string            `json:"private_key,omitempty"`
	Passphrase     string            `json:"private_key_passphrase,omitempty"`
	HostKey        []string          `json:"host_key,omitempty"`
	ExtraHeaders   map[string]string `json:"extra_headers,omitempty"`

	TLS       *TLS       `json:"tls,omitempty"`
	Transport *Transport `json:"transport,omitempty"`
	Multiplex *Multiplex `json:"multiplex,omitempty"`

	// Raw, when set, is the whole outbound as written by the user (a custom server).
	Raw json.RawMessage `json:"-"`
}

func (o Outbound) MarshalJSON() ([]byte, error) {
	if o.Raw != nil {
		return o.Raw, nil
	}
	type plain Outbound
	return json.Marshal(plain(o))
}

type Hy2Obfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type TLS struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	UTLS       *UTLS    `json:"utls,omitempty"`
	Reality    *Reality `json:"reality,omitempty"`
	Fragment   bool     `json:"fragment,omitempty"` // split the ClientHello (sing-box 1.12+)
}

type UTLS struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint"`
}

type Reality struct {
	Enabled   bool   `json:"enabled"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id,omitempty"`
}

type Transport struct {
	Type        string            `json:"type"` // ws grpc http httpupgrade
	Path        string            `json:"path,omitempty"`
	Host        any               `json:"host,omitempty"` // string (httpupgrade) or []string (http)
	Headers     map[string]string `json:"headers,omitempty"`
	ServiceName string            `json:"service_name,omitempty"`
}

type Multiplex struct {
	Enabled    bool `json:"enabled"`
	MaxStreams int  `json:"max_streams,omitempty"`
}

// Endpoint is a WireGuard endpoint (sing-box 1.11+ replaced the outbound).
type Endpoint struct {
	Type       string   `json:"type"`
	Tag        string   `json:"tag"`
	Detour     string   `json:"detour,omitempty"`
	Address    []string `json:"address"`
	PrivateKey string   `json:"private_key"`
	MTU        int      `json:"mtu,omitempty"`
	Peers      []Peer   `json:"peers"`
}

type Peer struct {
	Address      string   `json:"address"`
	Port         int      `json:"port"`
	PublicKey    string   `json:"public_key"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Keepalive    int      `json:"persistent_keepalive_interval,omitempty"` // seconds
	Reserved     []int    `json:"reserved,omitempty"`
}

type Route struct {
	Rules                 []Rule    `json:"rules"`
	RuleSet               []RuleSet `json:"rule_set,omitempty"`
	Final                 string    `json:"final"`
	DefaultDomainResolver string    `json:"default_domain_resolver,omitempty"`
	AutoDetectInterface   bool      `json:"auto_detect_interface,omitempty"`
	FindProcess           bool      `json:"find_process,omitempty"` // needed for process_name / process_path rules
}

// Rule is a route rule; Action defaults to "route" when Outbound is set.
type Rule struct {
	Action        string   `json:"action,omitempty"` // sniff resolve reject hijack-dns route
	Outbound      string   `json:"outbound,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	IPIsPrivate   bool     `json:"ip_is_private,omitempty"`
	Port          []int    `json:"port,omitempty"`
	PortRange     []string `json:"port_range,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
	ProcessRegex  []string `json:"process_path_regex,omitempty"`
	RuleSet       []string `json:"rule_set,omitempty"`
}

type RuleSet struct {
	Type   string `json:"type"` // local
	Tag    string `json:"tag"`
	Format string `json:"format"` // binary
	Path   string `json:"path"`
}

// OpenVPNEndpoint is the "openvpn-client" endpoint (sing-box 1.14+): a userspace
// OpenVPN tunnel, so no administrator rights are needed.
type OpenVPNEndpoint struct {
	Type    string       `json:"type"`
	Tag     string       `json:"tag"`
	Detour  string       `json:"detour,omitempty"`
	Server  string       `json:"server,omitempty"`
	Port    int          `json:"server_port,omitempty"`
	Servers []OVPNServer `json:"servers,omitempty"`
	Random  bool         `json:"remote_random,omitempty"`
	Network string       `json:"network,omitempty"`

	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	TLS *OVPNTLS `json:"tls"`

	DataCiphers         []string `json:"data_ciphers,omitempty"`
	DataCiphersFallback string   `json:"data_ciphers_fallback,omitempty"`
	Auth                string   `json:"auth,omitempty"`
	Compression         string   `json:"compression,omitempty"`
	CompressionLZO      string   `json:"compression_lzo,omitempty"`
	AllowCompression    string   `json:"allow_compression,omitempty"`
	MSSFix              int      `json:"mss_fix,omitempty"`
	Fragment            int      `json:"fragment,omitempty"`
	RouteNoPull         bool     `json:"route_no_pull,omitempty"`
	Topology            string   `json:"topology,omitempty"`
	PingInterval        string   `json:"ping_interval,omitempty"`
	PingRestart         string   `json:"ping_restart,omitempty"`
	RenegotiateInterval string   `json:"renegotiate_interval,omitempty"`
	RenegotiateDisabled bool     `json:"renegotiate_disabled,omitempty"`
}

type OVPNServer struct {
	Server  string `json:"server"`
	Port    int    `json:"server_port"`
	Network string `json:"network,omitempty"`
}

type OVPNTLS struct {
	ServerName      string           `json:"server_name,omitempty"`
	ServerNameType  string           `json:"server_name_type,omitempty"`
	Certificate     []string         `json:"certificate,omitempty"`
	ClientCert      []string         `json:"client_certificate,omitempty"`
	ClientKey       []string         `json:"client_key,omitempty"`
	PeerFingerprint []string         `json:"peer_fingerprint,omitempty"`
	RemoteCertTLS   string           `json:"remote_certificate_tls,omitempty"`
	VersionMin      string           `json:"version_min,omitempty"`
	ControlWrap     *OVPNControlWrap `json:"control_wrap,omitempty"`
}

type OVPNControlWrap struct {
	Type      string   `json:"type"`
	Key       []string `json:"key"`
	Direction string   `json:"direction,omitempty"`
}
