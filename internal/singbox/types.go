// Package singbox builds sing-box (1.12+) configurations from engine-neutral
// profiles. Like package xray it only produces data; running the binary is the
// engine package's job.
package singbox

// Config is the subset of the sing-box configuration this app generates.
type Config struct {
	Log       Log        `json:"log"`
	DNS       *DNS       `json:"dns,omitempty"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Endpoints []Endpoint `json:"endpoints,omitempty"`
	Route     Route      `json:"route"`
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
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
	Users      []User `json:"users,omitempty"`
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
	Keepalive    string   `json:"persistent_keepalive_interval,omitempty"`
	Reserved     []int    `json:"reserved,omitempty"`
}

type Route struct {
	Rules                 []Rule    `json:"rules"`
	RuleSet               []RuleSet `json:"rule_set,omitempty"`
	Final                 string    `json:"final"`
	DefaultDomainResolver string    `json:"default_domain_resolver,omitempty"`
	AutoDetectInterface   bool      `json:"auto_detect_interface,omitempty"`
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
	RuleSet       []string `json:"rule_set,omitempty"`
}

type RuleSet struct {
	Type   string `json:"type"` // local
	Tag    string `json:"tag"`
	Format string `json:"format"` // binary
	Path   string `json:"path"`
}
