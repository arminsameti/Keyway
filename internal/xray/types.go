// Package xray contains the typed Xray-core configuration model, the config
// builder and the process runner.
package xray

import "encoding/json"

// Config is the subset of the Xray-core JSON configuration this app generates.
type Config struct {
	Log       LogConfig  `json:"log"`
	DNS       *DNS       `json:"dns,omitempty"`
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
	Stats     *struct{}  `json:"stats,omitempty"`
	API       *API       `json:"api,omitempty"`
	Policy    *Policy    `json:"policy,omitempty"`
}

// API exposes Xray's gRPC services; only the statistics service is enabled.
type API struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type Policy struct {
	System PolicySystem `json:"system"`
}

type PolicySystem struct {
	OutboundUplink   bool `json:"statsOutboundUplink"`
	OutboundDownlink bool `json:"statsOutboundDownlink"`
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
}

// DNS lists its servers as plain strings, or DNSServer objects for a resolver
// that answers for some domains only.
type DNS struct {
	Servers []any  `json:"servers"`
	Tag     string `json:"tag,omitempty"` // inbound tag of Xray's own queries, for routing
}

type Routing struct {
	DomainStrategy string `json:"domainStrategy"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// ---- inbounds ----

type Inbound struct {
	Tag      string    `json:"tag"`
	Protocol string    `json:"protocol"`
	Listen   string    `json:"listen"`
	Port     int       `json:"port"`
	Settings any       `json:"settings"`
	Sniffing *Sniffing `json:"sniffing,omitempty"`
}

type Sniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type Account struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

// SocksInbound are the settings of a "socks" inbound.
type SocksInbound struct {
	Auth     string    `json:"auth"`
	Accounts []Account `json:"accounts,omitempty"`
	UDP      bool      `json:"udp"`
}

// HTTPInbound are the settings of an "http" inbound (no UDP option exists).
type HTTPInbound struct {
	Accounts []Account `json:"accounts,omitempty"`
}

// ---- outbounds ----

type Outbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings,omitempty"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *Mux            `json:"mux,omitempty"`
	ProxySettings  *ProxySettings  `json:"proxySettings,omitempty"`

	// Raw, when set, is the whole outbound as written by the user (a custom
	// server); the typed fields are then only used for lookups such as Tag.
	Raw json.RawMessage `json:"-"`
}

// ProxySettings dials an outbound through another one on v2ray-core, which
// silently ignores sockopt.dialerProxy.
type ProxySettings struct {
	Tag            string `json:"tag"`
	TransportLayer bool   `json:"transportLayer"`
}

func (o Outbound) MarshalJSON() ([]byte, error) {
	if o.Raw != nil {
		return o.Raw, nil
	}
	type plain Outbound
	return json.Marshal(plain(o))
}

type Mux struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency,omitempty"`
}

// VMess / VLESS share the "vnext" layout.
type VNextSettings struct {
	VNext []VNext `json:"vnext"`
}

type VNext struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Users   []User `json:"users"`
}

type User struct {
	ID         string `json:"id"`
	AlterID    *int   `json:"alterId,omitempty"` // vmess only
	Security   string `json:"security,omitempty"`
	Encryption string `json:"encryption,omitempty"` // vless only
	Flow       string `json:"flow,omitempty"`       // vless only
}

// ServersSettings serves trojan, shadowsocks and socks outbounds.
type ServersSettings struct {
	Servers []Server `json:"servers"`
}

type Server struct {
	Address  string    `json:"address"`
	Port     int       `json:"port"`
	Password string    `json:"password,omitempty"`
	Method   string    `json:"method,omitempty"`
	Users    []Account `json:"users,omitempty"`
}

// HysteriaSettings are the outbound settings of the "hysteria" protocol.
type HysteriaSettings struct {
	Version int    `json:"version"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

// WireGuardSettings are the outbound settings of the "wireguard" protocol.
type WireGuardSettings struct {
	SecretKey string          `json:"secretKey"`
	Address   []string        `json:"address"`
	Peers     []WireGuardPeer `json:"peers"`
	MTU       int             `json:"mtu,omitempty"`
	Reserved  []int           `json:"reserved,omitempty"`
}

type WireGuardPeer struct {
	PublicKey    string   `json:"publicKey"`
	PreSharedKey string   `json:"preSharedKey,omitempty"`
	Endpoint     string   `json:"endpoint"`
	KeepAlive    int      `json:"keepAlive,omitempty"`
	AllowedIPs   []string `json:"allowedIPs,omitempty"`
}

// ---- stream settings ----

type StreamSettings struct {
	Network     string               `json:"network"`
	Security    string               `json:"security,omitempty"`
	TLS         *TLSSettings         `json:"tlsSettings,omitempty"`
	Reality     *RealitySettings     `json:"realitySettings,omitempty"`
	TCP         *TCPSettings         `json:"tcpSettings,omitempty"`
	WS          *WSSettings          `json:"wsSettings,omitempty"`
	GRPC        *GRPCSettings        `json:"grpcSettings,omitempty"`
	HTTPUpgrade *HTTPUpgradeSettings `json:"httpupgradeSettings,omitempty"`
	XHTTP       *XHTTPSettings       `json:"xhttpSettings,omitempty"`
	H2          *H2Settings          `json:"httpSettings,omitempty"`
	KCP         *KCPSettings         `json:"kcpSettings,omitempty"`
	Hysteria    *HysteriaStream      `json:"hysteriaSettings,omitempty"`
	Sockopt     *Sockopt             `json:"sockopt,omitempty"`
}

// Sockopt carries the one socket option this app uses: dialing an outbound
// through another outbound (a chain hop).
type Sockopt struct {
	DialerProxy string `json:"dialerProxy,omitempty"`
}

type TLSSettings struct {
	ServerName  string   `json:"serverName,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	// PinnedPeerCertSha256 is the hex SHA-256 of the server certificate
	// (colons allowed). Newer cores accept it in place of allowInsecure.
	PinnedPeerCertSha256 string `json:"pinnedPeerCertSha256,omitempty"`
}

type RealitySettings struct {
	ServerName  string `json:"serverName,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type TCPSettings struct {
	Header *TCPHeader `json:"header,omitempty"`
}

type TCPHeader struct {
	Type    string      `json:"type"`
	Request *TCPRequest `json:"request,omitempty"`
}

type TCPRequest struct {
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type WSSettings struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

type GRPCSettings struct {
	ServiceName string `json:"serviceName"`
	Authority   string `json:"authority,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}

type HTTPUpgradeSettings struct {
	Path string `json:"path"`
	Host string `json:"host,omitempty"`
}

type XHTTPSettings struct {
	Path string `json:"path"`
	Host string `json:"host,omitempty"`
	Mode string `json:"mode,omitempty"`
}

type H2Settings struct {
	Path string   `json:"path"`
	Host []string `json:"host,omitempty"`
}

type KCPSettings struct {
	Header *KCPHeader `json:"header,omitempty"`
	Seed   string     `json:"seed,omitempty"`
}

type KCPHeader struct {
	Type string `json:"type"`
}

type HysteriaStream struct {
	Version int    `json:"version"`
	Auth    string `json:"auth"`
}

// HasVisionFlow reports whether the outbound is VLESS with an XTLS flow, which
// is incompatible with mux.
func (o Outbound) HasVisionFlow() bool {
	v, ok := o.Settings.(*VNextSettings)
	if !ok {
		return false
	}
	for _, s := range v.VNext {
		for _, u := range s.Users {
			if u.Flow != "" {
				return true
			}
		}
	}
	return false
}

// MuxCapable reports whether enabling mux makes sense for this outbound.
func (o Outbound) MuxCapable() bool {
	switch o.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks":
	default:
		return false
	}
	if o.HasVisionFlow() {
		return false
	}
	if o.StreamSettings != nil {
		switch o.StreamSettings.Network {
		case "grpc", "h2", "kcp", "xhttp", "hysteria":
			return false
		}
	}
	return true
}
