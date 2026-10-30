// Package profile is the engine-neutral description of one proxy server. Link
// parsers and the manual-entry form produce a Profile; each engine (Xray,
// sing-box) turns it into its own configuration and decides whether it can run
// it at all.
package profile

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Protocol names (stable: persisted in Node.Protocol and used by the UI).
const (
	VLESS       = "vless"
	VMess       = "vmess"
	Trojan      = "trojan"
	Shadowsocks = "shadowsocks"
	SOCKS       = "socks"
	HTTP        = "http"
	Hysteria2   = "hysteria2"
	WireGuard   = "wireguard"
	TUIC        = "tuic"
	Hysteria    = "hysteria"
	AnyTLS      = "anytls"
	ShadowTLS   = "shadowtls"
	Naive       = "naive"
	SSH         = "ssh"
)

// Profile is one proxy server. Fields that do not apply to Protocol are empty.
type Profile struct {
	Protocol string `json:"protocol"`
	Server   string `json:"server"`
	Port     int    `json:"port"`

	UUID       string `json:"uuid,omitempty"`       // vless, vmess, tuic
	Username   string `json:"username,omitempty"`   // socks, http, naive, ssh
	Password   string `json:"password,omitempty"`   // trojan, shadowsocks, socks, http, hysteria2, tuic, anytls, shadowtls, naive, ssh
	Flow       string `json:"flow,omitempty"`       // vless
	Encryption string `json:"encryption,omitempty"` // vless ("none")
	AlterID    int    `json:"alterId,omitempty"`    // vmess
	Cipher     string `json:"cipher,omitempty"`     // vmess security, shadowsocks method

	Transport Transport `json:"transport"`
	Security  Security  `json:"security"`

	// Protocol-specific settings; nil when not used.
	Hysteria  *HysteriaOpts  `json:"hysteria,omitempty"` // hysteria, hysteria2
	WireGuard *WireGuardOpts `json:"wireguard,omitempty"`
	TUIC      *TUICOpts      `json:"tuic,omitempty"`
	ShadowTLS *ShadowTLSOpts `json:"shadowtls,omitempty"` // inner Shadowsocks: Cipher + Password
	SSH       *SSHOpts       `json:"ssh,omitempty"`
	AnyTLS    *AnyTLSOpts    `json:"anytls,omitempty"`
	Naive     *NaiveOpts     `json:"naive,omitempty"`
}

// HysteriaOpts covers both Hysteria versions. Password is the auth string.
type HysteriaOpts struct {
	UpMbps       int    `json:"upMbps,omitempty"`
	DownMbps     int    `json:"downMbps,omitempty"`
	Obfs         string `json:"obfs,omitempty"`         // hysteria2: "salamander"; hysteria: "xplus"
	ObfsPassword string `json:"obfsPassword,omitempty"` // obfuscation password
}

// WireGuardOpts is a single-peer WireGuard tunnel.
type WireGuardOpts struct {
	PrivateKey    string   `json:"privateKey"`
	PeerPublicKey string   `json:"peerPublicKey"`
	PreSharedKey  string   `json:"preSharedKey,omitempty"`
	LocalAddress  []string `json:"localAddress"` // CIDRs, e.g. 10.7.0.2/32
	MTU           int      `json:"mtu,omitempty"`
	Reserved      []int    `json:"reserved,omitempty"` // 3 bytes (Cloudflare WARP)
	AllowedIPs    []string `json:"allowedIps,omitempty"`
	Keepalive     int      `json:"keepalive,omitempty"` // seconds
}

// TUICOpts holds TUIC v5 options (UUID and Password are top-level).
type TUICOpts struct {
	CongestionControl string `json:"congestionControl,omitempty"` // bbr cubic new_reno
	UDPRelayMode      string `json:"udpRelayMode,omitempty"`      // native quic
	ZeroRTT           bool   `json:"zeroRtt,omitempty"`
}

// ShadowTLSOpts wraps an inner Shadowsocks connection in a borrowed TLS handshake.
type ShadowTLSOpts struct {
	Version  int    `json:"version"`
	Password string `json:"password"`
	SNI      string `json:"sni"` // the handshake server
}

// SSHOpts tunnels through an SSH server (Username/Password are top-level).
type SSHOpts struct {
	PrivateKeyPath string   `json:"privateKeyPath,omitempty"`
	PrivateKey     string   `json:"privateKey,omitempty"` // PEM, from imported configs
	Passphrase     string   `json:"passphrase,omitempty"`
	HostKeys       []string `json:"hostKeys,omitempty"` // pins the server
}

// AnyTLSOpts holds AnyTLS session options.
type AnyTLSOpts struct {
	IdleTimeoutSec int `json:"idleTimeoutSec,omitempty"`
}

// NaiveOpts holds NaiveProxy options (Username/Password are top-level).
type NaiveOpts struct {
	ExtraHeaders map[string]string `json:"extraHeaders,omitempty"`
}

// Transport is the stream layer under the proxy protocol.
type Transport struct {
	Type        string `json:"type"` // tcp ws grpc httpupgrade xhttp h2 kcp quic udp
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"` // comma separated for h2 / tcp-http
	ServiceName string `json:"serviceName,omitempty"`
	Authority   string `json:"authority,omitempty"`
	Mode        string `json:"mode,omitempty"`       // grpc "multi", xhttp mode
	HeaderType  string `json:"headerType,omitempty"` // tcp "http", kcp header
	Seed        string `json:"seed,omitempty"`       // kcp
}

// Security is the TLS / Reality layer.
type Security struct {
	Kind        string   `json:"kind"` // none tls reality
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`  // skip certificate verification
	PinSHA256   string   `json:"pinSha256,omitempty"` // server certificate fingerprint (hex, colons allowed)
	PublicKey   string   `json:"publicKey,omitempty"` // reality
	ShortID     string   `json:"shortId,omitempty"`   // reality
	SpiderX     string   `json:"spiderX,omitempty"`   // reality
}

var transports = map[string]bool{
	"tcp": true, "ws": true, "grpc": true, "httpupgrade": true, "xhttp": true, "h2": true, "kcp": true,
	"quic": true, "udp": true,
}

// UDPBased reports whether the protocol runs over UDP, so a TCP dial says
// nothing about whether the server is reachable.
func (p Profile) UDPBased() bool {
	switch p.Protocol {
	case Hysteria2, Hysteria, TUIC, WireGuard:
		return true
	}
	return false
}

// Validate checks the fields every engine relies on. Error messages never
// contain credentials.
func (p Profile) Validate() error {
	if strings.TrimSpace(p.Server) == "" {
		return fmt.Errorf("missing server address")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("invalid port %d", p.Port)
	}
	switch p.Protocol {
	case VLESS, VMess:
		if strings.TrimSpace(p.UUID) == "" {
			return fmt.Errorf("%s: missing user id", p.Protocol)
		}
	case Trojan, Hysteria2, Hysteria, AnyTLS:
		if p.Password == "" {
			return fmt.Errorf("%s: missing password", p.Protocol)
		}
	case Shadowsocks:
		if p.Password == "" || p.Cipher == "" {
			return fmt.Errorf("shadowsocks: missing method or password")
		}
	case TUIC:
		if strings.TrimSpace(p.UUID) == "" || p.Password == "" {
			return fmt.Errorf("tuic: missing uuid or password")
		}
	case WireGuard:
		w := p.WireGuard
		if w == nil || w.PrivateKey == "" || w.PeerPublicKey == "" {
			return fmt.Errorf("wireguard: missing private key or peer public key")
		}
		if len(w.LocalAddress) == 0 {
			return fmt.Errorf("wireguard: missing local address")
		}
		if len(w.Reserved) != 0 && len(w.Reserved) != 3 {
			return fmt.Errorf("wireguard: reserved must be 3 bytes")
		}
		for _, b := range w.Reserved {
			if b < 0 || b > 255 {
				return fmt.Errorf("wireguard: reserved bytes must be 0-255")
			}
		}
	case ShadowTLS:
		st := p.ShadowTLS
		if st == nil || st.Password == "" || st.SNI == "" || p.Cipher == "" || p.Password == "" {
			return fmt.Errorf("shadowtls: missing password, handshake server or inner shadowsocks")
		}
		if st.Version < 1 || st.Version > 3 {
			return fmt.Errorf("shadowtls: version must be 1-3")
		}
	case Naive:
		if p.Username == "" || p.Password == "" {
			return fmt.Errorf("naive: missing username or password")
		}
	case SSH:
		if p.Username == "" {
			return fmt.Errorf("ssh: missing user")
		}
		if p.Password == "" && (p.SSH == nil || (p.SSH.PrivateKeyPath == "" && p.SSH.PrivateKey == "")) {
			return fmt.Errorf("ssh: set a password or a private key")
		}
	case SOCKS, HTTP:
	default:
		return fmt.Errorf("unsupported protocol %q", p.Protocol)
	}
	if p.Transport.Type != "" && !transports[p.Transport.Type] {
		return fmt.Errorf("unsupported transport %q", p.Transport.Type)
	}
	switch p.Security.Kind {
	case "", "none", "tls":
	case "reality":
		if p.Security.PublicKey == "" {
			return fmt.Errorf("reality without public key")
		}
	default:
		return fmt.Errorf("unsupported security %q", p.Security.Kind)
	}
	if p.Security.PinSHA256 != "" && !ValidPin(p.Security.PinSHA256) {
		return fmt.Errorf("pinned certificate must be a hex SHA-256 fingerprint")
	}
	return nil
}

// ValidPin accepts a SHA-256 fingerprint as hex, with or without colons.
func ValidPin(pin string) bool {
	h := strings.ReplaceAll(pin, ":", "")
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}
