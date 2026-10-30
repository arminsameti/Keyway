package singbox

import (
	"strconv"
	"strings"

	"xray-friendly/internal/profile"
)

// defaultDataCiphers are sing-box's own defaults for OpenVPN data channels.
var defaultDataCiphers = []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"}

func pemLines(s string) []string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func seconds(n int) string { return strconv.Itoa(n) + "s" }

func stubCompression(c string) bool {
	switch strings.ToLower(c) {
	case "", "no", "none", "off", "disabled", "stub", "stub-v2":
		return true
	}
	return false
}

// openVPN renders an OpenVPN profile as an "openvpn-client" endpoint dialing
// through detour ("" = directly). The tunnel runs in sing-box's userspace
// network stack, so it needs no privileges and no system interface.
func openVPN(p profile.Profile, tag, detour string) OpenVPNEndpoint {
	o := p.OpenVPN
	network := p.Transport.Type
	if network == "" {
		network = "udp"
	}
	ep := OpenVPNEndpoint{Type: "openvpn-client", Tag: tag, Detour: detour, Network: network,
		Username: p.Username, Password: p.Password}
	if len(o.Remotes) == 0 {
		ep.Server, ep.Port = p.Server, p.Port
	} else {
		ep.Servers = []OVPNServer{{Server: p.Server, Port: p.Port}}
		for _, r := range o.Remotes {
			ep.Servers = append(ep.Servers, OVPNServer{Server: r.Server, Port: r.Port, Network: r.Network})
		}
		ep.Random = o.RemoteRandom
	}

	t := &OVPNTLS{
		ServerName: o.VerifyName, Certificate: pemLines(o.CA), ClientCert: pemLines(o.Cert), ClientKey: pemLines(o.Key),
		PeerFingerprint: o.PeerFingerprint, RemoteCertTLS: o.RemoteCertTLS, VersionMin: o.TLSVersionMin,
	}
	if o.VerifyName != "" {
		t.ServerNameType = o.VerifyNameType
	}
	if w := o.ControlWrap; w != nil {
		t.ControlWrap = &OVPNControlWrap{Type: w.Type, Key: pemLines(w.Key), Direction: w.Direction}
	}
	ep.TLS = t

	// Data channel: the profile's own list, or sing-box's defaults; the legacy
	// "cipher" directive stays allowed (and is the fallback for old peers).
	ciphers := o.DataCiphers
	if len(ciphers) == 0 {
		ciphers = append([]string{}, defaultDataCiphers...)
		if o.Cipher != "" {
			ciphers = append(ciphers, o.Cipher)
		}
	}
	ep.DataCiphers = ciphers
	ep.DataCiphersFallback = o.Cipher
	ep.Auth = o.Auth

	ep.Compression, ep.CompressionLZO = o.Compression, o.CompLZO
	if !stubCompression(o.Compression) || (o.CompLZO != "" && !stubCompression(o.CompLZO)) {
		ep.AllowCompression = "asym" // the profile asks for compression: accept it from the server
	}

	if o.RenegSec != nil {
		if *o.RenegSec == 0 {
			ep.RenegotiateDisabled = true
		} else {
			ep.RenegotiateInterval = seconds(*o.RenegSec)
		}
	}
	if o.PingInterval > 0 {
		ep.PingInterval = seconds(o.PingInterval)
	}
	if o.PingRestart > 0 {
		ep.PingRestart = seconds(o.PingRestart)
	}
	ep.MSSFix = o.MSSFix
	if network == "udp" {
		ep.Fragment = o.Fragment // sing-box refuses fragmentation over TCP
	}
	ep.RouteNoPull, ep.Topology = o.RouteNoPull, o.Topology
	return ep
}
