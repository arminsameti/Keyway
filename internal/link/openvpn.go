package link

import (
	"fmt"
	"strconv"
	"strings"

	"xray-friendly/internal/profile"
)

// LooksLikeOVPN reports whether text is an OpenVPN client profile (.ovpn).
func LooksLikeOVPN(text string) bool {
	hasRemote, hasMarker := false, false
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "remote":
			hasRemote = len(f) >= 2
		case "client", "<ca>", "<cert>", "<tls-crypt>", "<tls-auth>", "auth-user-pass", "remote-cert-tls", "nobind":
			hasMarker = true
		case "dev":
			hasMarker = hasMarker || (len(f) >= 2 && strings.HasPrefix(strings.ToLower(f[1]), "tun"))
		}
	}
	return hasRemote && hasMarker
}

// ovpnRejected lists directives this app cannot honour, with the reason. A
// profile that uses one is refused rather than imported half-working.
var ovpnRejected = map[string]string{
	"secret":        "static-key mode (secret) is deprecated and not supported",
	"http-proxy":    "reaching the server through an HTTP proxy is not supported here; add the proxy as a hop in a chain instead",
	"socks-proxy":   "reaching the server through a SOCKS proxy is not supported here; add the proxy as a hop in a chain instead",
	"plugin":        "OpenVPN plugins are not supported",
	"pkcs12":        "PKCS#12 bundles are not supported; use embedded <ca>, <cert> and <key> sections",
	"cryptoapicert": "Windows certificate store entries are not supported",
	"askpass":       "private keys protected by a passphrase are not supported",
	"mode":          "this is a server configuration, not a client profile",
	"server":        "this is a server configuration, not a client profile",
	"server-bridge": "this is a server configuration, not a client profile",
	"tls-server":    "this is a server configuration, not a client profile",
}

// ovpnArgs splits a directive line, honouring "double quotes" and \ escapes.
func ovpnArgs(line string) []string {
	var out []string
	var cur strings.Builder
	quote, started := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			started = true
		case c == '"':
			quote, started = !quote, true
		case (c == ' ' || c == '\t') && !quote:
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		case (c == '#' || c == ';') && !quote && !started:
			return out // trailing comment
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}

func ovpnNetwork(proto string) (string, bool) {
	switch strings.ToLower(proto) {
	case "udp", "udp4", "udp6":
		return "udp", true
	case "tcp", "tcp4", "tcp6", "tcp-client", "tcp4-client", "tcp6-client":
		return "tcp", true
	}
	return "", false
}

// ParseOVPNProfile reads an .ovpn client profile into an unvalidated profile
// and a suggested name. Credentials that OpenVPN would prompt for or read
// from a file are not stored: OpenVPN.NeedsCredential is set instead.
func ParseOVPNProfile(text string) (profile.Profile, string, error) {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	blocks := map[string]string{}
	var directives [][]string
	var connBlocks []string

	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '<' && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			name := strings.ToLower(strings.Trim(line, "<>"))
			var body []string
			closed := false
			for i++; i < len(lines); i++ {
				if strings.TrimSpace(lines[i]) == "</"+name+">" {
					closed = true
					break
				}
				body = append(body, strings.TrimRight(lines[i], " \t"))
			}
			if !closed {
				return profile.Profile{}, "", fmt.Errorf("OpenVPN: the <%s> section is not closed", name)
			}
			content := strings.Trim(strings.Join(body, "\n"), "\n")
			if name == "connection" {
				connBlocks = append(connBlocks, content)
			} else {
				blocks[name] = content
			}
			continue
		}
		if args := ovpnArgs(line); len(args) > 0 {
			args[0] = strings.ToLower(args[0])
			directives = append(directives, args)
		}
	}

	o := &profile.OpenVPNOpts{}
	p := profile.Profile{Protocol: profile.OpenVPN, OpenVPN: o, Security: profile.Security{Kind: "tls"}}
	network := "udp"
	type remote struct {
		host, proto string
		port        int
	}
	var remotes []remote
	var keyDirection string
	wrapDir := ""

	addRemote := func(args []string, defaultProto string) error {
		if len(args) < 2 {
			return fmt.Errorf("OpenVPN: a remote line needs a server address")
		}
		r := remote{host: args[1], port: 1194, proto: defaultProto}
		if len(args) >= 3 {
			n, err := strconv.Atoi(args[2])
			if err != nil || n < 1 || n > 65535 {
				return fmt.Errorf("OpenVPN: invalid remote port %q", args[2])
			}
			r.port = n
		}
		if len(args) >= 4 {
			if net, ok := ovpnNetwork(args[3]); ok {
				r.proto = net
			}
		}
		remotes = append(remotes, r)
		return nil
	}

	for _, d := range directives {
		name := d[0]
		if why, bad := ovpnRejected[name]; bad {
			return p, "", fmt.Errorf("OpenVPN: %s", why)
		}
		arg := func(i int) string {
			if i < len(d) {
				return d[i]
			}
			return ""
		}
		switch name {
		case "dev", "dev-type":
			if strings.HasPrefix(strings.ToLower(arg(1)), "tap") {
				return p, "", fmt.Errorf("OpenVPN: TAP (bridged) mode is not supported; this app uses routed tunnels")
			}
		case "proto":
			n, ok := ovpnNetwork(arg(1))
			if !ok {
				return p, "", fmt.Errorf("OpenVPN: unsupported protocol %q", arg(1))
			}
			network = n
		case "remote":
			if err := addRemote(d, ""); err != nil {
				return p, "", err
			}
		case "remote-random":
			o.RemoteRandom = true
		case "ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2":
			// A file name means the material is not in this text.
			if f := arg(1); f != "" && f != "[inline]" {
				if _, has := blocks[name]; !has {
					return p, "", fmt.Errorf("OpenVPN: %s refers to the file %q; this app needs the certificates and keys embedded in the profile (<ca>, <cert>, <key> sections)", name, f)
				}
			}
			if name == "tls-auth" && len(d) >= 3 {
				wrapDir = d[2]
			}
		case "key-direction":
			keyDirection = arg(1)
		case "auth-user-pass":
			if len(d) >= 2 {
				o.NeedsCredential = true // a credentials file we cannot read
			} else if _, inline := blocks["auth-user-pass"]; !inline {
				o.NeedsCredential = true // OpenVPN would prompt
			}
		case "cipher":
			o.Cipher = arg(1)
		case "data-ciphers", "ncp-ciphers":
			o.DataCiphers = strings.FieldsFunc(arg(1), func(r rune) bool { return r == ':' || r == ',' })
		case "data-ciphers-fallback":
			o.Cipher = arg(1)
		case "auth":
			o.Auth = strings.ToUpper(arg(1))
		case "compress":
			alg := strings.ToLower(arg(1))
			switch alg {
			case "lzo":
				o.CompLZO = "yes"
			case "":
				o.Compression = "stub-v2"
			default:
				o.Compression = alg
			}
		case "comp-lzo":
			o.CompLZO = strings.ToLower(arg(1))
			if o.CompLZO == "" {
				o.CompLZO = "adaptive"
			}
		case "remote-cert-tls":
			o.RemoteCertTLS = strings.ToLower(arg(1))
		case "verify-x509-name":
			o.VerifyName = arg(1)
			o.VerifyNameType = strings.ToLower(arg(2))
			if o.VerifyNameType == "" {
				o.VerifyNameType = "subject"
			}
		case "tls-version-min":
			o.TLSVersionMin = arg(1)
		case "reneg-sec":
			if n, err := strconv.Atoi(arg(1)); err == nil && n >= 0 {
				o.RenegSec = &n
			}
		case "ping":
			o.PingInterval, _ = strconv.Atoi(arg(1))
		case "ping-restart":
			o.PingRestart, _ = strconv.Atoi(arg(1))
		case "keepalive":
			o.PingInterval, _ = strconv.Atoi(arg(1))
			o.PingRestart, _ = strconv.Atoi(arg(2))
		case "mssfix":
			o.MSSFix, _ = strconv.Atoi(arg(1))
		case "fragment":
			o.Fragment, _ = strconv.Atoi(arg(1))
		case "route-nopull":
			o.RouteNoPull = true
		case "topology":
			o.Topology = strings.ToLower(arg(1))
		}
	}

	// <connection> blocks: each holds its own remote (and maybe proto).
	for _, cb := range connBlocks {
		proto := ""
		var rs [][]string
		for _, l := range strings.Split(cb, "\n") {
			a := ovpnArgs(strings.TrimSpace(l))
			if len(a) == 0 {
				continue
			}
			switch strings.ToLower(a[0]) {
			case "remote":
				a[0] = "remote"
				rs = append(rs, a)
			case "proto":
				if n, ok := ovpnNetwork(strings.Join(a[1:], "")); ok {
					proto = n
				}
			}
		}
		for _, r := range rs {
			if err := addRemote(r, proto); err != nil {
				return p, "", err
			}
		}
	}
	if len(remotes) == 0 {
		return p, "", fmt.Errorf("OpenVPN: the profile has no remote server")
	}

	// embedded material
	o.CA = blocks["ca"]
	o.Cert = blocks["cert"]
	o.Key = blocks["key"]
	for _, pem := range []string{o.Key} {
		if strings.Contains(pem, "ENCRYPTED") {
			return p, "", fmt.Errorf("OpenVPN: the client key is protected by a passphrase, which is not supported")
		}
	}
	wrapType := ""
	for _, t := range []string{"tls-crypt-v2", "tls-crypt", "tls-auth"} { // strongest first
		if _, ok := blocks[t]; ok {
			wrapType = strings.ReplaceAll(t, "-", "_")
			break
		}
	}
	if wrapType != "" {
		key := blocks[strings.ReplaceAll(wrapType, "_", "-")]
		w := &profile.OVPNControlWrap{Type: wrapType, Key: key}
		if wrapType == "tls_auth" {
			dir := wrapDir
			if dir == "" {
				dir = keyDirection
			}
			switch dir {
			case "0":
				w.Direction = "server"
			case "1":
				w.Direction = "client"
			}
		}
		o.ControlWrap = w
	}
	if cred, ok := blocks["auth-user-pass"]; ok {
		f := strings.Split(cred, "\n")
		if len(f) >= 2 {
			p.Username, p.Password = strings.TrimSpace(f[0]), strings.TrimSpace(f[1])
			o.NeedsCredential = false
		}
	}

	// transport and servers
	first := remotes[0]
	p.Server, p.Port = first.host, first.port
	p.Transport.Type = first.proto
	if p.Transport.Type == "" {
		p.Transport.Type = network
	}
	for _, r := range remotes[1:] {
		rr := profile.OVPNRemote{Server: r.host, Port: r.port}
		if r.proto != "" && r.proto != p.Transport.Type {
			rr.Network = r.proto
		}
		o.Remotes = append(o.Remotes, rr)
	}
	return p, "OpenVPN " + first.host, nil
}

// ParseOVPN reads an .ovpn profile into a node (stored as a profile: OpenVPN
// has no share-link format). name overrides the suggested name when set.
func ParseOVPN(text, name string) (Result, error) {
	p, suggested, err := ParseOVPNProfile(text)
	if err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(name) == "" {
		name = suggested
	}
	return ProfileNode(p, name)
}
