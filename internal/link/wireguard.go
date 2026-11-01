package link

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"keyway/internal/profile"
)

// parseWireGuard reads wireguard:// and wg:// links:
//
//	wireguard://<private key>@host:port?publickey=..&address=10.7.0.2/32,fd00::2/128&mtu=1420&reserved=0,0,0#name
//
// Parameter names differ between clients, so the common spellings are accepted.
func parseWireGuard(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	q := u.Query()
	key := ""
	if u.User != nil {
		key = u.User.Username()
	}
	wg := &profile.WireGuardOpts{
		PrivateKey:    firstNonEmpty(key, q.Get("privatekey"), q.Get("private_key"), q.Get("secretKey")),
		PeerPublicKey: firstNonEmpty(q.Get("publickey"), q.Get("public_key"), q.Get("peer_public_key"), q.Get("publicKey")),
		PreSharedKey:  firstNonEmpty(q.Get("presharedkey"), q.Get("pre_shared_key"), q.Get("psk"), q.Get("preSharedKey")),
		LocalAddress:  splitComma(firstNonEmpty(q.Get("address"), q.Get("ip"), q.Get("local_address"))),
		AllowedIPs:    splitComma(firstNonEmpty(q.Get("allowedips"), q.Get("allowed_ips"))),
	}
	if wg.MTU, err = optInt(firstNonEmpty(q.Get("mtu"))); err != nil {
		return Result{}, fmt.Errorf("wireguard: mtu: %w", err)
	}
	if wg.Keepalive, err = optInt(firstNonEmpty(q.Get("keepalive"), q.Get("persistent_keepalive"))); err != nil {
		return Result{}, fmt.Errorf("wireguard: keepalive: %w", err)
	}
	if wg.Reserved, err = parseReserved(q.Get("reserved")); err != nil {
		return Result{}, fmt.Errorf("wireguard: %w", err)
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 51820)
	if err != nil {
		return Result{}, fmt.Errorf("wireguard: %w", err)
	}
	pr := profile.Profile{Protocol: profile.WireGuard, Server: host, Port: port, WireGuard: wg,
		Transport: profile.Transport{Type: "udp"}}
	if err := pr.Validate(); err != nil {
		return Result{}, err
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("wg-%s:%d", host, port))
	return Result{Node: newNode(name, profile.WireGuard, host, port, raw), Profile: pr}, nil
}

func optInt(s string) (int, error) {
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "s"))
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid number %q", s)
	}
	return n, nil
}

func parseReserved(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, p := range splitComma(s) {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("reserved must be three numbers 0-255")
		}
		out = append(out, n)
	}
	if len(out) != 3 {
		return nil, fmt.Errorf("reserved must be three numbers 0-255")
	}
	return out, nil
}

// LooksLikeWireGuardConf reports whether text is a wg-quick .conf file.
func LooksLikeWireGuardConf(text string) bool {
	low := strings.ToLower(text)
	return strings.Contains(low, "[interface]") && strings.Contains(low, "[peer]")
}

// ParseWireGuardConf reads a wg-quick .conf file (one interface, first peer).
// DNS, Table, PostUp and similar host-side settings do not apply to a proxy
// tunnel and are ignored.
func ParseWireGuardConf(text, name string) (Result, error) {
	wg := &profile.WireGuardOpts{}
	var endpoint string
	section, peers := "", 0
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		var err error
		switch {
		case section == "interface" && k == "privatekey":
			wg.PrivateKey = v
		case section == "interface" && k == "address":
			wg.LocalAddress = append(wg.LocalAddress, splitComma(v)...)
		case section == "interface" && k == "mtu":
			wg.MTU, err = optInt(v)
		case section == "peer" && peers == 1 && k == "publickey":
			wg.PeerPublicKey = v
		case section == "peer" && peers == 1 && k == "presharedkey":
			wg.PreSharedKey = v
		case section == "peer" && peers == 1 && k == "endpoint":
			endpoint = v
		case section == "peer" && peers == 1 && k == "allowedips":
			wg.AllowedIPs = append(wg.AllowedIPs, splitComma(v)...)
		case section == "peer" && peers == 1 && k == "persistentkeepalive":
			wg.Keepalive, err = optInt(v)
		}
		if err != nil {
			return Result{}, fmt.Errorf("wireguard config: %s: %w", k, err)
		}
	}
	if peers == 0 {
		return Result{}, fmt.Errorf("wireguard config has no [Peer]")
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return Result{}, fmt.Errorf("wireguard config: Endpoint must be host:port")
	}
	port, err := parsePort(portStr, 0)
	if err != nil {
		return Result{}, fmt.Errorf("wireguard config: %w", err)
	}
	pr := profile.Profile{Protocol: profile.WireGuard, Server: host, Port: port, WireGuard: wg,
		Transport: profile.Transport{Type: "udp"}}
	if err := pr.Validate(); err != nil {
		return Result{}, err
	}
	if strings.TrimSpace(name) == "" {
		name = "WireGuard " + host
	}
	return ProfileNode(pr, name)
}

func encodeWireGuard(p profile.Profile, hostport, frag string) string {
	w := p.WireGuard
	q := url.Values{}
	q.Set("publickey", w.PeerPublicKey)
	q.Set("address", strings.Join(w.LocalAddress, ","))
	setIf(q, "presharedkey", w.PreSharedKey)
	setIf(q, "allowedips", strings.Join(w.AllowedIPs, ","))
	if w.MTU > 0 {
		q.Set("mtu", strconv.Itoa(w.MTU))
	}
	if w.Keepalive > 0 {
		q.Set("keepalive", strconv.Itoa(w.Keepalive))
	}
	if len(w.Reserved) == 3 {
		q.Set("reserved", fmt.Sprintf("%d,%d,%d", w.Reserved[0], w.Reserved[1], w.Reserved[2]))
	}
	return "wireguard://" + url.User(w.PrivateKey).String() + "@" + hostport + "?" + q.Encode() + frag
}
