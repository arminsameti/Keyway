package link

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"keyway/internal/profile"
)

func truthy(v string) bool { return v == "1" || strings.EqualFold(v, "true") }

// tlsFromQuery reads the TLS options shared by the QUIC-based links.
func tlsFromQuery(q url.Values, defaultALPN string) (profile.Security, error) {
	pin := q.Get("pinSHA256")
	if pin != "" && !profile.ValidPin(pin) {
		return profile.Security{}, fmt.Errorf("pinSHA256 must be a hex SHA-256 fingerprint")
	}
	sec := profile.Security{
		Kind:      "tls",
		SNI:       firstNonEmpty(q.Get("sni"), q.Get("peer")),
		PinSHA256: pin,
		Insecure:  pin == "" && (truthy(q.Get("insecure")) || truthy(q.Get("allow_insecure")) || truthy(q.Get("allowInsecure"))),
	}
	if a := q.Get("alpn"); a != "" {
		sec.ALPN = splitComma(a)
	} else if defaultALPN != "" {
		sec.ALPN = []string{defaultALPN}
	}
	return sec, nil
}

// parseTUIC reads tuic://uuid:password@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=..#name (v5 only).
func parseTUIC(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	q := u.Query()
	if v := q.Get("version"); v != "" && v != "5" {
		return Result{}, fmt.Errorf("tuic: only version 5 is supported")
	}
	id, pw := "", ""
	if u.User != nil {
		id = u.User.Username()
		pw, _ = u.User.Password()
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("tuic: %w", err)
	}
	sec, err := tlsFromQuery(q, "h3")
	if err != nil {
		return Result{}, fmt.Errorf("tuic: %w", err)
	}
	cc := strings.ToLower(firstNonEmpty(q.Get("congestion_control"), q.Get("congestion-control"), q.Get("cc")))
	switch cc {
	case "", "bbr", "cubic", "new_reno":
	default:
		return Result{}, fmt.Errorf("tuic: unsupported congestion control %q", cc)
	}
	mode := strings.ToLower(firstNonEmpty(q.Get("udp_relay_mode"), q.Get("udp-relay-mode")))
	if mode != "" && mode != "native" && mode != "quic" {
		return Result{}, fmt.Errorf("tuic: udp relay mode must be native or quic")
	}
	pr := profile.Profile{
		Protocol: profile.TUIC, Server: host, Port: port, UUID: id, Password: pw,
		Transport: profile.Transport{Type: "quic"}, Security: sec,
		TUIC: &profile.TUICOpts{CongestionControl: cc, UDPRelayMode: mode,
			ZeroRTT: truthy(q.Get("reduce_rtt")) || truthy(q.Get("zero_rtt_handshake"))},
	}
	if err := pr.Validate(); err != nil {
		return Result{}, err
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("tuic-%s:%d", host, port))
	return Result{Node: newNode(name, profile.TUIC, host, port, raw), Profile: pr}, nil
}

// parseHysteria1 reads hysteria://host:port?auth=..&peer=..&upmbps=..&downmbps=..&obfs=xplus&obfsParam=..#name.
func parseHysteria1(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	q := u.Query()
	if p := q.Get("protocol"); p != "" && p != "udp" {
		return Result{}, fmt.Errorf("hysteria: only the UDP mode is supported, not %q", p)
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("hysteria: %w", err)
	}
	sec, err := tlsFromQuery(q, "hysteria")
	if err != nil {
		return Result{}, fmt.Errorf("hysteria: %w", err)
	}
	h := &profile.HysteriaOpts{}
	if h.UpMbps, err = optInt(q.Get("upmbps")); err != nil {
		return Result{}, fmt.Errorf("hysteria: upmbps: %w", err)
	}
	if h.DownMbps, err = optInt(q.Get("downmbps")); err != nil {
		return Result{}, fmt.Errorf("hysteria: downmbps: %w", err)
	}
	if o := q.Get("obfs"); o != "" && o != "none" {
		h.Obfs, h.ObfsPassword = o, q.Get("obfsParam")
	}
	auth := firstNonEmpty(q.Get("auth"), q.Get("auth_str"))
	if auth == "" && u.User != nil {
		auth = u.User.Username()
	}
	pr := profile.Profile{Protocol: profile.Hysteria, Server: host, Port: port, Password: auth,
		Transport: profile.Transport{Type: "quic"}, Security: sec, Hysteria: h}
	if err := pr.Validate(); err != nil {
		return Result{}, err
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("hysteria-%s:%d", host, port))
	return Result{Node: newNode(name, profile.Hysteria, host, port, raw), Profile: pr}, nil
}

// parseAnyTLS reads anytls://password@host:port?sni=..&insecure=1#name.
func parseAnyTLS(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	pw := ""
	if u.User != nil {
		pw = u.User.Username()
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("anytls: %w", err)
	}
	q := u.Query()
	sec, err := tlsFromQuery(q, "")
	if err != nil {
		return Result{}, fmt.Errorf("anytls: %w", err)
	}
	pr := profile.Profile{Protocol: profile.AnyTLS, Server: host, Port: port, Password: pw,
		Transport: profile.Transport{Type: "tcp"}, Security: sec}
	if idle, _ := optInt(q.Get("idle_session_timeout")); idle > 0 {
		pr.AnyTLS = &profile.AnyTLSOpts{IdleTimeoutSec: idle}
	}
	if err := pr.Validate(); err != nil {
		return Result{}, err
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("anytls-%s:%d", host, port))
	return Result{Node: newNode(name, profile.AnyTLS, host, port, raw), Profile: pr}, nil
}

// parseNaive reads naive+https://user:pass@host:port?extra-headers=..#name.
// Extra headers are "Name: value" pairs separated by \r\n or "|".
func parseNaive(raw string) (Result, error) {
	if strings.HasPrefix(strings.ToLower(raw), "naive+quic://") {
		return Result{}, fmt.Errorf("NaiveProxy over QUIC is not supported; use naive+https")
	}
	u, err := parseURL("https://" + raw[strings.Index(raw, "://")+3:])
	if err != nil {
		return Result{}, err
	}
	user, pw := "", ""
	if u.User != nil {
		user = u.User.Username()
		pw, _ = u.User.Password()
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("naive: %w", err)
	}
	q := u.Query()
	pr := profile.Profile{Protocol: profile.Naive, Server: host, Port: port, Username: user, Password: pw,
		Transport: profile.Transport{Type: "h2"}, Security: profile.Security{Kind: "tls", SNI: q.Get("sni"), ALPN: []string{"h2"}}}
	if h := q.Get("extra-headers"); h != "" {
		hdr := map[string]string{}
		for _, kv := range strings.FieldsFunc(h, func(r rune) bool { return r == '\r' || r == '\n' || r == '|' }) {
			k, v, ok := strings.Cut(kv, ":")
			if !ok || strings.TrimSpace(k) == "" {
				return Result{}, fmt.Errorf("naive: extra headers must be Name: value")
			}
			hdr[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
		pr.Naive = &profile.NaiveOpts{ExtraHeaders: hdr}
	}
	if err := pr.Validate(); err != nil {
		return Result{}, err
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("naive-%s:%d", host, port))
	return Result{Node: newNode(name, profile.Naive, host, port, raw), Profile: pr}, nil
}

func encodeQUICTLS(q url.Values, sec profile.Security, defaultALPN string) {
	setIf(q, "sni", sec.SNI)
	setIf(q, "pinSHA256", sec.PinSHA256)
	if sec.Insecure {
		q.Set("insecure", "1")
	}
	if a := strings.Join(sec.ALPN, ","); a != "" && a != defaultALPN {
		q.Set("alpn", a)
	}
}

func encodeQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

func encodeTUIC(p profile.Profile, hostport, frag string) string {
	q := url.Values{}
	encodeQUICTLS(q, p.Security, "h3")
	if t := p.TUIC; t != nil {
		setIf(q, "congestion_control", t.CongestionControl)
		setIf(q, "udp_relay_mode", t.UDPRelayMode)
		if t.ZeroRTT {
			q.Set("reduce_rtt", "1")
		}
	}
	return "tuic://" + url.UserPassword(p.UUID, p.Password).String() + "@" + hostport + encodeQuery(q) + frag
}

func encodeHysteria1(p profile.Profile, hostport, frag string) string {
	q := url.Values{}
	q.Set("auth", p.Password)
	encodeQUICTLS(q, p.Security, "hysteria")
	if h := p.Hysteria; h != nil {
		if h.UpMbps > 0 {
			q.Set("upmbps", strconv.Itoa(h.UpMbps))
		}
		if h.DownMbps > 0 {
			q.Set("downmbps", strconv.Itoa(h.DownMbps))
		}
		if h.Obfs != "" {
			q.Set("obfs", h.Obfs)
			setIf(q, "obfsParam", h.ObfsPassword)
		}
	}
	return "hysteria://" + hostport + encodeQuery(q) + frag
}

func encodeAnyTLS(p profile.Profile, hostport, frag string) string {
	q := url.Values{}
	encodeQUICTLS(q, p.Security, "")
	if p.AnyTLS != nil && p.AnyTLS.IdleTimeoutSec > 0 {
		q.Set("idle_session_timeout", strconv.Itoa(p.AnyTLS.IdleTimeoutSec))
	}
	return "anytls://" + url.User(p.Password).String() + "@" + hostport + encodeQuery(q) + frag
}

func encodeNaive(p profile.Profile, hostport, frag string) string {
	q := url.Values{}
	setIf(q, "sni", p.Security.SNI)
	if p.Naive != nil && len(p.Naive.ExtraHeaders) > 0 {
		var hs []string
		for _, k := range sortedKeys(p.Naive.ExtraHeaders) {
			hs = append(hs, k+": "+p.Naive.ExtraHeaders[k])
		}
		q.Set("extra-headers", strings.Join(hs, "\r\n"))
	}
	return "naive+https://" + url.UserPassword(p.Username, p.Password).String() + "@" + hostport + encodeQuery(q) + frag
}
