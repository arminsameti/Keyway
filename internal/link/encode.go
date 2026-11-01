package link

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"keyway/internal/profile"
)

// Encode renders the canonical share link for a profile. ok is false for
// protocols without a share-link format (HTTP, SSH, ShadowTLS); those nodes
// store their profile instead.
func Encode(p profile.Profile, name string) (link string, ok bool) {
	hostport := net.JoinHostPort(p.Server, strconv.Itoa(p.Port))
	frag := ""
	if name != "" {
		frag = "#" + url.PathEscape(name)
	}
	switch p.Protocol {
	case profile.VLESS:
		q := streamQuery(p)
		q.Set("encryption", orDefault(p.Encryption, "none"))
		setIf(q, "flow", p.Flow)
		return "vless://" + url.User(p.UUID).String() + "@" + hostport + "?" + q.Encode() + frag, true
	case profile.Trojan:
		q := streamQuery(p)
		return "trojan://" + url.User(p.Password).String() + "@" + hostport + "?" + q.Encode() + frag, true
	case profile.VMess:
		return encodeVMess(p, name), true
	case profile.Shadowsocks:
		cred := base64.RawURLEncoding.EncodeToString([]byte(p.Cipher + ":" + p.Password))
		return "ss://" + cred + "@" + hostport + frag, true
	case profile.SOCKS:
		u := ""
		if p.Username != "" {
			u = url.UserPassword(p.Username, p.Password).String() + "@"
		}
		return "socks5://" + u + hostport + frag, true
	case profile.Hysteria2:
		q := url.Values{}
		setIf(q, "sni", p.Security.SNI)
		setIf(q, "pinSHA256", p.Security.PinSHA256)
		if p.Security.Insecure {
			q.Set("insecure", "1")
		}
		if h := p.Hysteria; h != nil {
			if h.Obfs != "" {
				q.Set("obfs", h.Obfs)
				setIf(q, "obfs-password", h.ObfsPassword)
			}
			if h.UpMbps > 0 {
				q.Set("upmbps", strconv.Itoa(h.UpMbps))
			}
			if h.DownMbps > 0 {
				q.Set("downmbps", strconv.Itoa(h.DownMbps))
			}
		}
		s := "hysteria2://" + url.User(p.Password).String() + "@" + hostport
		if len(q) > 0 {
			s += "?" + q.Encode()
		}
		return s + frag, true
	case profile.WireGuard:
		if p.WireGuard == nil {
			return "", false
		}
		return encodeWireGuard(p, hostport, frag), true
	case profile.TUIC:
		return encodeTUIC(p, hostport, frag), true
	case profile.Hysteria:
		return encodeHysteria1(p, hostport, frag), true
	case profile.AnyTLS:
		return encodeAnyTLS(p, hostport, frag), true
	case profile.Naive:
		return encodeNaive(p, hostport, frag), true
	}
	return "", false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

// streamQuery renders the transport and security layers in the query format
// paramsFromQuery reads.
func streamQuery(p profile.Profile) url.Values {
	q := url.Values{}
	t := p.Transport
	q.Set("type", orDefault(t.Type, "tcp"))
	setIf(q, "path", t.Path)
	setIf(q, "host", t.Host)
	setIf(q, "serviceName", t.ServiceName)
	setIf(q, "authority", t.Authority)
	setIf(q, "mode", t.Mode)
	setIf(q, "headerType", t.HeaderType)
	setIf(q, "seed", t.Seed)

	s := p.Security
	q.Set("security", orDefault(s.Kind, "none"))
	setIf(q, "sni", s.SNI)
	setIf(q, "fp", s.Fingerprint)
	if len(s.ALPN) > 0 {
		q.Set("alpn", strings.Join(s.ALPN, ","))
	}
	if s.Insecure {
		q.Set("allowInsecure", "1")
	}
	setIf(q, "pbk", s.PublicKey)
	setIf(q, "sid", s.ShortID)
	setIf(q, "spx", s.SpiderX)
	return q
}

func encodeVMess(p profile.Profile, name string) string {
	t := p.Transport
	v := map[string]any{
		"v": "2", "ps": name, "add": p.Server, "port": strconv.Itoa(p.Port), "id": p.UUID,
		"aid": strconv.Itoa(p.AlterID), "scy": orDefault(p.Cipher, "auto"), "net": orDefault(t.Type, "tcp"),
		"host": t.Host, "path": t.Path, "tls": "", "sni": p.Security.SNI, "fp": p.Security.Fingerprint,
		"alpn": strings.Join(p.Security.ALPN, ","), "type": t.HeaderType,
	}
	if p.Security.Kind == "tls" {
		v["tls"] = "tls"
	}
	if t.Type == "grpc" {
		v["path"] = t.ServiceName
		v["type"] = ""
		if t.Mode == "multi" {
			v["type"] = "multi"
		}
	}
	b, _ := json.Marshal(v)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

// ProfileNode builds the node record for a profile that came from somewhere
// other than a share link (manual form, Clash, sing-box JSON). When a canonical
// link exists it becomes the node's RawLink, so the node behaves exactly like
// an imported one; otherwise the profile itself is stored.
func ProfileNode(p profile.Profile, name string) (Result, error) {
	if err := p.Validate(); err != nil {
		return Result{}, err
	}
	if p.Protocol == profile.Custom {
		// show the exit server's address where there is one
		p.Server, p.Port = profile.CustomEndpoint(p.Custom)
		if p.Server == "" {
			p.Server = "custom"
		}
		if strings.TrimSpace(name) == "" {
			name = "Custom " + map[string]string{"xray": "Xray", "sing-box": "sing-box"}[p.Custom.Engine]
		}
	}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("%s-%s:%d", p.Protocol, p.Server, p.Port)
	}
	if raw, ok := Encode(p, name); ok {
		res, err := Parse(raw)
		if err == nil && lossless(p, res.Profile) {
			res.Node.Name = name
			return res, nil
		}
		// The link format cannot carry everything (e.g. a Clash option with no
		// URI parameter): keep the full profile instead of a lossy link.
	}
	b, err := json.Marshal(p)
	if err != nil {
		return Result{}, err
	}
	n := newNode(name, p.Protocol, p.Server, p.Port, "")
	n.ID = ProfileID(b)
	n.Profile = b
	return Result{Node: n, Profile: p}, nil
}

// ProfileID derives a stable node ID from a stored profile.
func ProfileID(profileJSON []byte) string { return NodeID("profile:" + string(profileJSON)) }

// NodeProfile returns the profile of a stored node, from its link or its
// stored profile.
func NodeProfile(rawLink string, profileJSON []byte) (profile.Profile, error) {
	if rawLink != "" {
		res, err := Parse(rawLink)
		if err != nil {
			return profile.Profile{}, err
		}
		return res.Profile, nil
	}
	if len(profileJSON) == 0 {
		return profile.Profile{}, fmt.Errorf("node has neither a link nor a profile")
	}
	var p profile.Profile
	if err := json.Unmarshal(profileJSON, &p); err != nil {
		return profile.Profile{}, fmt.Errorf("stored profile is corrupt")
	}
	return p, p.Validate()
}

// lossless reports whether b (a profile read back from a's canonical link)
// keeps every field that changes how the server is reached. Defaults that a
// parser fills in (encryption "none", security "none") are not differences.
func lossless(a, b profile.Profile) bool {
	if a.Server != b.Server || a.Port != b.Port || a.UUID != b.UUID || a.Password != b.Password ||
		a.Username != b.Username || a.Cipher != b.Cipher || a.Flow != b.Flow || a.AlterID != b.AlterID {
		return false
	}
	as, bs := a.Security, b.Security
	if as.SNI != bs.SNI || as.PinSHA256 != bs.PinSHA256 || as.PublicKey != bs.PublicKey || as.ShortID != bs.ShortID ||
		as.Insecure != bs.Insecure || (as.Fingerprint != "" && as.Fingerprint != bs.Fingerprint) ||
		(len(as.ALPN) > 0 && !reflect.DeepEqual(as.ALPN, bs.ALPN)) || (as.Kind != "" && as.Kind != bs.Kind) {
		return false
	}
	at, bt := a.Transport, b.Transport
	if (at.Type != "" && at.Type != bt.Type) || at.Path != bt.Path && at.Path != "" || at.Host != bt.Host ||
		at.ServiceName != bt.ServiceName || at.Mode != bt.Mode || at.HeaderType != bt.HeaderType || at.Seed != bt.Seed {
		return false
	}
	return reflect.DeepEqual(a.Hysteria, b.Hysteria) && reflect.DeepEqual(a.WireGuard, b.WireGuard) &&
		reflect.DeepEqual(a.TUIC, b.TUIC) && reflect.DeepEqual(a.AnyTLS, b.AnyTLS) && reflect.DeepEqual(a.Naive, b.Naive)
}
