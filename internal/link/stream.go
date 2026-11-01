package link

import (
	"fmt"
	"net/url"
	"strings"

	"keyway/internal/profile"
)

// streamParams is the transport/security description shared by all link formats
// (URL query for vless/trojan, JSON fields for vmess).
type streamParams struct {
	Network       string // tcp ws grpc httpupgrade xhttp h2 kcp
	Security      string // none tls reality
	HeaderType    string // tcp/kcp header type
	Host, Path    string
	ServiceName   string
	Authority     string
	Mode          string
	Seed          string
	SNI, ALPN, FP string
	AllowInsecure bool
	PublicKey     string
	ShortID       string
	SpiderX       string
}

func normalizeNetwork(n string) string {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "", "tcp", "raw":
		return "tcp"
	case "gun":
		return "grpc"
	case "splithttp":
		return "xhttp"
	case "http":
		return "h2"
	default:
		return strings.ToLower(strings.TrimSpace(n))
	}
}

func paramsFromQuery(q url.Values) streamParams {
	p := streamParams{
		Network:       normalizeNetwork(q.Get("type")),
		Security:      strings.ToLower(q.Get("security")),
		HeaderType:    q.Get("headerType"),
		Host:          q.Get("host"),
		Path:          q.Get("path"),
		ServiceName:   q.Get("serviceName"),
		Authority:     q.Get("authority"),
		Mode:          q.Get("mode"),
		Seed:          q.Get("seed"),
		SNI:           firstNonEmpty(q.Get("sni"), q.Get("peer")),
		ALPN:          q.Get("alpn"),
		FP:            firstNonEmpty(q.Get("fp"), q.Get("fingerprint")),
		AllowInsecure: q.Get("allowInsecure") == "1" || q.Get("insecure") == "1" || q.Get("allowInsecure") == "true",
		PublicKey:     q.Get("pbk"),
		ShortID:       q.Get("sid"),
		SpiderX:       q.Get("spx"),
	}
	if p.Security == "" {
		if t := strings.ToLower(q.Get("tls")); t == "tls" || t == "1" || t == "true" {
			p.Security = "tls"
		}
	}
	// A reality public key implies reality even if "security" was omitted.
	if p.PublicKey != "" && p.Security != "reality" {
		p.Security = "reality"
	}
	return p
}

// applyStream copies params into the profile's transport and security layers,
// rejecting unknown values so a link never silently becomes a config an engine
// would refuse.
func applyStream(pr *profile.Profile, p streamParams) error {
	if p.Security == "" {
		p.Security = "none"
	}
	sec := profile.Security{Kind: p.Security}
	switch p.Security {
	case "none":
	case "tls":
		sec.SNI = firstNonEmpty(p.SNI, p.Host) // v2rayN behaviour: host doubles as SNI
		sec.Fingerprint = p.FP
		sec.Insecure = p.AllowInsecure
		if p.ALPN != "" {
			sec.ALPN = splitComma(p.ALPN)
		}
	case "reality":
		if p.PublicKey == "" {
			return fmt.Errorf("reality link without public key (pbk)")
		}
		sec.SNI = p.SNI
		sec.Fingerprint = orDefault(p.FP, "chrome")
		sec.PublicKey, sec.ShortID, sec.SpiderX = p.PublicKey, p.ShortID, p.SpiderX
	default:
		return fmt.Errorf("unsupported security %q", p.Security)
	}

	tr := profile.Transport{Type: p.Network}
	switch p.Network {
	case "tcp":
		if strings.EqualFold(p.HeaderType, "http") {
			tr.HeaderType, tr.Path, tr.Host = "http", orDefault(p.Path, "/"), p.Host
		}
	case "ws", "httpupgrade", "xhttp", "h2":
		tr.Path, tr.Host = orDefault(p.Path, "/"), p.Host
		if p.Network == "xhttp" {
			tr.Mode = p.Mode
		}
	case "grpc":
		tr.ServiceName = firstNonEmpty(p.ServiceName, p.Path)
		tr.Authority = p.Authority
		if p.Mode == "multi" {
			tr.Mode = "multi"
		}
	case "kcp":
		tr.Seed = p.Seed
		if p.HeaderType != "" && p.HeaderType != "none" {
			tr.HeaderType = p.HeaderType
		}
	default:
		return fmt.Errorf("unsupported transport %q", p.Network)
	}
	pr.Transport, pr.Security = tr, sec
	return nil
}
