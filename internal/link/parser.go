// Package link parses proxy share links (vmess://, vless://, ...) into nodes
// and typed Xray outbounds.
package link

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// Result is a parsed link: the node record to persist plus the engine-neutral
// server description that engines build their configuration from.
type Result struct {
	Node    models.Node
	Profile profile.Profile
}

type parser func(raw string) (Result, error)

// parsers maps a lower-case URL scheme to its parser.
var parsers = map[string]parser{
	"vmess":       parseVMess,
	"vless":       parseVLESS,
	"trojan":      parseTrojan,
	"ss":          parseSS,
	"socks":       parseSocks,
	"socks4":      parseSocks,
	"socks5":      parseSocks,
	"hysteria2":   parseHysteria2,
	"hy2":         parseHysteria2,
	"hysteria":    parseHysteria1,
	"wireguard":   parseWireGuard,
	"wg":          parseWireGuard,
	"tuic":        parseTUIC,
	"anytls":      parseAnyTLS,
	"naive+https": parseNaive,
	"naive+quic":  parseNaive,
}

// retired lists schemes that are recognised but deliberately not supported,
// with the reason shown to the user.
var retired = map[string]string{
	"ssr": "ShadowsocksR is retired — skipped",
}

// Schemes lists the supported share-link schemes.
func Schemes() []string {
	out := make([]string, 0, len(parsers))
	for k := range parsers {
		out = append(out, k)
	}
	return out
}

func schemeOf(raw string) string {
	i := strings.Index(raw, "://")
	if i <= 0 {
		return ""
	}
	return strings.ToLower(raw[:i])
}

// Parse parses one share link.
func Parse(raw string) (Result, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Result{}, fmt.Errorf("empty link")
	}
	if why, ok := retired[schemeOf(raw)]; ok {
		return Result{}, errors.New(why)
	}
	p, ok := parsers[schemeOf(raw)]
	if !ok {
		return Result{}, fmt.Errorf("unsupported scheme %q", schemeOf(raw))
	}
	return p(raw)
}

// NodeID derives a stable ID from a link, ignoring the display-name fragment so
// renaming a node in its subscription does not create a duplicate.
func NodeID(raw string) string {
	raw = strings.TrimSpace(raw)
	if i := strings.Index(raw, "#"); i >= 0 {
		raw = raw[:i]
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

func newNode(name, proto, server string, port int, raw string) models.Node {
	return models.Node{
		ID:        NodeID(raw),
		Name:      name,
		Protocol:  proto,
		Server:    server,
		Port:      port,
		RawLink:   raw,
		CreatedAt: time.Now().UTC(),
		LatencyMs: models.LatencyUnknown,
	}
}

// parseURL is url.Parse with scheme checking, shared by the URL-style parsers.
func parseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("malformed link: %w", err)
	}
	return u, nil
}
