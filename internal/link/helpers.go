package link

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// decodeB64Flexible decodes standard/URL-safe base64, with or without padding.
func decodeB64Flexible(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, fmt.Errorf("empty base64")
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// firstNonEmpty returns the first value that is not blank.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parsePort converts and range-checks a port string; blank yields def.
func parsePort(s string, def int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		if def == 0 {
			return 0, fmt.Errorf("missing port")
		}
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

// anyToInt reads a JSON number that may arrive as number or string.
func anyToInt(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return n
		}
	}
	return def
}

func checkEndpoint(host string, port int) error {
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("missing server address")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

// nameFromFragment decodes the URL fragment used as the node's display name.
func nameFromFragment(frag, fallback string) string {
	if frag == "" {
		return fallback
	}
	if d, err := url.PathUnescape(frag); err == nil && strings.TrimSpace(d) != "" {
		return d
	}
	return fallback
}
