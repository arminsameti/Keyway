package link

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// Item kinds produced by Classify.
const (
	KindReady        = "ready"
	KindSubscription = "subscription"
	KindSkipped      = "skipped"
)

// Item is one entry found in pasted text.
type Item struct {
	Line   int    // 1-based line in the (decoded) text
	Kind   string // ready | subscription | skipped
	Scheme string
	Result Result // set when Kind is ready
	URL    string // set when Kind is subscription
	Reason string // set when Kind is skipped; never contains the link itself
	Label  string // how to name a skipped entry from a config file ("HK 01 (snell)")
	Name   string // the entry's own name in a config file (Clash), for matching group members
}

// Formats recognised by DetectFormat.
const (
	FormatSingBox   = "sing-box"
	FormatClash     = "clash"
	FormatWireGuard = "wireguard"
	FormatOVPN      = "openvpn"
	FormatLinks     = "links"
	FormatBase64    = "base64"
)

// DetectFormat names the format of pasted text or a subscription body.
func DetectFormat(text string) string {
	switch {
	case LooksLikeSingBox(text):
		return FormatSingBox
	case LooksLikeClash(text):
		return FormatClash
	case LooksLikeWireGuardConf(text):
		return FormatWireGuard
	case LooksLikeOVPN(text):
		return FormatOVPN
	case strings.Contains(text, "://"):
		return FormatLinks
	}
	return FormatBase64
}

// Classify reads pasted text (or a subscription body) without saving or
// fetching anything. It understands sing-box JSON, Clash YAML, a WireGuard
// .conf file, and lines of share links; a text without any "://" is tried as
// one base64 blob (the usual subscription format). Share links are parsed,
// http(s) URLs are subscriptions, and everything else is reported as skipped
// with a reason. Later copies of the same server are skipped too.
func Classify(text string) []Item {
	var items []Item
	switch DetectFormat(text) {
	case FormatSingBox:
		var err error
		if items, err = ParseSingBox(text); err != nil {
			items = []Item{{Line: 1, Kind: KindSkipped, Reason: capitalize(err.Error())}}
		}
	case FormatClash:
		var err error
		if items, err = ParseClash(text); err != nil {
			items = []Item{{Line: 1, Kind: KindSkipped, Reason: capitalize(err.Error())}}
		}
	case FormatWireGuard:
		it := Item{Line: 1, Scheme: "wireguard", Label: "WireGuard config"}
		res, err := ParseWireGuardConf(text, "")
		if err != nil {
			it.Kind, it.Reason = KindSkipped, capitalize(err.Error())
		} else {
			it.Kind, it.Result = KindReady, res
		}
		items = []Item{it}
	case FormatOVPN:
		it := Item{Line: 1, Scheme: "openvpn", Label: "OpenVPN profile"}
		res, err := ParseOVPN(text, "")
		if err != nil {
			it.Kind, it.Reason = KindSkipped, capitalize(err.Error())
		} else {
			it.Kind, it.Result = KindReady, res
		}
		items = []Item{it}
	default:
		if !strings.Contains(text, "://") {
			if b, err := decodeB64Flexible(text); err == nil && strings.Contains(string(b), "://") {
				text = string(b)
			}
		}
		items = classifyLines(text)
	}
	return dedupe(items)
}

func classifyLines(text string) []Item {
	var items []Item
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		toks := linkTokens(line)
		if len(toks) == 0 {
			items = append(items, Item{Line: i + 1, Kind: KindSkipped, Reason: "Not a share link"})
			continue
		}
		for _, tok := range toks {
			it := Item{Line: i + 1, Scheme: schemeOf(tok)}
			switch it.Scheme {
			case "http", "https":
				if u, err := url.Parse(tok); err == nil && u.Host != "" {
					it.Kind, it.URL = KindSubscription, tok
				} else {
					it.Kind, it.Reason = KindSkipped, "Malformed subscription URL"
				}
			default:
				if res, err := Parse(tok); err != nil {
					it.Kind, it.Reason = KindSkipped, capitalize(err.Error())
				} else {
					it.Kind, it.Result = KindReady, res
				}
			}
			items = append(items, it)
		}
	}
	return items
}

// dedupe marks later copies of the same server as skipped.
func dedupe(items []Item) []Item {
	seen := map[string]int{} // node ID -> line
	for i := range items {
		it := &items[i]
		if it.Kind != KindReady {
			continue
		}
		if first, dup := seen[it.Result.Node.ID]; dup {
			it.Kind, it.Reason, it.Result = KindSkipped, fmt.Sprintf("Same server as line %d", first), Result{}
			continue
		}
		seen[it.Result.Node.ID] = it.Line
	}
	return items
}

// linkTokens splits a line into links. Some apps copy names with raw spaces
// ("vless://...#Frankfurt 01"), so words that follow a link's "#" and are not
// links themselves stay part of its name.
func linkTokens(line string) []string {
	var out []string
	for _, f := range strings.Fields(line) {
		if strings.Contains(f, "://") {
			for _, part := range strings.Split(f, ",") {
				if part = strings.Trim(part, `;"'`); strings.Contains(part, "://") {
					out = append(out, part)
				}
			}
			continue
		}
		if n := len(out); n > 0 && strings.Contains(out[n-1], "#") {
			out[n-1] += " " + strings.Trim(f, `;"',`)
		}
	}
	return out
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
