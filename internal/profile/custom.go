package profile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Custom is a server whose outbound is written by hand as Xray or sing-box
// JSON. The app keeps control of the inbounds, routing, DNS and statistics, so
// the system proxy, traffic counters and routing rules behave like they do for
// every other server.
const Custom = "custom"

// MaxCustomBytes bounds the stored JSON.
const MaxCustomBytes = 256 << 10

// CustomOpts is the profile of a Custom server.
type CustomOpts struct {
	Engine string `json:"engine"` // xray | sing-box: whose JSON this is
	Config string `json:"config"` // an outbound, an array of outbounds, or a whole config
}

// reservedTags are used by the generated parts of the config.
var reservedTags = map[string]map[string]bool{
	"xray":     {"direct": true, "block": true, "api": true, "fragment": true, "bridge": true},
	"sing-box": {"direct": true, "bridge": true},
}

// CustomParts is a custom config split into the pieces the builders place.
// The first outbound (or endpoint) is the exit and is tagged "proxy".
type CustomParts struct {
	Outbounds []map[string]any
	Endpoints []map[string]any // sing-box only
}

// ParseCustom reads the hand-written JSON and returns its outbounds, with the
// exit renamed to "proxy" (references from the other outbounds follow).
func ParseCustom(c *CustomOpts) (CustomParts, error) {
	var parts CustomParts
	if c == nil {
		return parts, fmt.Errorf("custom: missing configuration")
	}
	if c.Engine != "xray" && c.Engine != "sing-box" {
		return parts, fmt.Errorf("custom: choose Xray or sing-box")
	}
	text := strings.TrimSpace(c.Config)
	if text == "" {
		return parts, fmt.Errorf("custom: paste the outbound JSON")
	}
	if len(text) > MaxCustomBytes {
		return parts, fmt.Errorf("custom: the configuration is larger than %d KB", MaxCustomBytes>>10)
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(text)))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return parts, fmt.Errorf("custom: not valid JSON: %w", err)
	}
	if dec.More() {
		return parts, fmt.Errorf("custom: more than one JSON document")
	}
	kind := "protocol"
	if c.Engine == "sing-box" {
		kind = "type"
	}
	objs := func(v any) ([]map[string]any, error) {
		list, ok := v.([]any)
		if !ok {
			return nil, fmt.Errorf("custom: \"outbounds\" must be a list")
		}
		var out []map[string]any
		for _, e := range list {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("custom: every outbound must be a JSON object")
			}
			out = append(out, m)
		}
		return out, nil
	}
	var err error
	switch d := doc.(type) {
	case []any:
		parts.Outbounds, err = objs(d)
	case map[string]any:
		if _, single := d[kind]; single {
			parts.Outbounds = []map[string]any{d}
		} else {
			if v, ok := d["outbounds"]; ok {
				parts.Outbounds, err = objs(v)
			}
			if v, ok := d["endpoints"]; ok && err == nil && c.Engine == "sing-box" {
				parts.Endpoints, err = objs(v)
			}
		}
	default:
		err = fmt.Errorf("custom: expected an outbound object, a list of outbounds or a full config")
	}
	if err != nil {
		return parts, err
	}
	if len(parts.Outbounds)+len(parts.Endpoints) == 0 {
		return parts, fmt.Errorf("custom: no outbounds found (an outbound needs a %q field)", kind)
	}
	return parts, parts.finish(c.Engine, kind)
}

func (p *CustomParts) finish(engine, kind string) error {
	all := append(append([]map[string]any(nil), p.Outbounds...), p.Endpoints...)
	for _, m := range all {
		if _, ok := m[kind].(string); !ok {
			return fmt.Errorf("custom: an outbound has no %q field", kind)
		}
		if tag, _ := m["tag"].(string); reservedTags[engine][tag] {
			return fmt.Errorf("custom: the tag %q is used by the app; rename that outbound", tag)
		}
	}
	first := all[0]
	old, _ := first["tag"].(string)
	if old != "proxy" {
		for _, m := range all[1:] {
			if t, _ := m["tag"].(string); t == "proxy" {
				return fmt.Errorf("custom: the first outbound is the exit; rename the other outbound tagged \"proxy\"")
			}
		}
		first["tag"] = "proxy"
		if old != "" {
			for _, m := range all[1:] {
				renameRefs(m, old, "proxy")
			}
		}
	}
	return nil
}

// renameRefs rewrites dialerProxy / detour references to a renamed tag.
func renameRefs(v any, from, to string) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && s == from && (k == "dialerProxy" || k == "detour") {
				x[k] = to
				continue
			}
			renameRefs(e, from, to)
		}
	case []any:
		for _, e := range x {
			renameRefs(e, from, to)
		}
	}
}

// CustomEndpoint returns the server address of the exit outbound for display,
// or "" when the JSON does not make it easy to tell.
func CustomEndpoint(c *CustomOpts) (host string, port int) {
	parts, err := ParseCustom(c)
	if err != nil {
		return "", 0
	}
	var exit map[string]any
	if len(parts.Outbounds) > 0 {
		exit = parts.Outbounds[0]
	} else {
		exit = parts.Endpoints[0]
	}
	num := func(v any) int {
		if f, ok := v.(float64); ok {
			return int(f)
		}
		return 0
	}
	if s, _ := exit["server"].(string); s != "" { // sing-box
		return s, num(exit["server_port"])
	}
	settings, _ := exit["settings"].(map[string]any) // xray
	for _, key := range []string{"vnext", "servers"} {
		if list, _ := settings[key].([]any); len(list) > 0 {
			if m, _ := list[0].(map[string]any); m != nil {
				a, _ := m["address"].(string)
				return a, num(m["port"])
			}
		}
	}
	if a, _ := settings["address"].(string); a != "" {
		return a, num(settings["port"])
	}
	return "", 0
}

func (p Profile) validateCustom() error {
	_, err := ParseCustom(p.Custom)
	return err
}
