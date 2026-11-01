package link

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// cfg is one decoded YAML/JSON object with typed, forgiving getters: numbers
// may arrive as strings, lists as comma-separated strings.
type cfg map[string]any

func (c cfg) str(keys ...string) string {
	for _, k := range keys {
		switch v := c[k].(type) {
		case string:
			if v != "" {
				return v
			}
		case int, int64, float64, json.Number:
			return fmt.Sprint(v)
		}
	}
	return ""
}

func (c cfg) num(keys ...string) int {
	for _, k := range keys {
		switch v := c[k].(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case json.Number:
			n, _ := v.Int64()
			return int(n)
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				return n
			}
		}
	}
	return 0
}

func (c cfg) flag(keys ...string) bool {
	for _, k := range keys {
		switch v := c[k].(type) {
		case bool:
			if v {
				return true
			}
		case string:
			if truthy(v) {
				return true
			}
		}
	}
	return false
}

func (c cfg) obj(key string) cfg {
	switch v := c[key].(type) {
	case map[string]any:
		return cfg(v)
	case cfg:
		return v
	}
	return cfg{}
}

func (c cfg) list(keys ...string) []string {
	for _, k := range keys {
		switch v := c[k].(type) {
		case string:
			if v != "" {
				return splitComma(v)
			}
		case []any:
			var out []string
			for _, e := range v {
				if s := fmt.Sprint(e); s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}

func (c cfg) objs(key string) []cfg {
	raw, _ := c[key].([]any)
	var out []cfg
	for _, e := range raw {
		if m, ok := e.(map[string]any); ok {
			out = append(out, cfg(m))
		}
	}
	return out
}

// ints reads a list of small numbers ([1,2,3] or "1,2,3").
func (c cfg) ints(key string) ([]int, error) {
	switch v := c[key].(type) {
	case nil:
		return nil, nil
	case string:
		return parseReserved(v)
	case []any:
		var out []int
		for _, e := range v {
			n := cfg{"n": e}.num("n")
			if n < 0 || n > 255 {
				return nil, fmt.Errorf("reserved must be three numbers 0-255")
			}
			out = append(out, n)
		}
		if len(out) != 3 {
			return nil, fmt.Errorf("reserved must be three numbers 0-255")
		}
		return out, nil
	}
	return nil, fmt.Errorf("reserved must be three numbers 0-255")
}

// mbps reads a bandwidth such as 50, "50", "50 Mbps" or "100 mbps".
func mbps(c cfg, keys ...string) int {
	s := strings.ToLower(c.str(keys...))
	s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(s, "mbps"), "m"))
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
