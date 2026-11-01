package xray

import (
	"encoding/json"
	"fmt"

	"keyway/internal/profile"
)

// customOutbounds returns the user's outbounds; the exit comes first (Xray
// sends unmatched traffic to the first outbound) and is tagged "proxy".
func customOutbounds(p profile.Profile) ([]Outbound, error) {
	parts, err := profile.ParseCustom(p.Custom)
	if err != nil {
		return nil, err
	}
	out := make([]Outbound, 0, len(parts.Outbounds))
	for _, m := range parts.Outbounds {
		raw, err := json.Marshal(m)
		if err != nil {
			return nil, fmt.Errorf("custom: %w", err)
		}
		proto, _ := m["protocol"].(string)
		tag, _ := m["tag"].(string)
		out = append(out, Outbound{Tag: tag, Protocol: proto, Raw: raw})
	}
	return out, nil
}
