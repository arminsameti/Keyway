package link

import (
	"fmt"
	"strings"

	"keyway/internal/profile"
)

func parseVLESS(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	id := ""
	if u.User != nil {
		id = u.User.Username()
	}
	if strings.TrimSpace(id) == "" {
		return Result{}, fmt.Errorf("vless: missing user id")
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("vless: %w", err)
	}
	if err := checkEndpoint(host, port); err != nil {
		return Result{}, fmt.Errorf("vless: %w", err)
	}

	q := u.Query()
	pr := profile.Profile{
		Protocol: profile.VLESS, Server: host, Port: port,
		UUID: id, Encryption: orDefault(q.Get("encryption"), "none"), Flow: q.Get("flow"),
	}
	if err := applyStream(&pr, paramsFromQuery(q)); err != nil {
		return Result{}, fmt.Errorf("vless: %w", err)
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("vless-%s:%d", host, port))
	return Result{Node: newNode(name, profile.VLESS, host, port, raw), Profile: pr}, nil
}
