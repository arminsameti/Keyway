package link

import (
	"fmt"

	"xray-friendly/internal/profile"
)

func parseSocks(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 1080)
	if err != nil {
		return Result{}, fmt.Errorf("socks: %w", err)
	}
	if err := checkEndpoint(host, port); err != nil {
		return Result{}, fmt.Errorf("socks: %w", err)
	}
	pr := profile.Profile{
		Protocol: profile.SOCKS, Server: host, Port: port,
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "none"},
	}
	if u.User != nil && u.User.Username() != "" {
		pr.Username = u.User.Username()
		pr.Password, _ = u.User.Password()
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("socks-%s:%d", host, port))
	return Result{Node: newNode(name, profile.SOCKS, host, port, raw), Profile: pr}, nil
}
