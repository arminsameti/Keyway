package link

import (
	"fmt"
	"strings"

	"keyway/internal/profile"
)

func parseTrojan(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	pw := ""
	if u.User != nil {
		pw = u.User.Username()
		if p, ok := u.User.Password(); ok {
			pw += ":" + p
		}
	}
	if strings.TrimSpace(pw) == "" {
		return Result{}, fmt.Errorf("trojan: missing password")
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("trojan: %w", err)
	}
	if err := checkEndpoint(host, port); err != nil {
		return Result{}, fmt.Errorf("trojan: %w", err)
	}

	p := paramsFromQuery(u.Query())
	if p.Security == "" {
		p.Security = "tls" // trojan is TLS unless explicitly disabled
	}
	pr := profile.Profile{Protocol: profile.Trojan, Server: host, Port: port, Password: pw}
	if err := applyStream(&pr, p); err != nil {
		return Result{}, fmt.Errorf("trojan: %w", err)
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("trojan-%s:%d", host, port))
	return Result{Node: newNode(name, profile.Trojan, host, port, raw), Profile: pr}, nil
}
