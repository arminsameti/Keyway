package link

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"keyway/internal/profile"
)

var ssMethods = map[string]bool{
	"aes-128-gcm": true, "aes-256-gcm": true, "chacha20-poly1305": true,
	"chacha20-ietf-poly1305": true, "xchacha20-poly1305": true, "xchacha20-ietf-poly1305": true,
	"none": true, "plain": true,
}

func ssMethodOK(m string) bool { return ssMethods[m] || strings.HasPrefix(m, "2022-blake3-") }

// parseSS handles both Shadowsocks URI forms:
//
//	SIP002:  ss://base64(method:password)@host:port[?plugin=..]#name   (or plain method:password)
//	legacy:  ss://base64(method:password@host:port)#name
func parseSS(raw string) (Result, error) {
	body := raw[len("ss://"):]
	frag := ""
	if i := strings.Index(body, "#"); i >= 0 {
		body, frag = body[:i], body[i+1:]
	}
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		body, query = body[:i], body[i+1:]
	}
	if q, err := url.ParseQuery(query); err == nil && q.Get("plugin") != "" {
		return Result{}, fmt.Errorf("ss: plugins are not supported")
	}
	body = strings.TrimSuffix(body, "/")

	var userinfo, hostport string
	if at := strings.LastIndex(body, "@"); at >= 0 {
		userinfo, hostport = body[:at], body[at+1:]
	} else {
		dec, err := decodeB64Flexible(body)
		if err != nil {
			return Result{}, fmt.Errorf("ss: invalid encoding")
		}
		s := string(dec)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return Result{}, fmt.Errorf("ss: invalid encoding")
		}
		userinfo, hostport = s[:at], s[at+1:]
	}

	// userinfo is "method:password" (possibly percent-encoded) or its base64 form.
	cred := userinfo
	if un, err := url.PathUnescape(userinfo); err == nil {
		cred = un
	}
	if !strings.Contains(cred, ":") {
		dec, err := decodeB64Flexible(userinfo)
		if err != nil {
			return Result{}, fmt.Errorf("ss: invalid credentials")
		}
		cred = string(dec)
	}
	method, password, ok := strings.Cut(cred, ":")
	if !ok || password == "" {
		return Result{}, fmt.Errorf("ss: invalid credentials")
	}
	method = strings.ToLower(method)
	if !ssMethodOK(method) {
		return Result{}, fmt.Errorf("ss: unsupported cipher %q", method)
	}

	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return Result{}, fmt.Errorf("ss: invalid server address")
	}
	port, err := parsePort(portStr, 0)
	if err != nil {
		return Result{}, fmt.Errorf("ss: %w", err)
	}
	if err := checkEndpoint(host, port); err != nil {
		return Result{}, fmt.Errorf("ss: %w", err)
	}

	pr := profile.Profile{
		Protocol: profile.Shadowsocks, Server: host, Port: port, Cipher: method, Password: password,
		Transport: profile.Transport{Type: "tcp"}, Security: profile.Security{Kind: "none"},
	}
	name := nameFromFragment(frag, fmt.Sprintf("ss-%s:%d", host, port))
	return Result{Node: newNode(name, profile.Shadowsocks, host, port, raw), Profile: pr}, nil
}
