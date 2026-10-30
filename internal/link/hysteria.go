package link

import (
	"fmt"

	"xray-friendly/internal/profile"
)

// parseHysteria2 maps hysteria2:// / hy2:// links onto Xray's "hysteria" outbound
// (hysteria version 2), which needs a recent Xray core. Salamander obfuscation
// is kept in the profile; engine selection routes such servers to sing-box.
func parseHysteria2(raw string) (Result, error) {
	u, err := parseURL(raw)
	if err != nil {
		return Result{}, err
	}
	auth := ""
	if u.User != nil {
		auth = u.User.Username()
		if p, ok := u.User.Password(); ok {
			auth += ":" + p
		}
	}
	if auth == "" {
		return Result{}, fmt.Errorf("hysteria2: missing auth password")
	}
	host := u.Hostname()
	port, err := parsePort(u.Port(), 443)
	if err != nil {
		return Result{}, fmt.Errorf("hysteria2: %w", err)
	}
	if err := checkEndpoint(host, port); err != nil {
		return Result{}, fmt.Errorf("hysteria2: %w", err)
	}
	q := u.Query()
	opts := &profile.HysteriaOpts{}
	if o := q.Get("obfs"); o != "" && o != "none" {
		if o != "salamander" {
			return Result{}, fmt.Errorf("hysteria2: unknown obfuscation %q", o)
		}
		opts.Obfs, opts.ObfsPassword = o, q.Get("obfs-password")
		if opts.ObfsPassword == "" {
			return Result{}, fmt.Errorf("hysteria2: obfs-password is required with obfs")
		}
	}
	// Not in the official URI scheme, but widely used by clients.
	if opts.UpMbps, err = optInt(q.Get("upmbps")); err != nil {
		return Result{}, fmt.Errorf("hysteria2: upmbps: %w", err)
	}
	if opts.DownMbps, err = optInt(q.Get("downmbps")); err != nil {
		return Result{}, fmt.Errorf("hysteria2: downmbps: %w", err)
	}
	if *opts == (profile.HysteriaOpts{}) {
		opts = nil
	}
	pin := q.Get("pinSHA256")
	if pin != "" && !profile.ValidPin(pin) {
		return Result{}, fmt.Errorf("hysteria2: pinSHA256 must be a hex SHA-256 fingerprint")
	}

	pr := profile.Profile{
		Protocol: profile.Hysteria2, Server: host, Port: port, Password: auth, Hysteria: opts,
		Transport: profile.Transport{Type: "quic"},
		Security: profile.Security{
			Kind:      "tls",
			SNI:       firstNonEmpty(q.Get("sni"), q.Get("peer")),
			ALPN:      []string{"h3"},
			PinSHA256: pin,
			// A pin already authenticates the server, and cores that verify pins
			// reject allowInsecure, so it is only kept for unpinned links.
			Insecure: pin == "" && (q.Get("insecure") == "1" || q.Get("insecure") == "true"),
		},
	}
	name := nameFromFragment(u.Fragment, fmt.Sprintf("hy2-%s:%d", host, port))
	return Result{Node: newNode(name, profile.Hysteria2, host, port, raw), Profile: pr}, nil
}
