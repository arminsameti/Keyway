package models

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// ValidationError marks an error caused by invalid user input (HTTP 400).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, a...)}
}

var tagRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

var (
	routingModes = map[string]bool{"global": true, "bypass-private": true, "custom": true, "rules": true}
	enginePrefs  = map[string]bool{"xray": true, "sing-box": true, "v2ray": true, "mihomo": true}
	updateChecks = map[string]bool{"never": true, "daily": true, "weekly": true}
	latencyModes = map[string]bool{"tcp": true, "real": true}
	logLevels    = map[string]bool{"debug": true, "info": true, "warning": true, "error": true, "none": true}
)

// IsLoopback reports whether a listen address only accepts local connections.
func IsLoopback(listen string) bool {
	if listen == "" || strings.EqualFold(listen, "localhost") {
		return true
	}
	ip := net.ParseIP(listen)
	return ip != nil && ip.IsLoopback()
}

// EffectiveListen is the address an inbound really binds to, honouring AllowLAN.
func (s Settings) EffectiveListen(ib Inbound) string {
	listen := ib.Listen
	if listen == "" {
		listen = "127.0.0.1"
	}
	if s.AllowLAN && IsLoopback(listen) {
		return "0.0.0.0"
	}
	return listen
}

// Normalize trims input and fills zero values that have a sensible default.
func (s *Settings) Normalize() {
	d := DefaultSettings()
	s.RoutingMode = strings.TrimSpace(s.RoutingMode)
	if s.RoutingMode == "" {
		s.RoutingMode = d.RoutingMode
	}
	s.TUN.normalize()
	s.LogLevel = strings.ToLower(strings.TrimSpace(s.LogLevel))
	if s.LogLevel == "" {
		s.LogLevel = d.LogLevel
	}
	if s.MuxConcurrency == 0 {
		s.MuxConcurrency = d.MuxConcurrency
	}
	if s.AutoPickMin == 0 {
		s.AutoPickMin = d.AutoPickMin
	}
	if s.APIPort == 0 {
		s.APIPort = d.APIPort
	}
	if s.EnginePreference == "" {
		s.EnginePreference = d.EnginePreference
	}
	if s.EngineUpdateCheck == "" {
		s.EngineUpdateCheck = d.EngineUpdateCheck
	}
	if s.LatencyMethod == "" {
		s.LatencyMethod = d.LatencyMethod
	}
	if s.AppUpdateCheck == "" {
		s.AppUpdateCheck = d.AppUpdateCheck
	}
	dns := make([]string, 0, len(s.DNS))
	for _, e := range s.DNS {
		if e = strings.TrimSpace(e); e != "" {
			dns = append(dns, e)
		}
	}
	s.DNS = dns
	s.DNSMode = strings.ToLower(strings.TrimSpace(s.DNSMode))
	if s.DNSMode == "" {
		s.DNSMode = d.DNSMode
	}
	s.DNSDirect = strings.TrimSpace(s.DNSDirect)
	for i := range s.Inbounds {
		ib := &s.Inbounds[i]
		ib.Tag = strings.TrimSpace(ib.Tag)
		ib.Protocol = strings.ToLower(strings.TrimSpace(ib.Protocol))
		ib.Listen = strings.TrimSpace(ib.Listen)
		if ib.Listen == "" {
			ib.Listen = "127.0.0.1"
		}
	}
}

// Validate checks the settings and returns a *ValidationError describing every problem.
func (s Settings) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, invalid(format, a...)) }

	if !routingModes[s.RoutingMode] {
		add("unknown routing mode %q", s.RoutingMode)
	}
	s.validateRuleSets(add)
	s.TUN.validate(add)
	if !logLevels[s.LogLevel] {
		add("unknown log level %q", s.LogLevel)
	}
	if s.MuxConcurrency < 1 || s.MuxConcurrency > 1024 {
		add("mux concurrency must be 1-1024")
	}
	if s.AutoPickMin < 1 || s.AutoPickMin > 1440 {
		add("auto-pick interval must be 1-1440 minutes")
	}
	if s.SubUpdateHours < 0 || s.SubUpdateHours > 720 {
		add("subscription update interval must be 0-720 hours")
	}
	if s.APIPort < 1 || s.APIPort > 65535 {
		add("API port must be 1-65535")
	}
	if !enginePrefs[s.EnginePreference] {
		add("unknown engine preference %q", s.EnginePreference)
	}
	if !updateChecks[s.EngineUpdateCheck] {
		add("engine update check must be never, daily or weekly")
	}
	if s.AppUpdateCheck != "daily" && s.AppUpdateCheck != "never" {
		add("app update check must be daily or never")
	}
	if !latencyModes[s.LatencyMethod] {
		add("latency method must be tcp or real")
	}
	if len(s.DNS) > 8 {
		add("at most 8 DNS servers")
	}
	for _, e := range s.DNS {
		if strings.ContainsAny(e, " \t\r\n") {
			add("DNS entry %q must not contain whitespace", e)
		}
	}
	s.validateDNS(add)

	tags := map[string]bool{}
	ports := map[int]string{}
	enabled := 0
	for _, ib := range s.Inbounds {
		name := ib.Tag
		if !tagRe.MatchString(ib.Tag) {
			add("inbound tag %q must be 1-32 chars of letters, digits, . _ -", ib.Tag)
		}
		if tags[ib.Tag] {
			add("duplicate inbound tag %q", ib.Tag)
		}
		tags[ib.Tag] = true
		if ib.Protocol != "socks" && ib.Protocol != "http" {
			add("inbound %s: protocol must be socks or http", name)
		}
		if ib.Port < 1 || ib.Port > 65535 {
			add("inbound %s: port must be 1-65535", name)
		}
		if ib.Listen != "" && !IsLoopback(ib.Listen) && net.ParseIP(ib.Listen) == nil {
			add("inbound %s: listen %q is not an IP address", name, ib.Listen)
		}
		if (ib.Username == "") != (ib.Password == "") {
			add("inbound %s: username and password must be set together", name)
		}
		if !ib.Enabled {
			continue
		}
		enabled++
		if other, dup := ports[ib.Port]; dup {
			add("inbound %s: port %d already used by %s", name, ib.Port, other)
		}
		ports[ib.Port] = name
		if ib.Port == s.APIPort {
			add("inbound %s: port %d is the web UI port", name, ib.Port)
		}
		if !IsLoopback(s.EffectiveListen(ib)) && ib.Username == "" {
			add("inbound %s listens on the network; set a username and password (open proxies are refused)", name)
		}
	}
	if enabled == 0 {
		add("enable at least one inbound")
	}
	return errors.Join(errs...)
}
