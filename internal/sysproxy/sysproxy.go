// Package sysproxy toggles the macOS system proxy via networksetup.
package sysproxy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ErrUnsupported is returned on platforms without networksetup.
var ErrUnsupported = errors.New("system proxy control is only available on macOS")

// State is the proxy configuration of one network service.
type State struct {
	Socks  bool `json:"socks"`
	Web    bool `json:"web"`
	Secure bool `json:"secure"`
}

// On reports whether any proxy kind is enabled.
func (s State) On() bool { return s.Socks || s.Web || s.Secure }

// Manager wraps networksetup. The command runner is injectable for tests.
type Manager struct {
	run  func(ctx context.Context, name string, args ...string) (string, error)
	goos string
}

// New returns a Manager that shells out to the real tools.
func New() *Manager { return &Manager{run: execRun, goos: runtime.GOOS} }

// NewWithRunner builds a Manager around a custom command runner and platform
// name; used by tests of this and dependent packages.
func NewWithRunner(goos string, run func(ctx context.Context, name string, args ...string) (string, error)) *Manager {
	return &Manager{run: run, goos: goos}
}

func execRun(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%s: %w: %s", name, err, s)
	}
	return s, nil
}

func (m *Manager) supported() error {
	if m.goos != "darwin" {
		return ErrUnsupported
	}
	return nil
}

// Services lists the enabled network services (disabled ones are marked with "*").
func (m *Manager) Services(ctx context.Context) ([]string, error) {
	if err := m.supported(); err != nil {
		return nil, err
	}
	out, err := m.run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	return parseServices(out), nil
}

func parseServices(out string) []string {
	var svcs []string
	for i, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "*") || (i == 0 && strings.HasPrefix(l, "An asterisk")) {
			continue
		}
		svcs = append(svcs, l)
	}
	return svcs
}

// Primary returns the network service carrying the default route ("" if unknown).
func (m *Manager) Primary(ctx context.Context) string {
	if m.supported() != nil {
		return ""
	}
	route, err := m.run(ctx, "route", "-n", "get", "default")
	if err != nil {
		return ""
	}
	dev := ""
	for _, l := range strings.Split(route, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), ":"); ok && k == "interface" {
			dev = strings.TrimSpace(v)
		}
	}
	if dev == "" {
		return ""
	}
	order, err := m.run(ctx, "networksetup", "-listnetworkserviceorder")
	if err != nil {
		return ""
	}
	return serviceForDevice(order, dev)
}

// serviceForDevice parses `networksetup -listnetworkserviceorder`:
//
//	(1) Wi-Fi
//	(Hardware Port: Wi-Fi, Device: en0)
func serviceForDevice(order, device string) string {
	lines := strings.Split(order, "\n")
	for i := 0; i+1 < len(lines); i++ {
		head := strings.TrimSpace(lines[i])
		next := strings.TrimSpace(lines[i+1])
		if !strings.HasPrefix(head, "(") || !strings.Contains(next, "Device: "+device+")") {
			continue
		}
		if j := strings.Index(head, ") "); j >= 0 {
			return strings.TrimPrefix(strings.TrimSpace(head[j+2:]), "*")
		}
	}
	return ""
}

// validate makes sure service is a real, enabled service name. This both fixes
// typos and prevents a crafted name from being parsed as a networksetup flag.
func (m *Manager) validate(ctx context.Context, service string) error {
	if service == "" || strings.HasPrefix(service, "-") {
		return fmt.Errorf("invalid network service %q", service)
	}
	svcs, err := m.Services(ctx)
	if err != nil {
		return err
	}
	for _, s := range svcs {
		if s == service {
			return nil
		}
	}
	return fmt.Errorf("unknown network service %q", service)
}

// Enable points the service at the local proxies. SOCKS is always set; HTTP and
// HTTPS proxies are set too when httpPort > 0.
func (m *Manager) Enable(ctx context.Context, service, host string, socksPort, httpPort int) error {
	if err := m.validate(ctx, service); err != nil {
		return err
	}
	steps := [][]string{
		{"-setsocksfirewallproxy", service, host, strconv.Itoa(socksPort)},
		{"-setsocksfirewallproxystate", service, "on"},
	}
	if httpPort > 0 {
		steps = append(steps,
			[]string{"-setwebproxy", service, host, strconv.Itoa(httpPort)},
			[]string{"-setwebproxystate", service, "on"},
			[]string{"-setsecurewebproxy", service, host, strconv.Itoa(httpPort)},
			[]string{"-setsecurewebproxystate", service, "on"},
		)
	}
	for _, s := range steps {
		if _, err := m.run(ctx, "networksetup", s...); err != nil {
			_ = m.Disable(ctx, service) // do not leave a half-configured proxy behind
			return err
		}
	}
	return nil
}

// Disable turns all three proxy kinds off for the service.
func (m *Manager) Disable(ctx context.Context, service string) error {
	if err := m.validate(ctx, service); err != nil {
		return err
	}
	var first error
	for _, s := range [][]string{
		{"-setsocksfirewallproxystate", service, "off"},
		{"-setwebproxystate", service, "off"},
		{"-setsecurewebproxystate", service, "off"},
	} {
		if _, err := m.run(ctx, "networksetup", s...); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Get reports the proxy state of one service.
func (m *Manager) Get(ctx context.Context, service string) State {
	enabled := func(flag string) bool {
		out, err := m.run(ctx, "networksetup", flag, service)
		return err == nil && strings.Contains(out, "Enabled: Yes")
	}
	return State{
		Socks:  enabled("-getsocksfirewallproxy"),
		Web:    enabled("-getwebproxy"),
		Secure: enabled("-getsecurewebproxy"),
	}
}
