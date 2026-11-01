package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"keyway/internal/models"
	"keyway/internal/sysproxy"
)

const (
	shutdownTimeout = 20 * time.Second
	sysStateFile    = "sysproxy.json"
)

func (s *Service) sysEnabledCopy() []string {
	s.sysMu.Lock()
	defer s.sysMu.Unlock()
	return append([]string{}, s.sysEnabled...)
}

func (s *Service) persistSysState() {
	p := filepath.Join(s.dir, sysStateFile)
	if len(s.sysEnabled) == 0 {
		_ = os.Remove(p)
		return
	}
	if b, err := json.Marshal(s.sysEnabled); err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

// proxyPorts picks the local ports the system proxy should point at. Inbounds
// with credentials are skipped: the macOS system proxy cannot carry them.
func proxyPorts(st models.Settings) (socks, http int, err error) {
	for _, ib := range st.Inbounds {
		if !ib.Enabled || ib.Username != "" {
			continue
		}
		switch ib.Protocol {
		case "socks":
			if socks == 0 {
				socks = ib.Port
			}
		case "http":
			if http == 0 {
				http = ib.Port
			}
		}
	}
	if socks == 0 {
		return 0, 0, errors.New("the system proxy needs an enabled SOCKS inbound without credentials")
	}
	return socks, http, nil
}

// enableSysProxy turns the system proxy on for services (default: the primary
// network service, else every enabled one) and remembers which ones we touched.
func (s *Service) enableSysProxy(ctx context.Context, st models.Settings, services []string) error {
	socks, http, err := proxyPorts(st)
	if err != nil {
		return err
	}
	if len(services) == 0 {
		if p := s.sys.Primary(ctx); p != "" {
			services = []string{p}
		} else if all, err := s.sys.Services(ctx); err == nil {
			services = all
		} else {
			return err
		}
	}
	s.sysMu.Lock()
	defer s.sysMu.Unlock()
	var errs []error
	for _, svc := range services {
		if err := s.sys.Enable(ctx, svc, "127.0.0.1", socks, http); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", svc, err))
			continue
		}
		if !contains(s.sysEnabled, svc) {
			s.sysEnabled = append(s.sysEnabled, svc)
		}
	}
	s.persistSysState()
	return errors.Join(errs...)
}

// disableSysProxy turns the proxy off for every service this app enabled.
func (s *Service) disableSysProxy(ctx context.Context) error {
	s.sysMu.Lock()
	defer s.sysMu.Unlock()
	var errs []error
	var left []string
	for _, svc := range s.sysEnabled {
		if err := s.sys.Disable(ctx, svc); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", svc, err))
			left = append(left, svc)
		}
	}
	s.sysEnabled = left
	s.persistSysState()
	return errors.Join(errs...)
}

// dropSysProxy is disableSysProxy with its own timeout, for callbacks.
func (s *Service) dropSysProxy() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.disableSysProxy(ctx); err != nil {
		s.log.Warn("disable system proxy", "err", err)
	}
}

// recoverSysProxy undoes a system proxy left behind by a crashed run.
func (s *Service) recoverSysProxy(ctx context.Context) {
	b, err := os.ReadFile(filepath.Join(s.dir, sysStateFile))
	if err != nil {
		return
	}
	var left []string
	if json.Unmarshal(b, &left) != nil {
		_ = os.Remove(filepath.Join(s.dir, sysStateFile))
		return
	}
	s.sysMu.Lock()
	s.sysEnabled = left
	s.sysMu.Unlock()
	s.log.Warn("restoring system proxy left over from a previous run", "services", left)
	if err := s.disableSysProxy(ctx); err != nil {
		s.log.Warn("restore system proxy", "err", err)
	}
}

// SysProxyView describes system-proxy support and state for the UI.
type SysProxyView struct {
	Supported bool                      `json:"supported"`
	Services  []string                  `json:"services"`
	Primary   string                    `json:"primary"`
	Enabled   []string                  `json:"enabled"` // services this app switched on
	States    map[string]sysproxy.State `json:"states"`
}

// SystemProxy reports the proxy state of every network service.
func (s *Service) SystemProxy(ctx context.Context) SysProxyView {
	v := SysProxyView{Services: []string{}, Enabled: s.sysEnabledCopy(), States: map[string]sysproxy.State{}}
	svcs, err := s.sys.Services(ctx)
	if err != nil {
		return v
	}
	v.Supported = true
	v.Services = svcs
	v.Primary = s.sys.Primary(ctx)
	for _, svc := range svcs {
		v.States[svc] = s.sys.Get(ctx, svc)
	}
	return v
}

// SetSystemProxy switches the system proxy on or off by hand.
func (s *Service) SetSystemProxy(ctx context.Context, on bool, services []string) (SysProxyView, error) {
	var err error
	if on {
		err = s.enableSysProxy(ctx, s.store.Get().Settings, services)
	} else {
		if len(services) > 0 { // explicit services: also clear ones we did not enable
			s.sysMu.Lock()
			for _, svc := range services {
				if !contains(s.sysEnabled, svc) {
					s.sysEnabled = append(s.sysEnabled, svc)
				}
			}
			s.sysMu.Unlock()
		}
		err = s.disableSysProxy(ctx)
	}
	return s.SystemProxy(ctx), err
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
