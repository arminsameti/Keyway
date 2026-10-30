package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"xray-friendly/internal/engine"
	"xray-friendly/internal/link"
)

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }

// ConnectResult carries non-fatal information from a successful connect.
type ConnectResult struct {
	Config  string `json:"config"`
	Warning string `json:"warning,omitempty"`
}

// Connect starts (or restarts) xray with the active node.
func (s *Service) Connect(ctx context.Context) (ConnectResult, error) {
	s.life.Lock()
	defer s.life.Unlock()
	return s.connectLocked(ctx)
}

// Reconnect is Connect, named for call sites that switch a running connection.
func (s *Service) Reconnect(ctx context.Context) (ConnectResult, error) { return s.Connect(ctx) }

// connectLocked requires s.life. The new config is generated and preflighted
// (xray -test / sing-box check) BEFORE the running instance is stopped, so a
// bad config never takes down a working connection.
func (s *Service) connectLocked(ctx context.Context) (ConnectResult, error) {
	d := s.store.Get()
	node, ok := d.FindNode(d.ActiveNodeID)
	if !ok {
		return ConnectResult{}, ErrNoActiveNode
	}
	p, err := link.NodeProfile(node.RawLink, node.Profile)
	if err != nil {
		return ConnectResult{}, fmt.Errorf("node %q: %w", node.Name, err)
	}
	e, inst, err := s.resolveFor(p, d)
	var ni *engine.NotInstalledError
	if errors.As(err, &ni) && s.autoDownloadOK(d) {
		s.log.Info("downloading the engine this server needs", "engine", ni.Engine.Name())
		if _, derr := s.DownloadEngine(ctx, ni.Engine.Name(), ""); errors.Is(derr, ErrBusy) {
			return ConnectResult{}, fmt.Errorf("%w: %s is still downloading; connect again when it has finished", ErrBusy, ni.Engine.DisplayName())
		} else if derr != nil {
			return ConnectResult{}, fmt.Errorf("%s is needed for this server, and downloading it failed: %w", ni.Engine.DisplayName(), derr)
		}
		d = s.store.Get()
		e, inst, err = s.resolveFor(p, d)
	}
	if err != nil {
		return ConnectResult{}, err
	}
	if err := s.prepare(ctx, e, d); err != nil {
		return ConnectResult{}, err
	}
	cfg, err := e.Config(p, d.Settings)
	if err != nil {
		return ConnectResult{}, err
	}
	path := filepath.Join(s.dir, "config.json")
	if err := engine.WriteConfig(path, cfg); err != nil {
		return ConnectResult{}, err
	}
	if err := e.Check(ctx, inst, path); err != nil {
		return ConnectResult{}, fmt.Errorf("%s rejected the configuration: %w", e.DisplayName(), err)
	}

	if err := s.run.Stop(); err != nil {
		return ConnectResult{}, err
	}
	l := e.Launch(inst, path)
	if err := s.run.Start(engine.StartOptions{Binary: l.Binary, Args: l.Args, Env: l.Env}); err != nil {
		s.dropSysProxy()
		return ConnectResult{}, err
	}
	s.setCurrent(runInfo{NodeID: node.ID, Engine: e, Version: inst.Version})

	res := ConnectResult{Config: path}
	if d.Engines[e.Name()] != inst.Version {
		if err := s.setActiveEngine(e.Name(), inst.Version); err != nil {
			s.log.Warn("remember active engine version", "err", err)
		}
	}
	if d.Settings.AutoSystemProxy {
		if err := s.enableSysProxy(ctx, d.Settings, nil); err != nil {
			s.log.Warn("enable system proxy", "err", err)
			res.Warning = "connected, but the system proxy could not be set: " + err.Error()
		}
	}
	s.log.Info("connected", "node", node.Name, "engine", e.Name(), "version", inst.Version)
	return res, nil
}

// Disconnect stops the engine and restores any system proxy this app enabled.
func (s *Service) Disconnect(ctx context.Context) error {
	s.life.Lock()
	defer s.life.Unlock()
	err := s.run.Stop()
	if perr := s.disableSysProxy(ctx); perr != nil {
		s.log.Warn("disable system proxy", "err", perr)
		if err == nil {
			err = perr
		}
	}
	return err
}

// Shutdown is called on process exit.
func (s *Service) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = s.Disconnect(ctx)
}

// Recover cleans up after a crashed previous run: a leftover xray process and a
// system proxy that would otherwise point at a dead port.
func (s *Service) Recover(ctx context.Context) {
	if engine.ReapStale(filepath.Join(s.dir, "xray.pid"), s.enginesDir) {
		s.log.Warn("stopped a stale engine process from a previous run")
	}
	s.recoverSysProxy(ctx)
}

// onEngineExit runs when the engine ends. If it died on its own, the system
// proxy would blackhole the user's traffic, so it is cleared.
func (s *Service) onEngineExit(unexpected bool, err error) {
	if !unexpected {
		return
	}
	s.log.Warn("engine exited unexpectedly", "err", err)
	s.dropSysProxy()
}
