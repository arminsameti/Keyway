package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"xray-friendly/internal/engine"
	"xray-friendly/internal/models"
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

// connectLocked requires s.life. Every new config is generated and preflighted
// (xray -test / sing-box check) BEFORE anything running is stopped, so a bad
// config never takes down a working connection.
//
// A server is a one-hop chain. The hops are split into as few processes as
// possible (see engine.PlanSegments); several processes are started in order,
// each dialing through the loopback bridge of the one before it.
func (s *Service) connectLocked(ctx context.Context) (ConnectResult, error) {
	d := s.store.Get()
	node, ok := d.FindNode(d.ActiveNodeID)
	if !ok {
		return ConnectResult{}, ErrNoActiveNode
	}
	hops, names, err := s.resolveHops(d, node)
	if err != nil {
		return ConnectResult{}, fmt.Errorf("node %q: %w", node.Name, err)
	}
	pl, err := s.planFor(hops, names, d, s.finalFor(d))
	for attempt := 0; attempt < len(s.engines); attempt++ {
		var ni *engine.NotInstalledError
		if !errors.As(err, &ni) || !s.autoDownloadOK(d) {
			break
		}
		s.log.Info("downloading the engine this server needs", "engine", ni.Engine.Name())
		if _, derr := s.DownloadEngine(ctx, ni.Engine.Name(), ""); errors.Is(derr, ErrBusy) {
			return ConnectResult{}, fmt.Errorf("%w: %s is still downloading; connect again when it has finished", ErrBusy, ni.Engine.DisplayName())
		} else if derr != nil {
			return ConnectResult{}, fmt.Errorf("%s is needed for this server, and downloading it failed: %w", ni.Engine.DisplayName(), derr)
		}
		d = s.store.Get()
		pl, err = s.planFor(hops, names, d, s.finalFor(d))
	}
	if err != nil {
		return ConnectResult{}, err
	}
	final := pl.finalEngine()
	if err := s.prepare(ctx, final, d); err != nil { // routing rule sets belong to the segment that routes
		return ConnectResult{}, err
	}
	segs, err := pl.segments()
	if err != nil {
		return ConnectResult{}, err
	}

	stats, serr := newStatsAPI()
	if serr != nil {
		return ConnectResult{}, serr
	}
	segs[len(segs)-1].Stats = stats
	if d.Settings.TUN.Enabled {
		segs[len(segs)-1].TUN = tunOptions(d.Settings.TUN, pl)
	}

	// write and preflight every segment's config before touching what runs now
	s.removeSegmentConfigs()
	paths := make([]string, len(segs))
	for k, seg := range segs {
		cfg, err := pl.steps[k].Engine.Config(seg, d.Settings)
		if err != nil {
			return ConnectResult{}, err
		}
		paths[k] = s.segmentConfigPath(k, len(segs))
		if err := engine.WriteConfig(paths[k], cfg); err != nil {
			return ConnectResult{}, err
		}
		if err := pl.steps[k].Engine.Check(ctx, pl.installs[k], paths[k]); err != nil {
			return ConnectResult{}, fmt.Errorf("%s rejected the configuration: %w", pl.steps[k].Engine.DisplayName(), err)
		}
	}

	if err := s.stopAll(); err != nil {
		return ConnectResult{}, err
	}
	if err := s.startAll(pl, paths, d); err != nil {
		_ = s.stopAll()
		s.dropSysProxy()
		return ConnectResult{}, err
	}
	s.startTraffic(trafficSourceFor(final, pl.finalInstall(), stats))
	s.setCurrent(runInfo{NodeID: node.ID, Engine: final, Version: pl.finalInstall().Version, Label: engine.EngineNames(pl.steps), TUN: d.Settings.TUN.Enabled})

	res := ConnectResult{Config: paths[len(paths)-1]}
	for k, st := range pl.steps {
		if d.Engines[st.Engine.Name()] != pl.installs[k].Version {
			if err := s.setActiveEngine(st.Engine.Name(), pl.installs[k].Version); err != nil {
				s.log.Warn("remember active engine version", "err", err)
			}
		}
	}
	if d.Settings.AutoSystemProxy {
		if err := s.enableSysProxy(ctx, d.Settings, nil); err != nil {
			s.log.Warn("enable system proxy", "err", err)
			res.Warning = "connected, but the system proxy could not be set: " + err.Error()
		}
	}
	s.log.Info("connected", "node", node.Name, "hops", len(hops), "engines", engine.EngineNames(pl.steps))
	return res, nil
}

// segmentConfigPath is where a segment's config is written: the last one (the
// one that serves the user) keeps the name config.json.
func (s *Service) segmentConfigPath(k, n int) string {
	if k == n-1 {
		return filepath.Join(s.dir, "config.json")
	}
	return filepath.Join(s.dir, fmt.Sprintf("config-segment-%d.json", k))
}

// removeSegmentConfigs deletes the configs of earlier multi-process chains.
func (s *Service) removeSegmentConfigs() {
	old, _ := filepath.Glob(filepath.Join(s.dir, "config-segment-*.json"))
	for _, f := range old {
		_ = os.Remove(f)
	}
}

// startAll launches the processes of a plan, the entry segment first.
func (s *Service) startAll(pl *connPlan, paths []string, d models.AppData) error {
	last := len(pl.steps) - 1
	for k := 0; k < last; k++ {
		l := pl.steps[k].Engine.Launch(pl.installs[k], paths[k])
		r := engine.NewSegmentRunner(filepath.Join(s.dir, fmt.Sprintf("segment-%d.pid", k)), s.run,
			fmt.Sprintf("hop %d–%d · %s", pl.steps[k].From+1, pl.steps[k].To, pl.steps[k].Engine.DisplayName()))
		r.OnExit(s.onSegmentExit)
		if err := r.Start(engine.StartOptions{Binary: l.Binary, Args: l.Args, Env: l.Env}); err != nil {
			return fmt.Errorf("%s (hops %d–%d): %w", pl.steps[k].Engine.DisplayName(), pl.steps[k].From+1, pl.steps[k].To, err)
		}
		s.extraMu.Lock()
		s.extra = append(s.extra, r)
		s.extraMu.Unlock()
	}
	l := pl.steps[last].Engine.Launch(pl.installs[last], paths[last])
	if d.Settings.TUN.Enabled {
		el, err := s.elevation(d, pl.installs[last], paths[last])
		if err != nil {
			return err
		}
		return s.run.Start(engine.StartOptions{Elevate: el})
	}
	return s.run.Start(engine.StartOptions{Binary: l.Binary, Args: l.Args, Env: l.Env})
}

// stopAll stops the process that serves the user first, then the earlier ones.
func (s *Service) stopAll() error {
	s.stopTraffic()
	err := s.run.Stop()
	s.extraMu.Lock()
	ex := s.extra
	s.extra = nil
	s.extraMu.Unlock()
	for i := len(ex) - 1; i >= 0; i-- {
		if e := ex[i].Stop(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// Disconnect stops the engines and restores any system proxy this app enabled.
func (s *Service) Disconnect(ctx context.Context) error {
	s.life.Lock()
	defer s.life.Unlock()
	err := s.stopAll()
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

// Recover cleans up after a crashed previous run: leftover engine processes
// and a system proxy that would otherwise point at a dead port.
func (s *Service) Recover(ctx context.Context) {
	pids := []string{filepath.Join(s.dir, "xray.pid")}
	more, _ := filepath.Glob(filepath.Join(s.dir, "segment-*.pid"))
	for _, pid := range append(pids, more...) {
		if engine.ReapStale(pid, s.enginesDir) {
			s.log.Warn("stopped a stale engine process from a previous run", "pidfile", filepath.Base(pid))
		}
	}
	s.stopStaleHelper()
	s.recoverSysProxy(ctx)
}

// onEngineExit runs when the last process ends. If it died on its own, the
// system proxy would blackhole the user's traffic, so it is cleared. The earlier
// processes of a chain are useless without it and are stopped too.
func (s *Service) onEngineExit(unexpected bool, err error) {
	if !unexpected {
		return
	}
	s.log.Warn("engine exited unexpectedly", "err", err)
	s.dropSysProxy()
	go func() {
		s.extraMu.Lock()
		ex := s.extra
		s.extra = nil
		s.extraMu.Unlock()
		for i := len(ex) - 1; i >= 0; i-- {
			_ = ex[i].Stop()
		}
	}()
}

// onSegmentExit runs when an earlier process of a chain ends. Without it the
// last process can no longer reach its first hop, so the whole chain is taken
// down instead of pretending to be connected.
func (s *Service) onSegmentExit(unexpected bool, err error) {
	if !unexpected {
		return
	}
	s.log.Warn("a chain segment exited unexpectedly; stopping the chain", "err", err)
	s.dropSysProxy()
	go func() { _ = s.run.Stop() }()
}
