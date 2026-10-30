package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/link"
	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// Latency measurement modes.
const (
	ModeTCP   = "tcp"   // fast TCP connect to the server; cannot test UDP protocols
	ModeProxy = "proxy" // real request through a temporary engine instance
	ModeReal  = "real"  // alias of ModeProxy (the name used in settings)
	ModeAuto  = "auto"  // the latency method from settings
)

const (
	tcpTimeout   = 4 * time.Second
	proxyTimeout = 8 * time.Second
	tcpWorkers   = 16
	proxyWorkers = 4
)

func (s *Service) anyEngineInstalled() bool {
	for _, sl := range s.engines {
		if len(sl.Manager.Installed()) > 0 {
			return true
		}
	}
	return false
}

// Measure tests nodes and returns latency in ms (or a models.Latency* sentinel)
// per node ID, plus the mode that was actually used. In proxy mode each node is
// measured through the engine that would run it.
func (s *Service) Measure(ctx context.Context, nodes []models.Node, mode string) (map[string]int64, string, error) {
	d := s.store.Get()
	switch mode {
	case "", ModeAuto:
		mode = ModeTCP
		if d.Settings.LatencyMethod != ModeTCP && s.anyEngineInstalled() {
			mode = ModeProxy
		}
	case ModeProxy, ModeReal:
		mode = ModeProxy
		if !s.anyEngineInstalled() {
			return nil, mode, fmt.Errorf("%w: download an engine in Settings › Engines", core.ErrNotInstalled)
		}
	case ModeTCP:
	default:
		return nil, mode, &models.ValidationError{Msg: fmt.Sprintf("unknown latency mode %q", mode)}
	}

	workers := tcpWorkers
	if mode == ModeProxy {
		workers = proxyWorkers
	}
	out := make(map[string]int64, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, n := range nodes {
		wg.Add(1)
		go func(n models.Node) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			var ms int64
			if mode == ModeProxy {
				ms = s.probeNode(ctx, d, n)
			} else {
				ms = tcpProbe(ctx, n)
			}
			mu.Lock()
			out[n.ID] = ms
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out, mode, ctx.Err()
}

func tcpProbe(ctx context.Context, n models.Node) int64 {
	if n.Protocol == profile.Chain {
		return models.LatencyNA // only the real test measures a whole chain
	}
	udp := (profile.Profile{Protocol: n.Protocol}).UDPBased()
	if p, err := link.NodeProfile(n.RawLink, n.Profile); err == nil {
		udp = p.UDPBased() // e.g. OpenVPN over TCP can be measured
	}
	if udp {
		return models.LatencyNA // UDP: a TCP dial proves nothing
	}
	d := net.Dialer{Timeout: tcpTimeout}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(n.Server, strconv.Itoa(n.Port)))
	if err != nil {
		return models.LatencyFailed
	}
	c.Close()
	return time.Since(start).Milliseconds()
}

// probeNode measures one stored node (a server or a chain) end-to-end. A node
// whose engine is not installed cannot be measured in this mode (n/a), which
// is different from one that does not answer (failed).
func (s *Service) probeNode(ctx context.Context, d models.AppData, n models.Node) int64 {
	hops, names, err := s.resolveHops(d, n)
	if err != nil {
		return models.LatencyFailed
	}
	pl, err := s.planFor(hops, names, d)
	if err != nil {
		if errors.Is(err, core.ErrNotInstalled) {
			return models.LatencyNA
		}
		return models.LatencyFailed
	}
	ms, err := s.probe(ctx, pl)
	if err != nil {
		s.log.Debug("probe failed", "node", n.Name, "engines", engine.EngineNames(pl.steps), "err", err)
		return models.LatencyFailed
	}
	return ms
}

func (s *Service) applyLatencies(lat map[string]int64) {
	if len(lat) == 0 {
		return
	}
	if _, err := s.store.Update(func(d *models.AppData) error {
		for i := range d.Nodes {
			if v, ok := lat[d.Nodes[i].ID]; ok {
				d.Nodes[i].LatencyMs = v
			}
		}
		return nil
	}); err != nil {
		s.log.Warn("save latencies", "err", err)
	}
}

// TestLatency measures every node and stores the results.
func (s *Service) TestLatency(ctx context.Context, mode string) (map[string]int64, string, error) {
	nodes := s.store.Get().Nodes
	if len(nodes) == 0 {
		return map[string]int64{}, mode, nil
	}
	lat, used, err := s.Measure(ctx, nodes, mode)
	s.applyLatencies(lat)
	return lat, used, err
}

// chooseBest returns the reachable node with the lowest latency (first wins ties).
func chooseBest(nodes []models.Node, lat map[string]int64) (id string, ms int64) {
	id, ms = "", -1
	for _, n := range nodes {
		v, ok := lat[n.ID]
		if !ok || v < 0 {
			continue
		}
		if id == "" || v < ms {
			id, ms = n.ID, v
		}
	}
	return id, ms
}

// shouldSwitch decides whether auto-pick may abandon the current node: only if
// it is unusable, or the candidate is clearly better (>=30% and >=50 ms faster).
// Without this, two similar nodes would make the connection flap every cycle.
func shouldSwitch(cur int64, curKnown bool, best int64) bool {
	if !curKnown || cur < 0 {
		return true
	}
	return best*10 <= cur*7 && cur-best >= 50
}

// PickResult is the outcome of PickFastest.
type PickResult struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	LatencyMs   int64            `json:"latencyMs"`
	Latency     map[string]int64 `json:"latency"`
	Mode        string           `json:"mode"`
	Reconnected bool             `json:"reconnected"`
}

// PickFastest tests all nodes, selects the fastest and optionally reconnects.
// On ErrAllFailed the returned result still carries the measured latencies.
func (s *Service) PickFastest(ctx context.Context, reconnect bool, mode string) (PickResult, error) {
	d := s.store.Get()
	if len(d.Nodes) == 0 {
		return PickResult{}, ErrNoNodes
	}
	lat, used, err := s.Measure(ctx, d.Nodes, mode)
	if err != nil {
		return PickResult{}, err
	}
	s.applyLatencies(lat)
	res := PickResult{Latency: lat, Mode: used}
	id, ms := chooseBest(d.Nodes, lat)
	if id == "" {
		return res, ErrAllFailed
	}
	if err := s.SetActive(id); err != nil {
		return res, err
	}
	n, _ := d.FindNode(id)
	res.ID, res.Name, res.LatencyMs = id, n.Name, ms
	if reconnect && s.run.IsRunning() {
		if _, err := s.Reconnect(ctx); err != nil {
			return res, fmt.Errorf("selected %q but reconnect failed: %w", n.Name, err)
		}
		res.Reconnected = true
	}
	return res, nil
}

// AutoPickOnce is one iteration of the auto-pick loop.
func (s *Service) AutoPickOnce(ctx context.Context) (switched bool, err error) {
	d := s.store.Get()
	if len(d.Nodes) == 0 {
		return false, nil
	}
	lat, _, err := s.Measure(ctx, d.Nodes, ModeAuto)
	if err != nil {
		return false, err
	}
	s.applyLatencies(lat)
	best, bestMs := chooseBest(d.Nodes, lat)
	if best == "" || best == d.ActiveNodeID {
		return false, nil
	}
	cur, known := lat[d.ActiveNodeID]
	if !shouldSwitch(cur, known, bestMs) {
		return false, nil
	}
	if err := s.SetActive(best); err != nil {
		return false, err
	}
	n, _ := d.FindNode(best)
	s.log.Info("auto-pick switched node", "node", n.Name, "ms", bestMs)
	if s.run.IsRunning() {
		if _, err := s.Reconnect(ctx); err != nil {
			return true, err
		}
	}
	return true, nil
}
