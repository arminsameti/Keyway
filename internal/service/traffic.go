package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"keyway/internal/engine"
	"keyway/internal/profile"
)

const (
	trafficInterval = time.Second
	trafficHistory  = 60 // samples kept for the sparkline
)

// TrafficSample is the speed over one sampling interval, in bytes per second.
type TrafficSample struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Traffic is what the engine of the running connection has carried.
type Traffic struct {
	Available bool            `json:"available"` // false when not connected or the engine reports nothing
	UpBps     int64           `json:"upBps"`
	DownBps   int64           `json:"downBps"`
	UpTotal   int64           `json:"upTotal"`
	DownTotal int64           `json:"downTotal"`
	History   []TrafficSample `json:"history"`
}

// trafficSource reads cumulative byte counters from a running engine.
type trafficSource func(ctx context.Context) (up, down int64, err error)

type trafficMeter struct {
	mu      sync.Mutex
	t       Traffic
	lastUp  int64
	lastDwn int64
	primed  bool
	cancel  context.CancelFunc
}

func (m *trafficMeter) snapshot() Traffic {
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.t
	t.History = append([]TrafficSample(nil), m.t.History...)
	return t
}

func (m *trafficMeter) record(up, down int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.primed && up >= m.lastUp && down >= m.lastDwn {
		s := TrafficSample{Up: up - m.lastUp, Down: down - m.lastDwn}
		m.t.UpBps, m.t.DownBps = s.Up, s.Down
		m.t.History = append(m.t.History, s)
		if len(m.t.History) > trafficHistory {
			m.t.History = m.t.History[len(m.t.History)-trafficHistory:]
		}
	}
	m.lastUp, m.lastDwn, m.primed = up, down, true
	m.t.UpTotal, m.t.DownTotal, m.t.Available = up, down, true
}

// startTraffic begins sampling a freshly started connection.
func (s *Service) startTraffic(src trafficSource) {
	s.stopTraffic()
	ctx, cancel := context.WithCancel(context.Background())
	m := &trafficMeter{cancel: cancel}
	s.trafficMu.Lock()
	s.traffic = m
	s.trafficMu.Unlock()
	go func() {
		tick := time.NewTicker(trafficInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				cctx, c := context.WithTimeout(ctx, 3*time.Second)
				up, down, err := src(cctx)
				c()
				if err == nil {
					m.record(up, down)
				}
			}
		}
	}()
}

func (s *Service) stopTraffic() {
	s.trafficMu.Lock()
	m := s.traffic
	s.traffic = nil
	s.trafficMu.Unlock()
	if m != nil {
		m.cancel()
	}
}

// Traffic returns the counters of the current connection.
func (s *Service) Traffic() Traffic {
	s.trafficMu.Lock()
	m := s.traffic
	s.trafficMu.Unlock()
	if m == nil || !s.run.IsRunning() {
		return Traffic{History: []TrafficSample{}}
	}
	return m.snapshot()
}

// newStatsAPI reserves a loopback port and a secret for the engine's counters.
func newStatsAPI() (*profile.StatsAPI, error) {
	port, err := engine.FreePort()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &profile.StatsAPI{Port: port, Secret: hex.EncodeToString(b)}, nil
}

// trafficSourceFor returns the reader for an engine's stats endpoint.
func trafficSourceFor(e engine.Engine, in engine.Install, api *profile.StatsAPI) trafficSource {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(api.Port))
	if e.Name() == engine.NameXray {
		return func(ctx context.Context) (int64, int64, error) {
			out, err := exec.CommandContext(ctx, in.Bin, "api", "statsquery", "--server="+addr).Output()
			if err != nil {
				return 0, 0, err
			}
			return parseXrayStats(out)
		}
	}
	if e.Name() == engine.NameV2Ray {
		return func(ctx context.Context) (int64, int64, error) {
			out, err := exec.CommandContext(ctx, in.Bin, "api", "stats", "-json", "--server="+addr).Output()
			if err != nil {
				return 0, 0, err
			}
			return parseXrayStats(out)
		}
	}
	client := &http.Client{}
	return func(ctx context.Context) (int64, int64, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/connections", nil)
		if err != nil {
			return 0, 0, err
		}
		req.Header.Set("Authorization", "Bearer "+api.Secret)
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return 0, 0, fmt.Errorf("stats api: %s", resp.Status)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			return 0, 0, err
		}
		return parseSingBoxConnections(body)
	}
}

// parseXrayStats sums the uplink/downlink counters of every outbound except
// the stats API itself.
func parseXrayStats(b []byte) (up, down int64, err error) {
	var doc struct {
		Stat []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return 0, 0, err
	}
	for _, s := range doc.Stat {
		parts := strings.Split(s.Name, ">>>")
		if len(parts) != 4 || parts[0] != "outbound" || parts[1] == "api" {
			continue
		}
		var v int64
		switch x := s.Value.(type) {
		case float64:
			v = int64(x)
		case string:
			v, _ = strconv.ParseInt(x, 10, 64)
		}
		switch parts[3] {
		case "uplink":
			up += v
		case "downlink":
			down += v
		}
	}
	return up, down, nil
}

func parseSingBoxConnections(b []byte) (up, down int64, err error) {
	var doc struct {
		Up   int64 `json:"uploadTotal"`
		Down int64 `json:"downloadTotal"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return 0, 0, err
	}
	return doc.Up, doc.Down, nil
}
