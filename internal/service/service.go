// Package service holds all application logic: connecting, latency testing,
// fastest-node selection, subscriptions and system-proxy lifecycle. The HTTP
// layer and the auto-pick loop are thin callers of this package, so every
// reconnect or selection rule exists exactly once.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/link"
	"xray-friendly/internal/models"
	"xray-friendly/internal/store"
	"xray-friendly/internal/sysproxy"
)

// Sentinel errors the HTTP layer maps to status codes.
var (
	ErrNoActiveNode = errors.New("select a node first")
	ErrNodeNotFound = errors.New("node not found")
	ErrNoNodes      = errors.New("no nodes yet; import a link or subscription first")
	ErrAllFailed    = errors.New("all nodes failed")
	ErrBusy         = errors.New("another operation of this kind is already in progress")
)

// EngineSlot pairs a proxy engine with the manager of its installed versions.
type EngineSlot struct {
	Engine  engine.Engine
	Manager *core.Manager
}

// Config wires the service's collaborators.
type Config struct {
	Store      *store.Store
	Engines    []EngineSlot // in order of precedence when no preference applies
	EnginesDir string       // parent of every engine's install dir (stale-process reaping)
	Runner     *engine.Runner
	Sys        *sysproxy.Manager
	Logger     *slog.Logger
	Dir        string // data directory (config.json, sysproxy.json live here)
	// AutoDownload lets the service fetch a missing engine when a server needs
	// it (and settings.autoDownloadEngines agrees). Off in tests.
	AutoDownload bool
}

// Service is the application core.
type Service struct {
	store      *store.Store
	engines    []EngineSlot
	enginesDir string
	run        *engine.Runner
	sys        *sysproxy.Manager
	log        *slog.Logger
	dir        string
	autoDL     bool

	trafficMu sync.Mutex
	traffic   *trafficMeter

	curMu sync.Mutex
	cur   runInfo // what the running engine was started with

	// extra holds the earlier processes of a multi-process chain; s.run is the
	// last one, which serves the user's inbounds.
	extraMu sync.Mutex
	extra   []*engine.Runner
	jobs    jobs // background engine downloads

	life   sync.Mutex // serialises connect / disconnect / reconnect
	subMu  sync.Mutex // serialises subscription refreshes
	coreMu sync.Mutex // serialises core downloads

	sysMu      sync.Mutex
	sysEnabled []string // network services whose proxy we switched on

	verMu    sync.Mutex
	verCache map[string]string
	tagCache map[string]map[string]bool

	fetch func(ctx context.Context, url string) (string, error) // replaceable in tests
}

// New builds the service and migrates old data if needed.
func New(c Config) (*Service, error) {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if len(c.Engines) == 0 {
		return nil, errors.New("service: no engines configured")
	}
	s := &Service{
		store: c.Store, engines: c.Engines, enginesDir: c.EnginesDir, run: c.Runner, sys: c.Sys, log: c.Logger, dir: c.Dir,
		autoDL:   c.AutoDownload,
		verCache: map[string]string{}, tagCache: map[string]map[string]bool{},
		fetch: safeFetch,
	}
	s.run.OnExit(s.onEngineExit)
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate data: %w", err)
	}
	s.syncTags()
	return s, nil
}

// migrate upgrades older documents step by step.
func (s *Service) migrate() error {
	if s.store.Get().Version >= models.SchemaVersion {
		return nil
	}
	_, err := s.store.Update(func(d *models.AppData) error {
		if d.Version < 2 {
			migrateNodeIDs(d)
		}
		if d.Version < 3 {
			// v3: one active version per engine, and the engine settings.
			if d.ActiveCore != "" {
				d.Engines[engine.NameXray] = d.ActiveCore
			}
			d.ActiveCore = ""
			def := models.DefaultSettings()
			d.Settings.AutoDownloadEngines = def.AutoDownloadEngines // zero value in v2 documents
			if d.Settings.LatencyMethod == "" {
				d.Settings.LatencyMethod = def.LatencyMethod
			}
		}
		d.Version = models.SchemaVersion
		return nil
	})
	return err
}

// migrateNodeIDs (v1 -> v2) switches node IDs to the fragment-independent scheme.
func migrateNodeIDs(d *models.AppData) {
	{
		idMap := map[string]string{}
		seen := map[string]bool{}
		var nodes []models.Node
		for _, n := range d.Nodes {
			id := n.ID
			if n.RawLink != "" {
				id = link.NodeID(n.RawLink)
			}
			idMap[n.ID] = id
			if seen[id] {
				continue
			}
			seen[id] = true
			n.ID = id
			nodes = append(nodes, n)
		}
		d.Nodes = nodes
		if m, ok := idMap[d.ActiveNodeID]; ok {
			d.ActiveNodeID = m
		}
	}
}

// runInfo describes what the running engine was started with.
type runInfo struct {
	NodeID  string
	Engine  engine.Engine // the process that carries the user's traffic
	Version string
	Label   string // every engine of the connection, e.g. "sing-box + Xray core"
	TUN     bool   // sing-box runs with a TUN interface
}

func (s *Service) setCurrent(r runInfo) {
	s.curMu.Lock()
	s.cur = r
	s.curMu.Unlock()
}

func (s *Service) current() runInfo {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	return s.cur
}

// State is the full snapshot a UI renders.
type State struct {
	Nodes         []NodeView            `json:"nodes"`
	ActiveNodeID  string                `json:"activeNodeId"`
	Settings      models.Settings       `json:"settings"`
	Engines       []EngineView          `json:"engines"`
	Subscriptions []models.Subscription `json:"subscriptions"`
	Running       bool                  `json:"running"`
	Warning       string                `json:"warning,omitempty"`
	SystemProxy   []string              `json:"systemProxyServices"`
}

// State returns the current snapshot.
func (s *Service) State() State {
	d := s.store.Get()
	return State{
		Nodes:         s.nodeViews(d),
		ActiveNodeID:  d.ActiveNodeID,
		Settings:      d.Settings,
		Engines:       s.Engines(),
		Subscriptions: d.Subscriptions,
		Running:       s.run.IsRunning(),
		Warning:       s.store.Warning(),
		SystemProxy:   s.sysEnabledCopy(),
	}
}

func (s *Service) engineVersion(bin string) string {
	s.verMu.Lock()
	defer s.verMu.Unlock()
	if v, ok := s.verCache[bin]; ok {
		return v
	}
	v := core.VersionOf(bin)
	if v != "" {
		s.verCache[bin] = v
	}
	return v
}

// Status is the lightweight runtime view used for polling.
type Status struct {
	engine.Status
	ActiveNode      string   `json:"activeNode"` // display name (no flag emoji)
	ActiveNodeID    string   `json:"activeNodeId"`
	ActiveCountry   string   `json:"activeCountryCode,omitempty"`
	ActiveLatencyMs int64    `json:"activeLatencyMs"`
	Protocol        string   `json:"protocol,omitempty"`
	Transport       string   `json:"transport,omitempty"`
	Engine          string   `json:"engine,omitempty"` // engine name while running
	EngineVersion   string   `json:"engineVersion,omitempty"`
	EngineLabel     string   `json:"engineLabel,omitempty"` // all engines of the connection
	UptimeSec       int64    `json:"uptimeSec"`
	RoutingMode     string   `json:"routingMode"`
	AutoPick        bool     `json:"autoPick"`
	SystemProxy     []string `json:"systemProxyServices"`
	SystemProxyOn   bool     `json:"systemProxyOn"`
	TUNOn           bool     `json:"tunOn"` // all traffic is captured by a TUN interface
}

// Status returns the runner state plus what is connected.
func (s *Service) Status() Status {
	d := s.store.Get()
	st := Status{
		Status: s.run.Status(), AutoPick: d.Settings.AutoPick, RoutingMode: d.Settings.RoutingMode,
		SystemProxy: s.sysEnabledCopy(), ActiveLatencyMs: models.LatencyUnknown,
	}
	st.SystemProxyOn = len(st.SystemProxy) > 0
	id := d.ActiveNodeID
	if st.Running {
		cur := s.current()
		if cur.NodeID != "" {
			id = cur.NodeID
		}
		if cur.Engine != nil {
			st.Engine, st.EngineVersion, st.EngineLabel = cur.Engine.Name(), cur.Version, cur.Label
			st.TUNOn = cur.TUN
		}
		if !st.StartedAt.IsZero() {
			st.UptimeSec = int64(time.Since(st.StartedAt).Seconds())
		}
	}
	if n, ok := d.FindNode(id); ok {
		v := s.nodeView(d, n)
		st.ActiveNode, st.ActiveNodeID, st.ActiveLatencyMs, st.ActiveCountry = v.DisplayName, n.ID, n.LatencyMs, v.CountryCode
		st.Protocol, st.Transport = v.ProtocolName, v.Transport
	}
	return st
}

// Logs returns engine log lines from sequence number since.
func (s *Service) Logs(since int) ([]string, int, bool) {
	lines, next := s.run.Logs(since)
	return lines, next, s.run.IsRunning()
}

// ---- nodes ----

// SetActive selects the node used by the next connect.
func (s *Service) SetActive(id string) error {
	_, err := s.store.Update(func(d *models.AppData) error {
		if _, ok := d.FindNode(id); !ok {
			return ErrNodeNotFound
		}
		d.ActiveNodeID = id
		return nil
	})
	return err
}

// DeleteNodes removes nodes by ID; deleting the active node clears the selection.
func (s *Service) DeleteNodes(ids ...string) (int, error) {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	removed := 0
	_, err := s.store.Update(func(d *models.AppData) error {
		keep := make([]models.Node, 0, len(d.Nodes))
		for _, n := range d.Nodes {
			if drop[n.ID] {
				removed++
				continue
			}
			keep = append(keep, n)
		}
		d.Nodes = keep
		if drop[d.ActiveNodeID] {
			d.ActiveNodeID = ""
		}
		return nil
	})
	return removed, err
}

// ErrNoShareLink is returned for nodes whose protocol has no share-link format.
var ErrNoShareLink = &models.ValidationError{Msg: "this server has no share link (its protocol has no link format)"}

// RawLink returns the share link of a node (for Copy Link and QR codes).
func (s *Service) RawLink(id string) (string, error) {
	n, ok := s.store.Get().FindNode(id)
	if !ok {
		return "", ErrNodeNotFound
	}
	if n.RawLink == "" {
		return "", ErrNoShareLink
	}
	return n.RawLink, nil
}

// ConfigJSON returns the last generated engine config.
func (s *Service) ConfigJSON() ([]byte, error) {
	return readFile(filepath.Join(s.dir, "config.json"))
}

// ---- settings ----

// SettingsResult tells the UI what the change implies.
type SettingsResult struct {
	ReconnectRequired bool `json:"reconnectRequired"`
	RestartRequired   bool `json:"restartRequired"`
}

// configRelevant blanks the fields that do not influence the generated xray config.
func configRelevant(st models.Settings) models.Settings {
	st = st.Clone()
	st.AutoPick, st.AutoPickMin, st.AutoConnect, st.AutoSystemProxy, st.SubUpdateHours, st.APIPort = false, 0, false, false, 0, 0
	return st
}

// UpdateSettings validates and persists new settings.
func (s *Service) UpdateSettings(ctx context.Context, in models.Settings) (SettingsResult, error) {
	in.Normalize()
	if err := in.Validate(); err != nil {
		return SettingsResult{}, err
	}
	old := s.store.Get().Settings
	if _, err := s.store.Update(func(d *models.AppData) error {
		d.Settings = in
		return nil
	}); err != nil {
		return SettingsResult{}, err
	}
	res := SettingsResult{RestartRequired: old.APIPort != in.APIPort}
	if s.run.IsRunning() {
		res.ReconnectRequired = !reflect.DeepEqual(configRelevant(old), configRelevant(in))
		if old.AutoSystemProxy != in.AutoSystemProxy {
			if in.AutoSystemProxy {
				if err := s.enableSysProxy(ctx, in, nil); err != nil {
					s.log.Warn("enable system proxy", "err", err)
				}
			} else if err := s.disableSysProxy(ctx); err != nil {
				s.log.Warn("disable system proxy", "err", err)
			}
		}
	}
	return res, nil
}
