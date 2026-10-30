package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"xray-friendly/internal/core"
	"xray-friendly/internal/engine"
	"xray-friendly/internal/link"
	"xray-friendly/internal/models"
	"xray-friendly/internal/profile"
)

// NodeView is a node plus everything the UI derives from its profile.
type NodeView struct {
	models.Node
	DisplayName     string `json:"displayName"`           // name without a leading flag emoji
	CountryCode     string `json:"countryCode,omitempty"` // ISO 3166-1 alpha-2, from the name
	ProtocolName    string `json:"protocolName"`
	Transport       string `json:"transport"`
	Security        string `json:"security"`
	SNI             string `json:"sni"`
	UDP             bool   `json:"udp"`              // TCP latency tests cannot measure it
	Engine          string `json:"engine,omitempty"` // engine that would run it
	EngineName      string `json:"engineName,omitempty"`
	EngineInstalled bool   `json:"engineInstalled"`
	EngineReason    string `json:"engineReason,omitempty"` // why no engine can run it
	HasLink         bool   `json:"hasLink"`
	Error           string `json:"error,omitempty"` // the stored link/profile no longer parses
}

func (s *Service) nodeViews(d models.AppData) []NodeView {
	out := make([]NodeView, 0, len(d.Nodes))
	for _, n := range d.Nodes {
		out = append(out, s.nodeView(d, n))
	}
	return out
}

func (s *Service) nodeView(d models.AppData, n models.Node) NodeView {
	v := NodeView{Node: n, HasLink: n.RawLink != "", ProtocolName: profile.ProtocolName(n.Protocol)}
	v.CountryCode, v.DisplayName = profile.SplitCountry(n.Name)
	p, err := link.NodeProfile(n.RawLink, n.Profile)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Transport, v.Security, v.SNI, v.UDP = p.DisplayTransport(), p.DisplaySecurity(), p.DisplaySNI(), p.UDPBased()
	e, err := engine.Candidate(p, d.Settings.EnginePreference, s.engineList())
	if err != nil {
		v.EngineReason = err.Error()
		return v
	}
	v.Engine, v.EngineName, v.EngineInstalled = e.Name(), e.DisplayName(), s.installed(e.Name())
	return v
}

// Nodes returns every node with its derived fields.
func (s *Service) Nodes() []NodeView { return s.nodeViews(s.store.Get()) }

// NodeInput creates or replaces a node: either a share link or a profile.
type NodeInput struct {
	Name    string           `json:"name"`
	Link    string           `json:"link,omitempty"`
	Profile *profile.Profile `json:"profile,omitempty"`
}

func (in NodeInput) build() (link.Result, error) {
	switch {
	case strings.TrimSpace(in.Link) != "" && in.Profile != nil:
		return link.Result{}, &models.ValidationError{Msg: "give either a link or a profile, not both"}
	case strings.TrimSpace(in.Link) != "":
		res, err := link.Parse(in.Link)
		if err != nil {
			return res, &models.ValidationError{Msg: err.Error()}
		}
		if name := strings.TrimSpace(in.Name); name != "" {
			res.Node.Name = name
		}
		return res, nil
	case in.Profile != nil:
		res, err := link.ProfileNode(*in.Profile, strings.TrimSpace(in.Name))
		if err != nil {
			return res, &models.ValidationError{Msg: err.Error()}
		}
		return res, nil
	}
	return link.Result{}, &models.ValidationError{Msg: "a link or a profile is required"}
}

// ErrDuplicateNode is returned when the server is already in the list.
var ErrDuplicateNode = &models.ValidationError{Msg: "this server is already in the list"}

// CreateNode adds one manually entered server.
func (s *Service) CreateNode(in NodeInput) (NodeView, error) {
	res, err := in.build()
	if err != nil {
		return NodeView{}, err
	}
	d, err := s.store.Update(func(d *models.AppData) error {
		if _, dup := d.FindNode(res.Node.ID); dup {
			return ErrDuplicateNode
		}
		d.Nodes = append(d.Nodes, res.Node)
		return nil
	})
	if err != nil {
		return NodeView{}, err
	}
	s.fetchEnginesFor([]models.Node{res.Node})
	return s.nodeView(d, res.Node), nil
}

// UpdateNode replaces a node's server details, keeping its ID, source and
// position, so the active selection and the subscription grouping survive.
func (s *Service) UpdateNode(id string, in NodeInput) (NodeView, error) {
	res, err := in.build()
	if err != nil {
		return NodeView{}, err
	}
	var out models.Node
	d, err := s.store.Update(func(d *models.AppData) error {
		for i := range d.Nodes {
			n := &d.Nodes[i]
			if n.ID != id {
				continue
			}
			if n.Server != res.Node.Server || n.Port != res.Node.Port || n.Protocol != res.Node.Protocol {
				n.LatencyMs = models.LatencyUnknown
			}
			n.Name, n.Protocol, n.Server, n.Port = res.Node.Name, res.Node.Protocol, res.Node.Server, res.Node.Port
			n.RawLink, n.Profile = res.Node.RawLink, res.Node.Profile
			out = *n
			return nil
		}
		return ErrNodeNotFound
	})
	if err != nil {
		return NodeView{}, err
	}
	return s.nodeView(d, out), nil
}

// TestServer measures one server that is not saved yet ("Test Connection"):
// a real request through a temporary engine instance.
func (s *Service) TestServer(ctx context.Context, in NodeInput) (int64, error) {
	res, err := in.build()
	if err != nil {
		return 0, err
	}
	e, inst, err := s.resolveFor(res.Profile, s.store.Get())
	if err != nil {
		return 0, err
	}
	ms, err := s.probe(ctx, e, inst, res.Profile)
	if err != nil {
		return 0, fmt.Errorf("the server did not answer through %s: %w", e.DisplayName(), err)
	}
	return ms, nil
}

// ---- engines ----

func (s *Service) engineList() []engine.Engine {
	out := make([]engine.Engine, len(s.engines))
	for i, sl := range s.engines {
		out[i] = sl.Engine
	}
	return out
}

func (s *Service) slot(name string) (EngineSlot, bool) {
	for _, sl := range s.engines {
		if sl.Engine.Name() == name {
			return sl, true
		}
	}
	return EngineSlot{}, false
}

func (s *Service) installed(name string) bool {
	sl, ok := s.slot(name)
	return ok && len(sl.Manager.Installed()) > 0
}

// resolveFor picks the engine for a profile and the installed version to run.
func (s *Service) resolveFor(p profile.Profile, d models.AppData) (engine.Engine, engine.Install, error) {
	e, err := engine.Select(p, d.Settings.EnginePreference, s.engineList(), s.installed)
	var ni *engine.NotInstalledError
	if errors.As(err, &ni) {
		return nil, engine.Install{}, fmt.Errorf("%w: %w", core.ErrNotInstalled, ni)
	}
	if err != nil {
		return nil, engine.Install{}, &models.ValidationError{Msg: err.Error()}
	}
	sl, _ := s.slot(e.Name())
	bin, dir, ver, err := sl.Manager.Resolve(d.Engines[e.Name()])
	if err != nil {
		return nil, engine.Install{}, err
	}
	return e, engine.Install{Version: ver, Bin: bin, AssetDir: dir}, nil
}

// syncTags tells tag-aware engines (sing-box) which build tags their active
// binary has, so Supports answers for the binary that will actually run.
func (s *Service) syncTags() {
	d := s.store.Get()
	for _, sl := range s.engines {
		ta, ok := sl.Engine.(engine.TagAware)
		if !ok {
			continue
		}
		bin, _, _, err := sl.Manager.Resolve(d.Engines[sl.Engine.Name()])
		if err != nil {
			ta.SetTags(nil)
			continue
		}
		s.verMu.Lock()
		tags, ok := s.tagCache[bin]
		if !ok {
			tags = core.TagsOf(bin)
			s.tagCache[bin] = tags
		}
		s.verMu.Unlock()
		ta.SetTags(tags)
	}
}

// prepare downloads the data files an engine needs for the current settings
// (sing-box rule sets) before its config is written.
func (s *Service) prepare(ctx context.Context, e engine.Engine, d models.AppData) error {
	ru, ok := e.(engine.RuleSetUser)
	if !ok {
		return nil
	}
	names := ru.RuleSets(d.Settings)
	if len(names) == 0 {
		return nil
	}
	sl, _ := s.slot(e.Name())
	if err := sl.Manager.EnsureRuleSets(ctx, names); err != nil {
		return fmt.Errorf("routing rules for %s: %w", e.DisplayName(), err)
	}
	return nil
}

// autoDownloadOK reports whether a missing engine may be fetched without asking.
func (s *Service) autoDownloadOK(d models.AppData) bool {
	return s.autoDL && d.Settings.AutoDownloadEngines
}

// fetchEnginesFor downloads, in the background, engines that newly added
// servers need ("Download an engine when a new server needs it").
func (s *Service) fetchEnginesFor(nodes []models.Node) {
	d := s.store.Get()
	if !s.autoDownloadOK(d) {
		return
	}
	need := map[string]bool{}
	for _, n := range nodes {
		p, err := link.NodeProfile(n.RawLink, n.Profile)
		if err != nil {
			continue
		}
		if e, err := engine.Candidate(p, d.Settings.EnginePreference, s.engineList()); err == nil && !s.installed(e.Name()) {
			need[e.Name()] = true
		}
	}
	for name := range need {
		if _, err := s.StartEngineDownload(name, ""); err != nil {
			s.log.Warn("automatic engine download failed", "engine", name, "err", err)
		}
	}
}

// ParseLink returns the profile and name of a share link or a WireGuard
// .conf file (to fill a form).
func (s *Service) ParseLink(raw string) (profile.Profile, string, error) {
	parse := link.Parse
	if link.LooksLikeWireGuardConf(raw) {
		parse = func(t string) (link.Result, error) { return link.ParseWireGuardConf(t, "") }
	}
	res, err := parse(strings.TrimSpace(raw))
	if err != nil {
		return profile.Profile{}, "", &models.ValidationError{Msg: err.Error()}
	}
	return res.Profile, res.Node.Name, nil
}

// NodeProfile returns the stored profile of a node (to edit it).
func (s *Service) NodeProfile(id string) (profile.Profile, string, error) {
	n, ok := s.store.Get().FindNode(id)
	if !ok {
		return profile.Profile{}, "", ErrNodeNotFound
	}
	p, err := link.NodeProfile(n.RawLink, n.Profile)
	return p, n.Name, err
}
