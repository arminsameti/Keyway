package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/link"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// NodeView is a node plus everything the UI derives from its profile.
type NodeView struct {
	models.Node
	DisplayName     string    `json:"displayName"`           // name without a leading flag emoji
	CountryCode     string    `json:"countryCode,omitempty"` // ISO 3166-1 alpha-2, from the name
	ProtocolName    string    `json:"protocolName"`
	Transport       string    `json:"transport"`
	Security        string    `json:"security"`
	SNI             string    `json:"sni"`
	UDP             bool      `json:"udp"`              // TCP latency tests cannot measure it
	RelaysUDP       bool      `json:"relaysUdp"`        // can carry UDP for a following hop of a chain
	Engine          string    `json:"engine,omitempty"` // engine that would run it
	EngineName      string    `json:"engineName,omitempty"`
	EngineInstalled bool      `json:"engineInstalled"`
	EngineReason    string    `json:"engineReason,omitempty"` // why no engine can run it
	Warning         string    `json:"warning,omitempty"`      // non-blocking: e.g. still needs a username and password
	HasLink         bool      `json:"hasLink"`
	Error           string    `json:"error,omitempty"` // the stored link/profile no longer parses, or a chain is broken
	Chain           bool      `json:"chain"`           // a chain of other servers
	Hops            []HopView `json:"hops,omitempty"`
}

// HopView is one server of a chain, in the order traffic takes (entry first).
type HopView struct {
	ID           string `json:"id"`
	Name         string `json:"name"` // display name, "" when the server is gone
	CountryCode  string `json:"countryCode,omitempty"`
	ProtocolName string `json:"protocolName"`
	Transport    string `json:"transport"`
	Missing      bool   `json:"missing"`
}

func (s *Service) nodeViews(d models.AppData) []NodeView {
	out := make([]NodeView, 0, len(d.Nodes))
	for _, n := range d.Nodes {
		if !d.Settings.TorEnabled && usesTor(d, n) {
			continue // kept in storage, shown again when Tor is turned back on
		}
		out = append(out, s.nodeView(d, n))
	}
	return out
}

func (s *Service) nodeView(d models.AppData, n models.Node) NodeView {
	v := NodeView{Node: n, HasLink: n.RawLink != "", ProtocolName: profile.ProtocolName(n.Protocol)}
	v.CountryCode, v.DisplayName = profile.SplitCountry(n.Name)
	if n.Protocol == profile.Chain {
		return s.chainView(d, v)
	}
	p, err := link.NodeProfile(n.RawLink, n.Profile)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	v.Transport, v.Security, v.SNI, v.UDP = p.DisplayTransport(), p.DisplaySecurity(), p.DisplaySNI(), p.UDPBased()
	v.RelaysUDP = profile.RelaysUDP(p)
	e, err := runsOn(p, n.Overrides, d.Settings.EnginePreference, s.engineList(), s.installed)
	if err != nil {
		v.EngineReason = err.Error()
		return v
	}
	v.Engine, v.EngineName, v.EngineInstalled = e.Name(), e.DisplayName(), s.installed(e.Name())
	if p.NeedsCredentials() {
		v.Warning = "Needs a username and password"
	}
	return v
}

// Nodes returns every node with its derived fields.
func (s *Service) Nodes() []NodeView { return s.nodeViews(s.store.Get()) }

// NodeInput creates or replaces a node: either a share link or a profile.
type NodeInput struct {
	Name    string           `json:"name"`
	Link    string           `json:"link,omitempty"`
	Profile *profile.Profile `json:"profile,omitempty"`
	Chain   []string         `json:"chain,omitempty"` // hop node IDs, entry first: a chain of other servers

	Overrides *profile.Overrides `json:"overrides,omitempty"` // per-server tweaks; nil clears them
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

var errTorOff = &models.ValidationError{Msg: "Tor is turned off; enable it in Settings"}

// ErrDuplicateNode is returned when the server is already in the list.
var ErrDuplicateNode = &models.ValidationError{Msg: "this server is already in the list"}

// CreateNode adds one manually entered server.
func (s *Service) CreateNode(in NodeInput) (NodeView, error) {
	if len(in.Chain) > 0 {
		return s.createChain(in)
	}
	res, err := in.build()
	if err != nil {
		return NodeView{}, err
	}
	if res.Node.Protocol == profile.Tor && !s.torOn() {
		return NodeView{}, errTorOff
	}
	if err := checkOverrides(res.Node, in.Overrides); err != nil {
		return NodeView{}, err
	}
	res.Node.Overrides = keepOverrides(in.Overrides)
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

// checkOverrides refuses overrides that cannot work for this server.
func checkOverrides(n models.Node, o *profile.Overrides) error {
	if o.IsZero() {
		return nil
	}
	p, err := link.NodeProfile(n.RawLink, n.Profile)
	if err != nil {
		return &models.ValidationError{Msg: err.Error()}
	}
	if _, err := o.Apply(p); err != nil {
		return &models.ValidationError{Msg: err.Error()}
	}
	return nil
}

// keepOverrides stores nothing when the overrides change nothing.
func keepOverrides(o *profile.Overrides) *profile.Overrides {
	if o.IsZero() {
		return nil
	}
	c := *o
	c.Engine = o.PinnedEngine() // stored trimmed
	if o.Mux != nil {
		m := *o.Mux
		c.Mux = &m
	}
	if o.Fragment != nil {
		f := *o.Fragment
		c.Fragment = &f
	}
	return &c
}

// UpdateNode replaces a node's server details, keeping its ID, source and
// position, so the active selection and the subscription grouping survive.
func (s *Service) UpdateNode(id string, in NodeInput) (NodeView, error) {
	if len(in.Chain) > 0 {
		return s.updateChain(id, in)
	}
	res, err := in.build()
	if err != nil {
		return NodeView{}, err
	}
	if res.Node.Protocol == profile.Tor && !s.torOn() {
		return NodeView{}, errTorOff
	}
	if err := checkOverrides(res.Node, in.Overrides); err != nil {
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
			n.Overrides = keepOverrides(in.Overrides)
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

// TestServer measures one server or chain that is not saved yet ("Test
// Connection"): a real request through temporary engine instances.
func (s *Service) TestServer(ctx context.Context, in NodeInput) (int64, error) {
	d := s.store.Get()
	hops, names, err := s.hopsFromInput(d, in)
	if err != nil {
		return 0, err
	}
	pl, err := s.planFor(hops, names, d, "")
	if err != nil {
		return 0, err
	}
	ms, err := s.probe(ctx, pl)
	if err != nil {
		what := "the server"
		if len(hops) > 1 {
			what = "the chain"
		}
		return 0, fmt.Errorf("%s did not answer through %s: %w", what, engine.EngineNames(pl.steps), err)
	}
	return ms, nil
}

// ---- engines ----

// usesTor reports whether a node is a Tor server or a chain with a Tor hop.
func usesTor(d models.AppData, n models.Node) bool {
	if n.Protocol == profile.Tor {
		return true
	}
	for _, id := range n.Chain {
		if h, ok := d.FindNode(id); ok && h.Protocol == profile.Tor {
			return true
		}
	}
	return false
}

// torOn reports whether the opt-in Tor feature is enabled.
//
// It reads a cached flag, not the store: engineList is called from inside store
// updates, which hold the store's lock.
func (s *Service) torOn() bool { return s.torFlag.Load() }

// visibleSlots are the engines that exist for the user: Tor only while enabled.
func (s *Service) visibleSlots() []EngineSlot {
	on := s.torOn()
	out := make([]EngineSlot, 0, len(s.engines))
	for _, sl := range s.engines {
		if sl.Engine.Name() == engine.NameTor && !on {
			continue
		}
		out = append(out, sl)
	}
	return out
}

// setDNS caches what the DNS settings amount to. Settings that do not parse
// (Validate refuses them, so only a hand-edited file) count as the default.
func (s *Service) setDNS(st models.Settings) {
	plan, err := st.DNSPlan()
	if err != nil {
		plan = models.DNSPlan{Mode: models.DNSModeDefault}
	}
	s.dnsPlan.Store(&plan)
}

// engineList is the engines the planner may use: those that cannot honour the
// DNS settings refuse every server, so it moves to one that can.
func (s *Service) engineList() []engine.Engine {
	slots := s.visibleSlots()
	out := make([]engine.Engine, len(slots))
	for i, sl := range slots {
		out[i] = sl.Engine
	}
	if p := s.dnsPlan.Load(); p != nil {
		out = engine.ForDNS(out, *p)
	}
	return out
}

func (s *Service) slot(name string) (EngineSlot, bool) {
	for _, sl := range s.visibleSlots() {
		if sl.Engine.Name() == name {
			return sl, true
		}
	}
	return EngineSlot{}, false
}

// runsOn names the engine that will run a server: the one connecting picks, with
// the node's overrides applied. An engine that still has to be downloaded is
// named too, so the caller can say so.
func runsOn(p profile.Profile, ov *profile.Overrides, pref string, engines []engine.Engine, installed func(string) bool) (engine.Engine, error) {
	p, err := ov.Apply(p)
	if err != nil {
		return nil, err
	}
	e, err := engine.Select(p, pref, engines, installed)
	var missing *engine.NotInstalledError
	if errors.As(err, &missing) {
		return e, nil
	}
	return e, err
}

// planShown is the plan connecting would use. Engines that still have to be
// downloaded stay in it, so the caller can say so.
func planShown(hops []profile.Profile, pref string, engines []engine.Engine, installed func(string) bool, final string) ([]engine.Step, error) {
	steps, err := engine.PlanSegments(hops, pref, engines, installed, final)
	var missing *engine.NotInstalledError
	if errors.As(err, &missing) {
		return steps, nil
	}
	return steps, err
}

func (s *Service) installed(name string) bool {
	sl, ok := s.slot(name)
	return ok && len(sl.Manager.Installed()) > 0
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
	if gd, ok := e.(engine.GeoDataUser); ok {
		// Mihomo would fetch a missing geodata file itself, unverified; its config
		// forbids that, so the verified copy must be there before it starts.
		if files := gd.GeoData(d.Settings); len(files) > 0 {
			sl, _ := s.slot(e.Name())
			if err := sl.Manager.EnsureGeoData(ctx, files); err != nil {
				return fmt.Errorf("routing data for %s: %w", e.DisplayName(), err)
			}
		}
	}
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
		allInstalled := func(string) bool { return true }
		if e, err := runsOn(p, n.Overrides, d.Settings.EnginePreference, s.engineList(), allInstalled); err == nil && !s.installed(e.Name()) {
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
	raw = strings.TrimSpace(raw)
	if link.LooksLikeOVPN(raw) {
		// Unvalidated: the form shows what is missing (e.g. credentials) instead of refusing.
		p, name, err := link.ParseOVPNProfile(raw)
		if err != nil {
			return profile.Profile{}, "", &models.ValidationError{Msg: err.Error()}
		}
		return p, name, nil
	}
	parse := link.Parse
	if link.LooksLikeWireGuardConf(raw) {
		parse = func(t string) (link.Result, error) { return link.ParseWireGuardConf(t, "") }
	}
	res, err := parse(raw)
	if err != nil {
		return profile.Profile{}, "", &models.ValidationError{Msg: err.Error()}
	}
	return res.Profile, res.Node.Name, nil
}

// chainView fills the derived fields of a chain node.
func (s *Service) chainView(d models.AppData, v NodeView) NodeView {
	v.Chain, v.ProtocolName = true, profile.ProtocolName(profile.Chain)
	v.Transport, v.Security, v.SNI = fmt.Sprintf("%d hops", len(v.Node.Chain)), "—", "—"
	v.UDP = true // a TCP dial to the entry says nothing about the whole chain: use the real test
	for _, id := range v.Node.Chain {
		hv := HopView{ID: id, Missing: true}
		if h, ok := d.FindNode(id); ok {
			hv.Missing = false
			hv.CountryCode, hv.Name = profile.SplitCountry(h.Name)
			hv.ProtocolName = profile.ProtocolName(h.Protocol)
			if hp, err := link.NodeProfile(h.RawLink, h.Profile); err == nil {
				hv.Transport = hp.DisplayTransport()
			}
		}
		v.Hops = append(v.Hops, hv)
	}
	hops, names, err := s.resolveHops(d, v.Node)
	if err != nil {
		v.Error = err.Error()
		return v
	}
	if err := checkCredentials(hops, names); err != nil {
		v.Warning = err.Error()
	}
	if err := profile.CheckChain(hops, names); err != nil {
		v.Error = err.Error()
		return v
	}
	steps, err := planShown(hops, d.Settings.EnginePreference, s.engineList(), s.installed, "")
	if err != nil {
		v.EngineReason = err.Error()
		return v
	}
	v.Engine = steps[len(steps)-1].Engine.Name()
	v.EngineName = engine.EngineNames(steps)
	v.EngineInstalled = true
	for _, st := range steps {
		if !s.installed(st.Engine.Name()) {
			v.EngineInstalled = false
		}
	}
	return v
}
