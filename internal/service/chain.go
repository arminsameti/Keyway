package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"keyway/internal/core"
	"keyway/internal/engine"
	"keyway/internal/link"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// connPlan is everything needed to run one server or chain: its hops, the
// processes they are split into and the installed engine version of each.
type connPlan struct {
	hops     []profile.Profile
	names    []string
	steps    []engine.Step
	installs []engine.Install // per step
	runDirs  []string         // per-run state directories (Tor); removed with cleanup
}

// cleanup removes the plan's per-run directories.
func (pl *connPlan) cleanup() {
	for _, d := range pl.runDirs {
		_ = os.RemoveAll(d)
	}
	pl.runDirs = nil
}

// hasBootstrap reports whether a step needs a bootstrap wait (Tor).
func (pl *connPlan) hasBootstrap() bool {
	for _, st := range pl.steps {
		if _, ok := st.Engine.(engine.Bootstrapper); ok {
			return true
		}
	}
	return false
}

func (pl *connPlan) finalEngine() engine.Engine { return pl.steps[len(pl.steps)-1].Engine }
func (pl *connPlan) finalInstall() engine.Install {
	return pl.installs[len(pl.installs)-1]
}

// resolveHops returns the hops of a node: itself for a server, the listed
// servers (looked up now, so edits and renames apply) for a chain.
func (s *Service) resolveHops(d models.AppData, n models.Node) ([]profile.Profile, []string, error) {
	if n.Protocol != profile.Chain {
		p, err := link.NodeProfile(n.RawLink, n.Profile)
		if err == nil {
			p, err = n.Overrides.Apply(p)
		}
		if err != nil {
			return nil, nil, err
		}
		return []profile.Profile{p}, []string{n.Name}, nil
	}
	return s.hopsOf(d, n.Chain)
}

func (s *Service) hopsOf(d models.AppData, ids []string) ([]profile.Profile, []string, error) {
	hops := make([]profile.Profile, 0, len(ids))
	names := make([]string, 0, len(ids))
	for i, id := range ids {
		h, ok := d.FindNode(id)
		if g, isGroup := d.FindGroup(id); !ok && isGroup {
			return nil, nil, &models.ValidationError{Msg: fmt.Sprintf("hop %d “%s” is a group; a chain can only contain single servers", i+1, g.Name)}
		}
		if !ok {
			return nil, nil, &models.ValidationError{Msg: fmt.Sprintf("hop %d is no longer in your server list", i+1)}
		}
		if h.Protocol == profile.Chain {
			return nil, nil, &models.ValidationError{Msg: fmt.Sprintf("hop %d “%s” is itself a chain; a chain can only contain single servers", i+1, h.Name)}
		}
		p, err := link.NodeProfile(h.RawLink, h.Profile)
		if err == nil {
			p, err = h.Overrides.Apply(p)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("hop %d “%s”: %w", i+1, h.Name, err)
		}
		hops = append(hops, p)
		names = append(names, h.Name)
	}
	return hops, names, nil
}

// planFor splits the hops into processes and resolves the installed engines.
// When an engine is missing the error wraps core.ErrNotInstalled and
// *engine.NotInstalledError.
//
// final names the engine that must serve the user's traffic ("" = any).
func (s *Service) planFor(hops []profile.Profile, names []string, d models.AppData, final string) (*connPlan, error) {
	if err := checkCredentials(hops, names); err != nil {
		return nil, err
	}
	if len(hops) > 1 {
		if err := profile.CheckChain(hops, names); err != nil {
			return nil, &models.ValidationError{Msg: err.Error()}
		}
	}
	steps, err := engine.PlanSegments(hops, d.Settings.EnginePreference, s.engineList(), s.installed, final)
	var ni *engine.NotInstalledError
	if errors.As(err, &ni) {
		return nil, fmt.Errorf("%w: %w", core.ErrNotInstalled, ni)
	}
	if err != nil {
		return nil, &models.ValidationError{Msg: err.Error()}
	}
	pl := &connPlan{hops: hops, names: names, steps: steps}
	for _, st := range steps {
		sl, _ := s.slot(st.Engine.Name())
		bin, dir, ver, err := sl.Manager.Resolve(d.Engines[st.Engine.Name()])
		if err != nil {
			return nil, err
		}
		pl.installs = append(pl.installs, engine.Install{Version: ver, Bin: bin, AssetDir: dir})
	}
	return pl, nil
}

// checkCredentials refuses to run a server whose profile still needs a
// username and password. Such servers are stored and editable, but cannot
// connect, test or measure until the credentials are added.
func checkCredentials(hops []profile.Profile, names []string) error {
	for i, h := range hops {
		if h.NeedsCredentials() {
			name := "this server"
			if i < len(names) && strings.TrimSpace(names[i]) != "" {
				name = "“" + names[i] + "”"
			}
			return &models.ValidationError{Msg: fmt.Sprintf("%s needs a username and password; add them in the server's settings", name)}
		}
	}
	return nil
}

// newBridge reserves a loopback port with fresh credentials for joining two
// processes of a chain.
func newBridge() (profile.Bridge, error) {
	port, err := engine.FreePort()
	if err != nil {
		return profile.Bridge{}, err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return profile.Bridge{}, err
	}
	h := hex.EncodeToString(b)
	return profile.Bridge{Port: port, User: h[:16], Pass: h[16:]}, nil
}

// segments builds the profile.Segment of every step, joined by bridges: step k
// listens on bridge k and step k+1 dials through it.
//
// base is where per-run directories of engines that keep state (Tor) are made;
// "" is a preview, which only needs placeholder values.
func (pl *connPlan) segments(base string) ([]profile.Segment, error) {
	bridges := make([]profile.Bridge, len(pl.steps)-1)
	for i := range bridges {
		b, err := newBridge()
		if err != nil {
			return nil, err
		}
		bridges[i] = b
	}
	segs := make([]profile.Segment, len(pl.steps))
	for k, st := range pl.steps {
		seg := profile.Segment{Hops: st.Hops(pl.hops)}
		if k > 0 {
			seg.Upstream = &bridges[k-1]
		}
		if k < len(pl.steps)-1 {
			seg.Listen = &bridges[k]
		}
		if _, ok := st.Engine.(engine.Bootstrapper); ok {
			rt := &profile.Runtime{Dir: "(per-run directory)", ControlPort: 1}
			if k < len(pl.installs) {
				rt.AssetDir = pl.installs[k].AssetDir
			}
			if base != "" {
				dir, err := os.MkdirTemp(base, "tor-run-*")
				if err != nil {
					pl.cleanup()
					return nil, err
				}
				pl.runDirs = append(pl.runDirs, dir)
				port, err := engine.FreePort()
				if err != nil {
					pl.cleanup()
					return nil, err
				}
				rt.Dir, rt.ControlPort = dir, port
			}
			seg.Runtime = rt
		}
		segs[k] = seg
	}
	return segs, nil
}

// probe measures the plan end to end: throw-away processes for every segment
// and a real HTTP request through the whole chain.
func (s *Service) probe(ctx context.Context, pl *connPlan) (int64, error) {
	segs, err := pl.segments(s.dir)
	if err != nil {
		return 0, err
	}
	defer pl.cleanup()
	finalPort, err := engine.FreePort()
	if err != nil {
		return 0, err
	}
	procs := make([]engine.TempProc, len(segs))
	for k, seg := range segs {
		cfg, err := pl.steps[k].Engine.ProbeConfig(seg, finalPort)
		if err != nil {
			return 0, err
		}
		wait := finalPort
		if seg.Listen != nil {
			wait = seg.Listen.Port
		}
		procs[k] = engine.TempProc{Engine: pl.steps[k].Engine, Install: pl.installs[k], Cfg: cfg, WaitPort: wait}
	}
	stop, err := engine.StartTempChain(ctx, procs)
	if err != nil {
		return 0, err
	}
	defer stop()
	timeoutSingle := proxyTimeout
	if pl.hasBootstrap() {
		timeoutSingle = torProbeTimeout
		for k, st := range pl.steps {
			if b, ok := st.Engine.(engine.Bootstrapper); ok {
				if err := b.WaitReady(ctx, segs[k], nil); err != nil {
					return 0, err
				}
			}
		}
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(finalPort))
	if len(pl.hops) == 1 {
		return engine.URLTest(ctx, addr, "", timeoutSingle)
	}
	// A chain sets up a tunnel or handshake per hop, and a UDP hop such as
	// WireGuard retries its first handshake only after 5 s when it started
	// before the hop in front of it was ready. That is startup cost, not the
	// chain's latency: warm it up, then time a second request.
	timeout := chainProbeTimeout(len(pl.hops))
	if pl.hasBootstrap() && timeout < torProbeTimeout {
		timeout = torProbeTimeout
	}
	if _, err := engine.URLTest(ctx, addr, "", timeout); err != nil {
		return 0, err
	}
	return engine.URLTest(ctx, addr, "", timeout)
}

// torProbeTimeout is the budget of a request through Tor once it has bootstrapped.
const torProbeTimeout = 30 * time.Second

// chainProbeTimeout allows each extra hop time to come up.
func chainProbeTimeout(hops int) time.Duration {
	t := proxyTimeout + time.Duration(hops-1)*6*time.Second
	if t > 45*time.Second {
		t = 45 * time.Second
	}
	return t
}

// ---- chains as nodes ----

// chainName is the default name of a chain: its entry and exit servers.
func chainName(names []string) string {
	if len(names) == 0 {
		return "Chain"
	}
	return fmt.Sprintf("%s → %s", names[0], names[len(names)-1])
}

// checkChain validates a chain of hop node IDs and returns its hops.
func (s *Service) checkChain(d models.AppData, ids []string) ([]profile.Profile, []string, error) {
	if len(ids) < 2 {
		return nil, nil, &models.ValidationError{Msg: "a chain needs at least two servers"}
	}
	if len(ids) > profile.MaxChainHops {
		return nil, nil, &models.ValidationError{Msg: fmt.Sprintf("a chain can have at most %d servers", profile.MaxChainHops)}
	}
	hops, names, err := s.hopsOf(d, ids)
	if err != nil {
		return nil, nil, err
	}
	if !d.Settings.TorEnabled {
		for _, h := range hops {
			if h.Protocol == profile.Tor {
				return nil, nil, errTorOff
			}
		}
	}
	if err := profile.CheckChain(hops, names); err != nil {
		return nil, nil, &models.ValidationError{Msg: err.Error()}
	}
	if _, err := engine.PlanSegments(hops, d.Settings.EnginePreference, s.engineList(), func(string) bool { return true }, ""); err != nil {
		return nil, nil, &models.ValidationError{Msg: err.Error()}
	}
	return hops, names, nil
}

func (s *Service) createChain(in NodeInput) (NodeView, error) {
	var node models.Node
	d, err := s.store.Update(func(d *models.AppData) error {
		_, names, err := s.checkChain(*d, in.Chain)
		if err != nil {
			return err
		}
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = chainName(names)
		}
		node = models.Node{ID: newID(), Name: name, Protocol: profile.Chain, Chain: append([]string(nil), in.Chain...),
			CreatedAt: time.Now().UTC(), LatencyMs: models.LatencyUnknown}
		d.Nodes = append(d.Nodes, node)
		return nil
	})
	if err != nil {
		return NodeView{}, err
	}
	s.fetchEnginesFor([]models.Node{node})
	return s.nodeView(d, node), nil
}

func (s *Service) updateChain(id string, in NodeInput) (NodeView, error) {
	var out models.Node
	d, err := s.store.Update(func(d *models.AppData) error {
		for i := range d.Nodes {
			n := &d.Nodes[i]
			if n.ID != id {
				continue
			}
			if n.Protocol != profile.Chain {
				return &models.ValidationError{Msg: "this server is not a chain"}
			}
			_, names, err := s.checkChain(*d, in.Chain)
			if err != nil {
				return err
			}
			for _, h := range in.Chain {
				if h == id {
					return &models.ValidationError{Msg: "a chain cannot contain itself"}
				}
			}
			name := strings.TrimSpace(in.Name)
			if name == "" {
				name = chainName(names)
			}
			n.Name, n.Chain, n.LatencyMs = name, append([]string(nil), in.Chain...), models.LatencyUnknown
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

// EditView is what the editor needs to change a node: a server's profile, or a
// chain's hop IDs.
type EditView struct {
	Name    string           `json:"name"`
	Profile *profile.Profile `json:"profile,omitempty"`
	Chain   []string         `json:"chain,omitempty"`

	Overrides *profile.Overrides `json:"overrides,omitempty"`
}

// NodeForEdit returns a node in editable form.
func (s *Service) NodeForEdit(id string) (EditView, error) {
	n, ok := s.store.Get().FindNode(id)
	if !ok {
		return EditView{}, ErrNodeNotFound
	}
	if n.Protocol == profile.Chain {
		return EditView{Name: n.Name, Chain: append([]string{}, n.Chain...)}, nil
	}
	p, err := link.NodeProfile(n.RawLink, n.Profile)
	if err != nil {
		return EditView{}, err
	}
	return EditView{Name: n.Name, Profile: &p, Overrides: n.Overrides}, nil
}

// hopsFromInput resolves a not-yet-saved server or chain ("Test Connection").
func (s *Service) hopsFromInput(d models.AppData, in NodeInput) ([]profile.Profile, []string, error) {
	if len(in.Chain) > 0 {
		return s.checkChain(d, in.Chain)
	}
	res, err := in.build()
	if err != nil {
		return nil, nil, err
	}
	p, err := in.Overrides.Apply(res.Profile)
	if err != nil {
		return nil, nil, &models.ValidationError{Msg: err.Error()}
	}
	return []profile.Profile{p}, []string{res.Node.Name}, nil
}

// ChainPlan is what saving or connecting a chain would do, for the editor.
type ChainPlan struct {
	Engine     string `json:"engine"`     // the process that serves the user's traffic
	EngineName string `json:"engineName"` // every engine, in order: "sing-box + Xray core"
	Processes  int    `json:"processes"`
	Installed  bool   `json:"installed"` // every engine of the plan is downloaded
}

// PlanChain validates a chain exactly as saving would and reports its plan.
func (s *Service) PlanChain(ids []string) (ChainPlan, error) {
	d := s.store.Get()
	hops, _, err := s.checkChain(d, ids)
	if err != nil {
		return ChainPlan{}, err
	}
	steps, err := planShown(hops, d.Settings.EnginePreference, s.engineList(), s.installed, "")
	if err != nil {
		return ChainPlan{}, &models.ValidationError{Msg: err.Error()}
	}
	pl := ChainPlan{Engine: steps[len(steps)-1].Engine.Name(), EngineName: engine.EngineNames(steps), Processes: len(steps), Installed: true}
	for _, st := range steps {
		if !s.installed(st.Engine.Name()) {
			pl.Installed = false
		}
	}
	return pl, nil
}

// ConfigPreview is the configuration this app would run for a node, one entry
// per engine process (entry first), for inspection. It is built exactly like a
// real connection's, so what you read is what runs.
type ConfigPreview struct {
	Engines []string `json:"engines"` // display name per process
	Configs []string `json:"configs"` // JSON text per process
	DNS     []string `json:"dns"`     // how names resolve per process; "" where the process serves no lookups
}

// previewDNS says how the process of a segment resolves names. Only the
// segment that serves the user does, and only the engines that run a DNS
// block of their own (Tor hands the lookups to its exit).
func previewDNS(st models.Settings, engineName string, seg profile.Segment) string {
	switch engineName {
	case engine.NameXray, engine.NameSingBox, engine.NameV2Ray:
	default:
		return ""
	}
	if seg.Listen != nil {
		return ""
	}
	return st.EffectiveDNS(engineName)
}

// PreviewConfig renders a node's configuration without starting anything.
func (s *Service) PreviewConfig(id string) (ConfigPreview, error) {
	d := s.store.Get()
	node, ok := d.FindNode(id)
	if !ok {
		return ConfigPreview{}, ErrNodeNotFound
	}
	hops, names, err := s.resolveHops(d, node)
	if err != nil {
		return ConfigPreview{}, err
	}
	if len(hops) > 1 {
		if err := profile.CheckChain(hops, names); err != nil {
			return ConfigPreview{}, &models.ValidationError{Msg: err.Error()}
		}
	}
	steps, err := planShown(hops, d.Settings.EnginePreference, s.engineList(), s.installed, s.finalFor(d))
	if err != nil {
		return ConfigPreview{}, &models.ValidationError{Msg: err.Error()}
	}
	pl := &connPlan{hops: hops, names: names, steps: steps}
	segs, err := pl.segments("")
	if err != nil {
		return ConfigPreview{}, err
	}
	var out ConfigPreview
	for k, seg := range segs {
		cfg, err := pl.steps[k].Engine.Config(seg, d.Settings)
		if err != nil {
			return ConfigPreview{}, err
		}
		out.Engines = append(out.Engines, pl.steps[k].Engine.DisplayName())
		out.Configs = append(out.Configs, string(cfg))
		out.DNS = append(out.DNS, previewDNS(d.Settings, pl.steps[k].Engine.Name(), seg))
	}
	return out, nil
}

// finalFor names the engine that must serve the user's traffic: sing-box when
// the settings need something only it can do (a TUN interface, per-app rules).
func (s *Service) finalFor(d models.AppData) string {
	if d.Settings.NeedsSingBox() {
		return engine.NameSingBox
	}
	return ""
}
