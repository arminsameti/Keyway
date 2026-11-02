package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"keyway/internal/link"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// ErrGroupNotFound is returned for a group ID that does not exist.
var ErrGroupNotFound = errors.New("group not found")

// GroupView is a group plus what the UI shows about its current member.
type GroupView struct {
	models.Group
	MemberCount      int    `json:"memberCount"`
	CurrentName      string `json:"currentName,omitempty"` // display name of the member in use
	CurrentCountry   string `json:"currentCountryCode,omitempty"`
	CurrentLatencyMs int64  `json:"currentLatencyMs"`
	SourceName       string `json:"sourceName,omitempty"` // name of the owning subscription
}

func (s *Service) groupView(d models.AppData, g models.Group) GroupView {
	v := GroupView{Group: g, MemberCount: len(g.Members), CurrentLatencyMs: models.LatencyUnknown}
	if v.Members == nil {
		v.Members = []string{}
	}
	if n, ok := d.FindNode(g.Current); ok {
		v.CurrentCountry, v.CurrentName = profile.SplitCountry(n.Name)
		v.CurrentLatencyMs = n.LatencyMs
	}
	for _, sub := range d.Subscriptions {
		if sub.ID == g.Source {
			v.SourceName = sub.Name
		}
	}
	return v
}

func (s *Service) groupViews(d models.AppData) []GroupView {
	out := make([]GroupView, 0, len(d.Groups))
	for _, g := range d.Groups {
		out = append(out, s.groupView(d, g))
	}
	return out
}

// Groups returns every group with its derived fields.
func (s *Service) Groups() []GroupView { return s.groupViews(s.store.Get()) }

// GroupInput creates or replaces a group. With SubscriptionID set the group
// holds every server of that subscription (and Members is ignored).
type GroupInput struct {
	Name           string   `json:"name"`
	Strategy       string   `json:"strategy"`
	Members        []string `json:"members,omitempty"` // node IDs, in priority order
	SubscriptionID string   `json:"subscriptionId,omitempty"`
}

// CreateGroup adds a group made by hand, or one that follows a subscription.
func (s *Service) CreateGroup(in GroupInput) (GroupView, error) {
	var out models.Group
	d, err := s.store.Update(func(d *models.AppData) error {
		g := models.Group{ID: newID(), Name: strings.TrimSpace(in.Name), Strategy: in.Strategy, Members: append([]string(nil), in.Members...)}
		if in.SubscriptionID != "" {
			var sub *models.Subscription
			for i := range d.Subscriptions {
				if d.Subscriptions[i].ID == in.SubscriptionID {
					sub = &d.Subscriptions[i]
				}
			}
			if sub == nil {
				return &models.ValidationError{Msg: "unknown subscription"}
			}
			for _, o := range d.Groups {
				if o.Follow && o.Source == sub.ID {
					return &models.ValidationError{Msg: fmt.Sprintf("the subscription “%s” already has a group", sub.Name)}
				}
			}
			g.Source, g.Follow, g.Members = sub.ID, true, nil
			for _, n := range d.Nodes {
				if n.Source == sub.ID {
					g.Members = append(g.Members, n.ID)
				}
			}
			if g.Name == "" {
				g.Name = sub.Name
			}
		}
		if err := s.checkGroup(*d, g); err != nil {
			return err
		}
		g.Current = g.Members[0]
		d.Groups = append(d.Groups, g)
		out = g
		return nil
	})
	if err != nil {
		return GroupView{}, err
	}
	g, _ := d.FindGroup(out.ID)
	return s.groupView(d, g), nil
}

// checkGroup validates a group and refuses Tor members while Tor is off.
func (s *Service) checkGroup(d models.AppData, g models.Group) error {
	if err := g.Validate(d.Nodes); err != nil {
		return err
	}
	if !d.Settings.TorEnabled {
		for _, id := range g.Members {
			if n, ok := d.FindNode(id); ok && usesTor(d, n) {
				return errTorOff
			}
		}
	}
	return nil
}

func ownedBy(d models.AppData, g models.Group) string {
	for _, sub := range d.Subscriptions {
		if sub.ID == g.Source {
			return sub.Name
		}
	}
	return "a subscription"
}

// UpdateGroup changes a group's name, strategy and members. A group that
// follows a subscription keeps that subscription's servers; a group imported
// from a subscription's Clash file is changed there, not here.
func (s *Service) UpdateGroup(id string, in GroupInput) (GroupView, error) {
	d, err := s.store.Update(func(d *models.AppData) error {
		for i := range d.Groups {
			g := &d.Groups[i]
			if g.ID != id {
				continue
			}
			if g.Imported() {
				return &models.ValidationError{Msg: fmt.Sprintf("this group comes from the subscription “%s” and is refreshed with it; you can only choose its server", ownedBy(*d, *g))}
			}
			next := *g
			next.Name, next.Strategy = strings.TrimSpace(in.Name), in.Strategy
			if g.Follow {
				if len(in.Members) > 0 {
					return &models.ValidationError{Msg: fmt.Sprintf("the servers of this group are the servers of the subscription “%s”", ownedBy(*d, *g))}
				}
			} else {
				next.Members = append([]string(nil), in.Members...)
			}
			if err := s.checkGroup(*d, next); err != nil {
				return err
			}
			*g = next
			return nil
		}
		return ErrGroupNotFound
	})
	if err != nil {
		return GroupView{}, err
	}
	g, _ := d.FindGroup(id)
	return s.groupView(d, g), nil
}

// DeleteGroup removes a group; deleting the active group keeps its current
// server selected.
func (s *Service) DeleteGroup(id string) error {
	_, err := s.store.Update(func(d *models.AppData) error {
		for i, g := range d.Groups {
			if g.ID != id {
				continue
			}
			if g.Imported() {
				return &models.ValidationError{Msg: fmt.Sprintf("this group is part of the subscription “%s”; remove the subscription to remove it", ownedBy(*d, g))}
			}
			d.Groups = append(d.Groups[:i], d.Groups[i+1:]...)
			return nil
		}
		return ErrGroupNotFound
	})
	return err
}

// groupCandidates are the members that automatic selection may use. Tor
// servers are never chosen for speed, and are skipped while Tor is off.
func groupCandidates(d models.AppData, g models.Group) []models.Node {
	var out []models.Node
	for _, id := range g.Members {
		n, ok := d.FindNode(id)
		if !ok {
			continue
		}
		if usesTor(d, n) && (g.Strategy == models.StrategyURLTest || !d.Settings.TorEnabled) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// groupChoice returns the member an automatic group should use, given the
// latencies measured for its candidates (members in group order).
//
//   - fallback: the first member that is not known to be down. A member that
//     cannot be measured (n/a) or has not been measured counts as usable.
//   - url-test: the fastest reachable member, but the current one is only
//     abandoned when it is down or the rival is clearly faster (shouldSwitch),
//     so two similar servers never make the group flap.
//   - select: never moves; the user's pick stays.
//
// When nothing works the current member is kept.
func groupChoice(g models.Group, members []models.Node, lat map[string]int64) string {
	switch g.Strategy {
	case models.StrategyFallback:
		for _, n := range members {
			if v, ok := lat[n.ID]; !ok || v != models.LatencyFailed {
				return n.ID
			}
		}
	case models.StrategyURLTest:
		best, ms := chooseBest(members, lat)
		if best == "" || best == g.Current {
			break
		}
		cur, known := lat[g.Current]
		if g.Current == "" || shouldSwitch(cur, known, ms) {
			return best
		}
	}
	return g.Current
}

// storedLatencies are the latencies already known from earlier tests.
func storedLatencies(nodes []models.Node) map[string]int64 {
	lat := make(map[string]int64, len(nodes))
	for _, n := range nodes {
		if n.LatencyMs != models.LatencyUnknown {
			lat[n.ID] = n.LatencyMs
		}
	}
	return lat
}

// SetActiveGroup makes a group the active server. An automatic group starts
// from the latencies already known; it is re-tested by EvaluateGroup.
func (s *Service) SetActiveGroup(id string) error {
	_, err := s.store.Update(func(d *models.AppData) error {
		for i := range d.Groups {
			g := &d.Groups[i]
			if g.ID != id {
				continue
			}
			if len(g.Members) == 0 {
				return &models.ValidationError{Msg: "this group has no servers yet"}
			}
			if g.Strategy != models.StrategySelect {
				cand := groupCandidates(*d, *g)
				g.Current = groupChoice(*g, cand, storedLatencies(cand))
			}
			d.ActiveGroupID = id
			return nil
		}
		return ErrGroupNotFound
	})
	return err
}

// SelectGroupMember sets the server a select group uses.
func (s *Service) SelectGroupMember(id, nodeID string) error {
	_, err := s.store.Update(func(d *models.AppData) error {
		for i := range d.Groups {
			g := &d.Groups[i]
			if g.ID != id {
				continue
			}
			if g.Strategy != models.StrategySelect {
				return &models.ValidationError{Msg: fmt.Sprintf("the server of a %s group is chosen automatically", g.Strategy)}
			}
			for _, m := range g.Members {
				if m == nodeID {
					g.Current = nodeID
					return nil
				}
			}
			return &models.ValidationError{Msg: "that server is not in this group"}
		}
		return ErrGroupNotFound
	})
	return err
}

// GroupResult is the outcome of EvaluateGroup.
type GroupResult struct {
	ID          string           `json:"id"` // the member now in use
	Name        string           `json:"name"`
	LatencyMs   int64            `json:"latencyMs"`
	Latency     map[string]int64 `json:"latency"`
	Mode        string           `json:"mode"`
	Changed     bool             `json:"changed"`
	Reconnected bool             `json:"reconnected"`
}

// EvaluateGroup tests a group's members and lets its strategy choose. A select
// group is only measured. If the group is active and its server changes, the
// running connection is moved over when reconnect is set. On ErrAllFailed the
// result still carries the measured latencies.
func (s *Service) EvaluateGroup(ctx context.Context, id, mode string, reconnect bool) (GroupResult, error) {
	d := s.store.Get()
	g, ok := d.FindGroup(id)
	if !ok {
		return GroupResult{}, ErrGroupNotFound
	}
	cand := groupCandidates(d, g)
	if len(cand) == 0 {
		return GroupResult{}, ErrNoNodes
	}
	lat, used, err := s.Measure(ctx, cand, mode)
	if err != nil {
		return GroupResult{}, err
	}
	s.applyLatencies(lat)
	res := GroupResult{ID: g.Current, Latency: lat, Mode: used}

	down := 0
	for _, n := range cand {
		if lat[n.ID] == models.LatencyFailed {
			down++
		}
	}
	choice := groupChoice(g, cand, lat)
	if choice != g.Current {
		d, err = s.store.Update(func(d *models.AppData) error {
			for i := range d.Groups {
				if d.Groups[i].ID == id {
					d.Groups[i].Current = choice
					return nil
				}
			}
			return ErrGroupNotFound
		})
		if err != nil {
			return res, err
		}
		res.ID, res.Changed = choice, true
	}
	if n, ok := d.FindNode(res.ID); ok {
		_, res.Name = profile.SplitCountry(n.Name)
		res.LatencyMs = n.LatencyMs
		if v, ok := lat[n.ID]; ok {
			res.LatencyMs = v
		}
	}
	if down == len(cand) {
		return res, ErrAllFailed
	}
	if res.Changed && d.ActiveGroupID == id {
		s.log.Info("group switched server", "group", g.Name, "node", res.Name)
		if reconnect && s.run.IsRunning() {
			if _, err := s.Reconnect(ctx); err != nil {
				return res, fmt.Errorf("group chose %q but reconnect failed: %w", res.Name, err)
			}
			res.Reconnected = true
		}
	}
	return res, nil
}

// ---- Clash groups ----

// newImportedGroup builds a group from a spec found in a config file.
func newImportedGroup(spec link.GroupSpec, source string) models.Group {
	name := []rune(spec.Name)
	if len(name) > 64 {
		name = name[:64]
	}
	return models.Group{ID: newID(), Name: string(name), Strategy: spec.Strategy, Members: spec.Members, Source: source}
}

// syncImportedGroups makes the groups imported from a subscription match the
// file's current proxy-groups: a group that is still there keeps its ID and the
// user's choice (matched by name), new ones are added, vanished ones are removed.
func syncImportedGroups(d *models.AppData, source string, specs []link.GroupSpec) {
	old := map[string]models.Group{}
	kept := make([]models.Group, 0, len(d.Groups))
	for _, g := range d.Groups {
		if g.Source == source && g.Imported() {
			if _, dup := old[g.Name]; !dup {
				old[g.Name] = g
			}
			continue
		}
		kept = append(kept, g)
	}
	for _, spec := range specs {
		g := newImportedGroup(spec, source)
		if o, ok := old[g.Name]; ok {
			g.ID, g.Current = o.ID, o.Current
			delete(old, g.Name)
		}
		kept = append(kept, g)
	}
	d.Groups = kept
}

// addPastedGroups adds the groups of a pasted Clash config as groups of the
// user's own, skipping names that already exist.
func addPastedGroups(d *models.AppData, specs []link.GroupSpec) {
	for _, spec := range specs {
		g := newImportedGroup(spec, "")
		exists := false
		for _, o := range d.Groups {
			if o.Source == "" && o.Name == g.Name {
				exists = true
			}
		}
		if !exists {
			g.Current = g.Members[0]
			d.Groups = append(d.Groups, g)
		}
	}
}
