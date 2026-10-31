package engine

import (
	"fmt"
	"sort"
	"strings"

	"xray-friendly/internal/profile"
)

// Step is one process of a chain: the hops [From, To) run on Engine.
type Step struct {
	Engine   Engine
	From, To int
}

// Hops returns the step's slice of the chain.
func (s Step) Hops(all []profile.Profile) []profile.Profile { return all[s.From:s.To] }

// PlanSegments splits a chain (entry first) into the fewest processes. Each
// hop is dialed through the one before it, so within one process the engine
// chains them itself (sing-box: detour, Xray: dialerProxy); between processes
// a loopback bridge joins them. The engine that can run the longest run of
// hops from the current position wins; ties go to an installed engine, then to
// the preferred one.
//
// When an engine in the plan is not installed, the plan is returned together
// with a *NotInstalledError so the caller can fetch it and plan again.
//
// final, when not empty, names the engine that must serve the user's traffic
// (TUN and per-app rules need sing-box). If the plan ends on another engine, a
// relay step with no hops of its own is appended: that process only forwards
// to the previous one through the bridge.
func PlanSegments(hops []profile.Profile, pref string, engines []Engine, installed func(string) bool, final string) ([]Step, error) {
	if len(hops) == 0 {
		return nil, fmt.Errorf("a chain needs at least one server")
	}
	order := append([]Engine{}, engines...)
	for i, e := range order {
		if e.Name() == pref {
			order[0], order[i] = order[i], order[0]
			break
		}
	}
	var steps []Step
	for i := 0; i < len(hops); {
		type cand struct {
			e    Engine
			to   int
			inst bool
			rank int
		}
		var cands []cand
		var reasons []string
		for rank, e := range order {
			to := 0
			for j := len(hops); j > i; j-- {
				if err := e.SupportsSegment(hops[i:j], i > 0); err == nil {
					to = j
					break
				}
			}
			if to == 0 {
				reasons = append(reasons, reasonFor(e, hops[i:i+1], i > 0))
				continue
			}
			cands = append(cands, cand{e, to, installed(e.Name()), rank})
		}
		if len(cands) == 0 {
			if len(hops) == 1 {
				return nil, fmt.Errorf("%w: %s", ErrNoEngine, strings.Join(reasons, "; "))
			}
			return nil, fmt.Errorf("%w: hop %d (%s): %s", ErrNoEngine, i+1, profile.ProtocolName(hops[i].Protocol), strings.Join(reasons, "; "))
		}
		sort.SliceStable(cands, func(a, b int) bool {
			if cands[a].to != cands[b].to {
				return cands[a].to > cands[b].to
			}
			if cands[a].inst != cands[b].inst {
				return cands[a].inst
			}
			return cands[a].rank < cands[b].rank
		})
		steps = append(steps, Step{Engine: cands[0].e, From: i, To: cands[0].to})
		i = cands[0].to
	}
	if final != "" && steps[len(steps)-1].Engine.Name() != final {
		var relay Engine
		for _, e := range engines {
			if e.Name() == final {
				relay = e
			}
		}
		if relay == nil {
			return nil, fmt.Errorf("%w: %s is needed for this setup", ErrNoEngine, final)
		}
		steps = append(steps, Step{Engine: relay, From: len(hops), To: len(hops)})
	}
	for _, st := range steps {
		if !installed(st.Engine.Name()) {
			return steps, &NotInstalledError{Engine: st.Engine}
		}
	}
	return steps, nil
}

// EngineNames lists the engines of a plan in order ("sing-box", "sing-box + Xray core").
func EngineNames(steps []Step) string {
	var names []string
	for _, s := range steps {
		n := s.Engine.DisplayName()
		if len(names) == 0 || names[len(names)-1] != n {
			names = append(names, n)
		}
	}
	return strings.Join(names, " + ")
}

// reasonFor is why e cannot run hops as a segment, for error messages.
func reasonFor(e Engine, hops []profile.Profile, hasUpstream bool) string {
	if err := e.SupportsSegment(hops, hasUpstream); err != nil {
		return e.DisplayName() + ": " + err.Error()
	}
	return e.DisplayName() + ": supported"
}
