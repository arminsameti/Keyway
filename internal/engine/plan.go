package engine

import (
	"fmt"
	"sort"
	"strings"

	"keyway/internal/profile"
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
// A hop may pin an engine (Overrides.Engine, the manual per-server choice).
// A pin is strict: the hop must run on that engine. A segment covering hops
// [i,j) may use engine e only when every pinned hop inside names e. Pinning
// an opt-in engine allows it for the pinned hops even when the global
// preference names another engine.
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
	byName := make(map[string]Engine, len(engines))
	for _, e := range engines {
		byName[e.Name()] = e
	}
	pins := make([]string, len(hops))
	for i, h := range hops {
		pins[i] = h.PinnedEngine()
		if pins[i] != "" {
			if _, ok := byName[pins[i]]; !ok {
				return nil, fmt.Errorf("%w: hop %d pins %q, which is not available (is it turned off?)", ErrNoEngine, i+1, pins[i])
			}
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
		effPref := pref
		if pins[i] != "" {
			effPref = pins[i]
		}
		order := preferredFirst(engines, effPref)
		var cands []cand
		var reasons []string
		for rank, e := range order {
			to := 0
			for j := len(hops); j > i; j-- {
				if !segmentPinsAllow(pins[i:j], e.Name()) {
					continue
				}
				if o, ok := e.(OptIn); ok && o.OptIn() {
					if e.Name() != pref && !pinsContain(pins[i:j], e.Name()) {
						continue
					}
				}
				if err := e.SupportsSegment(hops[i:j], i > 0); err == nil {
					to = j
					break
				}
			}
			if to == 0 {
				reasons = append(reasons, segmentReason(e, hops[i:i+1], i > 0, pins[i]))
				continue
			}
			cands = append(cands, cand{e, to, installed(e.Name()), rank})
		}
		if len(cands) == 0 {
			if len(hops) == 1 {
				if pins[0] != "" {
					return nil, fmt.Errorf("%w: pinned engine %s cannot run this server: %s", ErrNoEngine, pins[0], strings.Join(reasons, "; "))
				}
				return nil, fmt.Errorf("%w: %s", ErrNoEngine, strings.Join(reasons, "; "))
			}
			if pins[i] != "" {
				return nil, fmt.Errorf("%w: hop %d (%s) pins %s: %s", ErrNoEngine, i+1, profile.ProtocolName(hops[i].Protocol), pins[i], strings.Join(reasons, "; "))
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
	if rr, ok := steps[len(steps)-1].Engine.(RelayRequired); ok && rr.RelayRequired() && final == "" {
		final = NameSingBox // the one engine that can run a relay with no hops of its own
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

// segmentPinsAllow reports whether engine name may cover a segment: every
// pinned hop inside must name it.
func segmentPinsAllow(pins []string, name string) bool {
	for _, pin := range pins {
		if pin != "" && pin != name {
			return false
		}
	}
	return true
}

// pinsContain reports whether any hop of the segment pins name.
func pinsContain(pins []string, name string) bool {
	for _, pin := range pins {
		if pin == name {
			return true
		}
	}
	return false
}

// segmentReason is why e cannot run a single hop, for error messages. A pin
// to another engine is reported as such, so a strict choice that excludes e
// does not look like a capability gap.
func segmentReason(e Engine, hops []profile.Profile, hasUpstream bool, pin string) string {
	if pin != "" && pin != e.Name() {
		return e.DisplayName() + ": not used (this server pins " + pin + ")"
	}
	return reasonFor(e, hops, hasUpstream)
}

// reasonFor is why e cannot run hops as a segment, for error messages.
func reasonFor(e Engine, hops []profile.Profile, hasUpstream bool) string {
	if err := e.SupportsSegment(hops, hasUpstream); err != nil {
		return e.DisplayName() + ": " + err.Error()
	}
	return e.DisplayName() + ": supported"
}
