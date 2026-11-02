package engine

import (
	"keyway/internal/models"
	"keyway/internal/profile"
	"keyway/internal/v2ray"
	"keyway/internal/xray"
)

// DNSAware is implemented by engines that cannot honour every DNS setting.
// The planner has to know before it picks one: a setting the engine would drop
// silently is a leak, so such a server moves to another engine.
type DNSAware interface {
	SupportsDNS(models.DNSPlan) error
}

func (Xray) SupportsDNS(p models.DNSPlan) error  { return xray.SupportsDNS(p) }
func (V2Ray) SupportsDNS(p models.DNSPlan) error { return v2ray.SupportsDNS(p) }

// ForDNS returns the engines the planner may use under the DNS settings: those
// that cannot honour them refuse every server, with the reason. Only engines
// that implement DNSAware are wrapped, and the wrapper hides their optional
// interfaces (RuleSetUser, TagAware...), which Xray and V2Ray do not have.
func ForDNS(engines []Engine, p models.DNSPlan) []Engine {
	out := make([]Engine, len(engines))
	for i, e := range engines {
		out[i] = e
		if a, ok := e.(DNSAware); ok {
			if err := a.SupportsDNS(p); err != nil {
				out[i] = dnsRefusing{Engine: e, err: err}
			}
		}
	}
	return out
}

type dnsRefusing struct {
	Engine
	err error
}

func (d dnsRefusing) Supports(profile.Profile) error                { return d.err }
func (d dnsRefusing) SupportsSegment([]profile.Profile, bool) error { return d.err }
