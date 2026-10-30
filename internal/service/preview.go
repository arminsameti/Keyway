package service

import (
	"net/url"
	"strconv"

	"xray-friendly/internal/engine"
	"xray-friendly/internal/link"
	"xray-friendly/internal/profile"
)

// PreviewItem is one parsed entry shown in the Add Servers sheet.
type PreviewItem struct {
	Line            int    `json:"line"`
	Status          string `json:"status"` // ready | subscription | skipped
	Scheme          string `json:"scheme,omitempty"`
	Name            string `json:"name"`
	CountryCode     string `json:"countryCode,omitempty"`
	Protocol        string `json:"protocol,omitempty"` // display name
	Transport       string `json:"transport,omitempty"`
	Engine          string `json:"engine,omitempty"` // engine name that would run it
	EngineName      string `json:"engineName,omitempty"`
	EngineInstalled bool   `json:"engineInstalled"`
	Duplicate       bool   `json:"duplicate"` // already in the server list
	Reason          string `json:"reason,omitempty"`
}

// Preview is the dry-run result of an import.
type Preview struct {
	Items         []PreviewItem `json:"items"`
	Ready         int           `json:"ready"`
	Subscriptions int           `json:"subscriptions"`
	Skipped       int           `json:"skipped"`
}

// PreviewImport parses pasted text without saving or fetching anything.
func (s *Service) PreviewImport(text string) Preview {
	d := s.store.Get()
	out := Preview{Items: []PreviewItem{}}
	for _, it := range link.Classify(text) {
		pi := PreviewItem{Line: it.Line, Status: it.Kind, Scheme: it.Scheme, Reason: it.Reason}
		switch it.Kind {
		case link.KindReady:
			p := it.Result.Profile
			pi.CountryCode, pi.Name = profile.SplitCountry(it.Result.Node.Name)
			pi.Protocol, pi.Transport = profile.ProtocolName(p.Protocol), p.DisplayTransport()
			_, pi.Duplicate = d.FindNode(it.Result.Node.ID)
			if e, err := engine.Candidate(p, d.Settings.EnginePreference, s.engineList()); err == nil {
				pi.Engine, pi.EngineName, pi.EngineInstalled = e.Name(), e.DisplayName(), s.installed(e.Name())
			} else {
				pi.Status, pi.Reason = link.KindSkipped, err.Error()
			}
		case link.KindSubscription:
			pi.Name = hostOf(it.URL)
			if u, err := url.Parse(it.URL); err == nil {
				pi.Name = u.Host
			}
		default:
			switch {
			case it.Label != "":
				pi.Name = it.Label
			case it.Scheme != "":
				pi.Name = "Line " + strconv.Itoa(it.Line) + " · " + it.Scheme + "://"
			default:
				pi.Name = "Line " + strconv.Itoa(it.Line)
			}
		}
		switch pi.Status {
		case link.KindReady:
			out.Ready++
		case link.KindSubscription:
			out.Subscriptions++
		default:
			out.Skipped++
		}
		out.Items = append(out.Items, pi)
	}
	return out
}
