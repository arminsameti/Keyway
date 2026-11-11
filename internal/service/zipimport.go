package service

import (
	"context"
	"strconv"
	"unicode"
	"unicode/utf8"

	"keyway/internal/link"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// PreviewZip is the dry-run of uploading an OpenVPN zip bundle: one item per
// .ovpn file found, with sibling ca/cert/key files resolved. Nothing is saved.
// Import-time credentials fill profiles that still need them.
func (s *Service) PreviewZip(data []byte, creds Credentials) Preview {
	d := s.store.Get()
	out := Preview{Items: []PreviewItem{}}
	items, err := link.ParseOVPNZip(data)
	if err != nil {
		out.Items = append(out.Items, PreviewItem{Line: 1, Status: link.KindSkipped, Name: "Zip file", Reason: capitalizeZip(err.Error())})
		out.Skipped = 1
		return out
	}
	for _, it := range items {
		pi := PreviewItem{Line: it.Line, Status: it.Kind, Scheme: it.Scheme, Reason: it.Reason}
		switch it.Kind {
		case link.KindReady:
			p := fillCredentials(it.Result.Profile, creds)
			pi.CountryCode, pi.Name = profile.SplitCountry(it.Result.Node.Name)
			pi.Protocol, pi.Transport = profile.ProtocolName(p.Protocol), p.DisplayTransport()
			_, pi.Duplicate = d.FindNode(it.Result.Node.ID)
			pi.NeedsCredential = p.NeedsCredentials()
			if e, err := runsOn(p, nil, d.Settings.EnginePreference, s.engineList(), s.installed); err == nil {
				pi.Engine, pi.EngineName, pi.EngineInstalled = e.Name(), e.DisplayName(), s.installed(e.Name())
			} else {
				pi.Status, pi.Reason = link.KindSkipped, err.Error()
			}
		default:
			switch {
			case it.Label != "":
				pi.Name = it.Label
			case it.Name != "":
				pi.Name = it.Name
			default:
				pi.Name = "File " + strconv.Itoa(it.Line)
			}
			if pi.Reason == "" {
				pi.Reason = "Could not be imported"
			}
		}
		switch pi.Status {
		case link.KindReady:
			out.Ready++
		default:
			pi.Status = link.KindSkipped
			out.Skipped++
		}
		out.Items = append(out.Items, pi)
	}
	return out
}

// ImportZip adds the servers from an OpenVPN zip bundle. Import-time
// credentials fill servers that were imported without any.
func (s *Service) ImportZip(_ context.Context, data []byte, creds Credentials) (ImportResult, error) {
	if err := creds.Validate(); err != nil {
		return ImportResult{}, err
	}
	items, err := link.ParseOVPNZip(data)
	if err != nil {
		return ImportResult{Errors: []string{capitalizeZip(err.Error())}, Total: len(s.store.Get().Nodes)}, nil
	}
	var nodes []models.Node
	var errs []string
	for _, it := range items {
		switch it.Kind {
		case link.KindReady:
			nodes = append(nodes, it.Result.Node)
		default:
			errs = append(errs, skipMessage(it))
		}
	}
	if nodes, err = applyImportCredentials(nodes, creds); err != nil {
		return ImportResult{}, err
	}
	var res ImportResult
	if len(nodes) > 0 {
		if _, err := s.store.Update(func(d *models.AppData) error {
			res.Added += mergeNodes(d, nodes, "")
			return nil
		}); err != nil {
			return res, err
		}
		s.fetchEnginesFor(nodes)
	}
	res.Errors = errs
	res.Total = len(s.store.Get().Nodes)
	if res.Errors == nil {
		res.Errors = []string{}
	}
	return res, nil
}

func capitalizeZip(s string) string {
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[size:]
}
