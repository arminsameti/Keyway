package service

import (
	"strings"

	"keyway/internal/link"
	"keyway/internal/models"
	"keyway/internal/profile"
)

// Credentials is a username and password supplied at import time for servers
// (OpenVPN auth-user-pass) that were imported without any.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Validate checks an import-time username/password pair: both empty means
// none were given, exactly one set is an error.
func (c Credentials) Validate() error {
	if c.Username == "" && c.Password == "" {
		return nil
	}
	if c.Username == "" || c.Password == "" {
		return &models.ValidationError{Msg: "username and password must be given together"}
	}
	return nil
}

// ValidateCredentials checks an import-time username/password pair: both
// empty means none were given, exactly one set is an error.
func ValidateCredentials(username, password string) (Credentials, error) {
	c := Credentials{Username: strings.TrimSpace(username), Password: strings.TrimSpace(password)}
	return c, c.Validate()
}

// fillCredentials returns the profile with import-time credentials applied
// when it still needs them. Profiles that already have credentials (or never
// needed any) are returned unchanged, as are incomplete pairs.
func fillCredentials(p profile.Profile, creds Credentials) profile.Profile {
	if creds.Username == "" || creds.Password == "" || !p.NeedsCredentials() {
		return p
	}
	p.Username, p.Password = creds.Username, creds.Password
	if o := p.OpenVPN; o != nil {
		o.NeedsCredential = false
	}
	return p
}

// applyImportCredentials fills empty OpenVPN credentials of freshly parsed
// nodes. The node ID derives from the profile, so patched nodes are rebuilt
// (keeping name, source and timestamps) to keep the ID in sync.
func applyImportCredentials(nodes []models.Node, creds Credentials) ([]models.Node, error) {
	if creds.Username == "" {
		return nodes, nil
	}
	out := make([]models.Node, 0, len(nodes))
	for _, n := range nodes {
		if n.Protocol != profile.OpenVPN {
			out = append(out, n)
			continue
		}
		p, err := link.NodeProfile(n.RawLink, n.Profile)
		if err != nil || !p.NeedsCredentials() {
			out = append(out, n)
			continue
		}
		res, err := link.ProfileNode(fillCredentials(p, creds), n.Name)
		if err != nil {
			return nil, err
		}
		res.Node.Source = n.Source
		res.Node.CreatedAt = n.CreatedAt
		res.Node.LatencyMs = n.LatencyMs
		out = append(out, res.Node)
	}
	return out, nil
}
