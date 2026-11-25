package models

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"
	"time"
)

const (
	maxFilterLists      = 100
	maxFilterUpdateHrs  = 720
	maxAllowedSiteBytes = 253
)

// FilterList is one ad-block list the user picked from the catalog or added by URL.
type FilterList struct {
	ID          string `json:"id"`
	CatalogKey  string `json:"catalogKey,omitempty"` // AdGuard filterKey; empty for a custom URL
	Name        string `json:"name"`
	URL         string `json:"url,omitempty"` // custom lists only; https only
	Enabled     bool   `json:"enabled"`
	UpdateHours int    `json:"updateHours,omitempty"` // 0 = use the catalog's expires, else 24
}

// FilterStatus is the download state of one list. It lives in AppData, never in
// Settings, so a settings save from the app cannot overwrite it.
type FilterStatus struct {
	UpdatedAt    time.Time `json:"updatedAt"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"lastModified,omitempty"`
	Domains      int       `json:"domains"` // after parsing, before de-duplication
	Skipped      int       `json:"skipped"` // lines that were not domain rules
	LastError    string    `json:"lastError,omitempty"`
	URL          string    `json:"url,omitempty"` // the URL of the last successful download
}

// EnabledFilterLists returns the lists the user has switched on.
func (s Settings) EnabledFilterLists() []FilterList {
	var out []FilterList
	for _, l := range s.FilterLists {
		if l.Enabled {
			out = append(out, l)
		}
	}
	return out
}

// FindFilterList returns the chosen list with the given ID.
func (d AppData) FindFilterList(id string) (FilterList, bool) {
	for _, l := range d.Settings.FilterLists {
		if l.ID == id {
			return l, true
		}
	}
	return FilterList{}, false
}

// FiltersActive reports whether any filter list applies: they only count while
// Block ads and trackers is on.
func (s Settings) FiltersActive() bool {
	return s.BlockAds && len(s.EnabledFilterLists()) > 0
}

func newFilterID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// normalizeFilters trims names, fills missing list IDs and cleans AllowedSites.
func (s *Settings) normalizeFilters() {
	if s.FilterLists == nil {
		s.FilterLists = []FilterList{}
	}
	for i := range s.FilterLists {
		l := &s.FilterLists[i]
		l.Name = strings.TrimSpace(l.Name)
		l.CatalogKey = strings.TrimSpace(l.CatalogKey)
		l.URL = strings.TrimSpace(l.URL)
		if l.ID == "" {
			l.ID = newFilterID()
		}
	}
	var lines []string
	for _, line := range strings.Split(s.AllowedSites, "\n") {
		line = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(line)), ".")
		if line != "" {
			lines = append(lines, line)
		}
	}
	s.AllowedSites = strings.Join(lines, "\n")
}

// validateFilters reports every problem of the filter-list selection.
func (s Settings) validateFilters(add func(string, ...any)) {
	if len(s.FilterLists) > maxFilterLists {
		add("at most %d filter lists", maxFilterLists)
	}
	ids := map[string]bool{}
	for _, l := range s.FilterLists {
		if l.ID == "" || ids[l.ID] {
			add("filter list %q needs a unique ID", l.Name)
		}
		ids[l.ID] = true
		if l.CatalogKey == "" {
			if l.URL == "" {
				add("filter list %q needs a catalog entry or a URL", l.Name)
			} else if u, err := url.Parse(l.URL); err != nil || u.Scheme != "https" || u.Host == "" {
				add("filter list %q: the URL must be https://", l.Name)
			}
		}
		if l.UpdateHours < 0 || l.UpdateHours > maxFilterUpdateHrs {
			add("filter list %q: update interval must be 0-%d hours", l.Name, maxFilterUpdateHrs)
		}
	}
	for _, line := range strings.Split(s.AllowedSites, "\n") {
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " \t\r") || len(line) > maxAllowedSiteBytes {
			add("allowed site %q must be a domain without spaces", line)
		}
	}
}
