package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFilterSettingsLoadOldData(t *testing.T) {
	old := `{"version":3,"nodes":[],"settings":{"routingMode":"bypass-private","blockAds":true}}`
	var d AppData
	if err := json.Unmarshal([]byte(old), &d); err != nil {
		t.Fatal(err)
	}
	if len(d.Settings.FilterLists) != 0 || d.Settings.AllowedSites != "" {
		t.Fatal("new fields should be empty")
	}
	d.Settings = DefaultSettings()
	if d.FilterStatus == nil {
		d.FilterStatus = map[string]FilterStatus{}
	}
	d.Settings.Normalize()
	if d.FilterStatus == nil || d.Settings.FilterLists == nil {
		t.Fatal("want non-nil collections")
	}
	if err := d.Settings.Validate(); err != nil {
		t.Fatal(err)
	}
	if DefaultAppData().FilterStatus == nil {
		t.Fatal("DefaultAppData must fill FilterStatus")
	}
}

func TestValidateFilterLists(t *testing.T) {
	many := make([]FilterList, 101)
	for i := range many {
		many[i] = FilterList{ID: string(rune('a'+i%26)) + strings.Repeat("x", i), CatalogKey: "k"}
	}
	cases := []struct {
		name, want string
		set        func(s *Settings)
	}{
		{"http url", "https", func(s *Settings) {
			s.FilterLists = []FilterList{{ID: "a", Name: "n", URL: "http://x"}}
		}},
		{"no url or key", "catalog entry or a URL", func(s *Settings) {
			s.FilterLists = []FilterList{{ID: "a", Name: "n"}}
		}},
		{"duplicate id", "unique ID", func(s *Settings) {
			s.FilterLists = []FilterList{{ID: "a", CatalogKey: "k"}, {ID: "a", CatalogKey: "j"}}
		}},
		{"too many", "at most 100", func(s *Settings) { s.FilterLists = many }},
		{"update hours", "update interval", func(s *Settings) {
			s.FilterLists = []FilterList{{ID: "a", CatalogKey: "k", UpdateHours: 721}}
		}},
		{"allowed site space", "allowed site", func(s *Settings) { s.AllowedSites = "exa mple.com" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := DefaultSettings()
			c.set(&s)
			s.Normalize()
			err := s.Validate()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}

	s := DefaultSettings()
	s.AllowedSites = "Example.COM.\n\n  other.org "
	s.FilterLists = []FilterList{{CatalogKey: "k", Name: " N "}}
	s.Normalize()
	if s.AllowedSites != "example.com\nother.org" {
		t.Fatalf("got %q", s.AllowedSites)
	}
	if s.FilterLists[0].ID == "" || s.FilterLists[0].Name != "N" {
		t.Fatalf("got %+v", s.FilterLists[0])
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFiltersActive(t *testing.T) {
	s := DefaultSettings()
	s.FilterLists = []FilterList{{ID: "a", CatalogKey: "k", Enabled: true}, {ID: "b", CatalogKey: "k"}}
	if !s.FiltersActive() || len(s.EnabledFilterLists()) != 1 {
		t.Fatal("want active with one enabled list")
	}
	s.BlockAds = false
	if s.FiltersActive() {
		t.Fatal("block ads off must disable filters")
	}
}

func TestCloneCopiesFilterLists(t *testing.T) {
	d := DefaultAppData()
	d.Settings.FilterLists = []FilterList{{ID: "a", CatalogKey: "k"}}
	d.FilterStatus["a"] = FilterStatus{Domains: 1}
	c := d.Clone()
	c.Settings.FilterLists[0].Name = "changed"
	c.FilterStatus["a"] = FilterStatus{Domains: 2}
	c.FilterStatus["b"] = FilterStatus{}
	if d.Settings.FilterLists[0].Name != "" || d.FilterStatus["a"].Domains != 1 || len(d.FilterStatus) != 1 {
		t.Fatal("clone aliases the original")
	}
}
