package filters

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CatalogURL is the AdGuard HostlistsRegistry catalog.
const CatalogURL = "https://adguardteam.github.io/HostlistsRegistry/assets/filters.json"

const problematicTag = 111

// CatalogList is one entry of the AdGuard catalog.
type CatalogList struct {
	Key                                      string
	ID, Group                                int
	Name, Description, Homepage, DownloadURL string
	Tags                                     []int
	Deprecated, Problematic                  bool
	Languages                                []string
	ExpiresSec                               int
	TimeUpdated                              string
}

// CatalogGroup is a catalog section such as General or Security.
type CatalogGroup struct {
	ID    int
	Name  string
	Order int
}

// Catalog is the parsed catalog, with groups and lists in display order.
type Catalog struct {
	Groups    []CatalogGroup
	Lists     []CatalogList
	FetchedAt time.Time
}

type rawCatalog struct {
	Filters []struct {
		FilterKey   string   `json:"filterKey"`
		FilterID    int      `json:"filterId"`
		GroupID     int      `json:"groupId"`
		Name        string   `json:"name"`
		Deprecated  bool     `json:"deprecated"`
		Description string   `json:"description"`
		Tags        []int    `json:"tags"`
		Languages   []string `json:"languages"`
		Homepage    string   `json:"homepage"`
		Expires     int      `json:"expires"`
		DisplayNum  int      `json:"displayNumber"`
		DownloadURL string   `json:"downloadUrl"`
		TimeUpdated string   `json:"timeUpdated"`
	} `json:"filters"`
	Tags []struct {
		TagID   int    `json:"tagId"`
		Keyword string `json:"keyword"`
	} `json:"tags"`
	Groups []struct {
		GroupID    int    `json:"groupId"`
		GroupName  string `json:"groupName"`
		DisplayNum int    `json:"displayNumber"`
	} `json:"groups"`
}

// ParseCatalog decodes the catalog JSON. It rejects a catalog with no lists
// and any list whose download URL is not https.
func ParseCatalog(b []byte) (Catalog, error) {
	var raw rawCatalog
	if err := json.Unmarshal(b, &raw); err != nil {
		return Catalog{}, fmt.Errorf("catalog is not valid JSON: %w", err)
	}
	if len(raw.Filters) == 0 {
		return Catalog{}, errors.New("catalog has no lists")
	}
	langOf := map[int]string{}
	for _, t := range raw.Tags {
		if t.TagID >= 100 && t.TagID <= 114 && strings.HasPrefix(t.Keyword, "lang:") {
			langOf[t.TagID] = strings.TrimPrefix(t.Keyword, "lang:")
		}
	}
	groupOrder := map[int]int{}
	var c Catalog
	for _, g := range raw.Groups {
		c.Groups = append(c.Groups, CatalogGroup{ID: g.GroupID, Name: g.GroupName, Order: g.DisplayNum})
		groupOrder[g.GroupID] = g.DisplayNum
	}
	sort.SliceStable(c.Groups, func(i, j int) bool { return c.Groups[i].Order < c.Groups[j].Order })

	display := map[string]int{}
	for _, f := range raw.Filters {
		u, err := url.Parse(f.DownloadURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return Catalog{}, fmt.Errorf("list %q has a download URL that is not https", f.FilterKey)
		}
		l := CatalogList{
			Key: f.FilterKey, ID: f.FilterID, Group: f.GroupID, Name: f.Name,
			Description: f.Description, Homepage: f.Homepage, DownloadURL: f.DownloadURL,
			Tags: f.Tags, Deprecated: f.Deprecated, ExpiresSec: f.Expires, TimeUpdated: f.TimeUpdated,
		}
		l.Languages = append(l.Languages, f.Languages...)
		for _, t := range f.Tags {
			if t == problematicTag {
				l.Problematic = true
			}
			if len(f.Languages) == 0 {
				if code, ok := langOf[t]; ok {
					l.Languages = append(l.Languages, code)
				}
			}
		}
		display[l.Key] = f.DisplayNum
		c.Lists = append(c.Lists, l)
	}
	sort.SliceStable(c.Lists, func(i, j int) bool {
		a, b := c.Lists[i], c.Lists[j]
		if ga, gb := groupOrder[a.Group], groupOrder[b.Group]; ga != gb {
			return ga < gb
		}
		return display[a.Key] < display[b.Key]
	})
	return c, nil
}

// Find returns the list with the given catalog key.
func (c Catalog) Find(key string) (CatalogList, bool) {
	for _, l := range c.Lists {
		if l.Key == key {
			return l, true
		}
	}
	return CatalogList{}, false
}
