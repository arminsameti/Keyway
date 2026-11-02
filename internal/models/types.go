// Package models holds the persisted data types and their defaults.
package models

import (
	"encoding/json"
	"time"

	"keyway/internal/profile"
)

// Latency sentinel values stored in Node.LatencyMs.
const (
	LatencyUnknown int64 = -1 // never measured
	LatencyFailed  int64 = -2 // measured, unreachable
	LatencyNA      int64 = -3 // not measurable in the chosen mode (e.g. UDP node via TCP dial)
)

// SchemaVersion is bumped whenever the persisted layout needs a migration.
const SchemaVersion = 3

// Node is one imported proxy. When RawLink is set it is authoritative: the
// engine configuration is regenerated from it at connect time, so fixes apply
// to already-imported nodes. Nodes without a share link (manual SSH, Clash or
// sing-box imports) carry their engine-neutral Profile instead.
type Node struct {
	ID        string             `json:"id"`
	Name      string             `json:"name"`
	Protocol  string             `json:"protocol"` // see profile.VLESS and friends
	Server    string             `json:"server"`
	Port      int                `json:"port"`
	RawLink   string             `json:"rawLink,omitempty"`
	Profile   json.RawMessage    `json:"profile,omitempty"`   // profile.Profile when RawLink is empty
	Chain     []string           `json:"chain,omitempty"`     // protocol "chain": IDs of the hop nodes, entry first
	Overrides *profile.Overrides `json:"overrides,omitempty"` // per-server tweaks over the global settings
	Source    string             `json:"source,omitempty"`    // subscription ID; empty for manually added nodes
	CreatedAt time.Time          `json:"createdAt"`
	LatencyMs int64              `json:"latencyMs"`
}

// Subscription is a persisted subscription URL whose nodes can be refreshed.
type Subscription struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	UpdatedAt time.Time `json:"updatedAt"`
	NodeCount int       `json:"nodeCount"`
	LastError string    `json:"lastError,omitempty"`
	Format    string    `json:"format,omitempty"` // links | base64 | clash | sing-box

	// Details the provider reports in response headers; all optional.
	Title       string    `json:"title,omitempty"`       // Profile-Title
	UpdateHours int       `json:"updateHours,omitempty"` // Profile-Update-Interval, in hours
	Usage       *SubUsage `json:"usage,omitempty"`       // Subscription-Userinfo
	Warnings    []string  `json:"warnings,omitempty"`    // what the last import could not use (e.g. unsupported Clash groups)
}

// SubUsage is the traffic quota a provider reports in Subscription-Userinfo.
// Total 0 means the provider gave no limit; a nil Expire means no expiry.
type SubUsage struct {
	Upload   int64      `json:"upload"`
	Download int64      `json:"download"`
	Total    int64      `json:"total"`
	Expire   *time.Time `json:"expire,omitempty"`
}

// Inbound is one local listener (SOCKS5 or HTTP).
type Inbound struct {
	Tag      string `json:"tag"`
	Protocol string `json:"protocol"` // socks | http
	Port     int    `json:"port"`
	Listen   string `json:"listen"` // 127.0.0.1 or 0.0.0.0
	UDP      bool   `json:"udp"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Enabled  bool   `json:"enabled"`
}

// Settings are the user-editable preferences.
type Settings struct {
	Inbounds        []Inbound `json:"inbounds"`
	RoutingMode     string    `json:"routingMode"` // global | bypass-private | custom
	BlockAds        bool      `json:"blockAds"`
	DirectSites     string    `json:"directSites"` // comma/newline separated geosite/geoip/domains
	ProxySites      string    `json:"proxySites"`
	BlockedSites    string    `json:"blockedSites"`
	DNS             []string  `json:"dns"`
	DNSMode         string    `json:"dnsMode"`   // default | system | secure | custom
	DNSDirect       string    `json:"dnsDirect"` // optional resolver for bypassed domains, by IP
	FakeIP          bool      `json:"fakeIp"`    // TUN: answer lookups with fake addresses
	LogLevel        string    `json:"logLevel"`  // debug info warning error none
	Mux             bool      `json:"mux"`
	MuxConcurrency  int       `json:"muxConcurrency"`
	AllowLAN        bool      `json:"allowLan"`
	Sniffing        bool      `json:"sniffing"`
	APIPort         int       `json:"apiPort"` // web UI port
	AutoPick        bool      `json:"autoPick"`
	AutoPickMin     int       `json:"autoPickMin"`     // minutes between auto-pick runs
	AutoConnect     bool      `json:"autoConnect"`     // connect the active node on launch
	AutoSystemProxy bool      `json:"autoSystemProxy"` // set macOS system proxy on connect, clear on disconnect
	SubUpdateHours  int       `json:"subUpdateHours"`  // 0 disables subscription auto-update

	EnginePreference    string `json:"enginePreference"`    // xray | sing-box | v2ray: used when several can run a server
	AutoDownloadEngines bool   `json:"autoDownloadEngines"` // fetch an engine when a new server needs it
	EngineUpdateCheck   string `json:"engineUpdateCheck"`   // never | daily | weekly
	LatencyMethod       string `json:"latencyMethod"`       // tcp | real
	TorEnabled          bool   `json:"torEnabled"`          // Tor servers, chains and the Tor engine are available
	AppUpdateCheck      string `json:"appUpdateCheck"`      // daily | never: ask GitHub whether a newer Keyway exists

	TUN TUNSettings `json:"tun"`

	RuleSets      []RuleSet `json:"ruleSets"`      // used by routing mode "rules"
	ActiveRuleSet string    `json:"activeRuleSet"` // ID of the rule set in use
}

// EngineCheck records the last update check for one engine.
type EngineCheck struct {
	CheckedAt time.Time `json:"checkedAt"`
	Latest    string    `json:"latest,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// AppData is the whole persisted document.
type AppData struct {
	Version      int    `json:"version"`
	ActiveNodeID string `json:"activeNodeId"`
	// ActiveGroupID is set when the active "server" is a group: ActiveNodeID then
	// always mirrors the group's current member (see ReconcileGroups).
	ActiveGroupID string `json:"activeGroupId,omitempty"`
	// ActiveCore is the schema-2 Xray version; migrated into Engines["xray"].
	ActiveCore    string                 `json:"activeCore,omitempty"`
	Engines       map[string]string      `json:"engines"`      // engine name -> active version tag
	EngineChecks  map[string]EngineCheck `json:"engineChecks"` // engine name -> last update check
	AppCheck      EngineCheck            `json:"appCheck"`     // last check for a newer Keyway
	Nodes         []Node                 `json:"nodes"`
	Subscriptions []Subscription         `json:"subscriptions"`
	Groups        []Group                `json:"groups"`
	Settings      Settings               `json:"settings"`
}

// DefaultSettings returns the out-of-the-box preferences.
func DefaultSettings() Settings {
	return Settings{
		Inbounds: []Inbound{
			{Tag: "socks-in", Protocol: "socks", Port: 10808, Listen: "127.0.0.1", UDP: true, Enabled: true},
			{Tag: "http-in", Protocol: "http", Port: 10809, Listen: "127.0.0.1", Enabled: true},
			{Tag: "mixed-extra", Protocol: "socks", Port: 10810, Listen: "127.0.0.1", UDP: true, Enabled: true},
		},
		RoutingMode:    "bypass-private",
		BlockAds:       true,
		DirectSites:    "geosite:private, geosite:cn",
		BlockedSites:   "geosite:category-ads-all",
		DNS:            []string{"1.1.1.1", "8.8.8.8", "localhost"},
		DNSMode:        DNSModeDefault,
		LogLevel:       "warning",
		MuxConcurrency: 8,
		Sniffing:       true,
		APIPort:        12345,
		AutoPickMin:    10,
		SubUpdateHours: 24,

		EnginePreference:    "xray",
		AutoDownloadEngines: true,
		EngineUpdateCheck:   "weekly",
		LatencyMethod:       "real",
		AppUpdateCheck:      "daily",
		TUN:                 TUNSettings{Privilege: "prompt", Stack: "mixed", MTU: 9000},
	}
}

// DefaultAppData returns an empty document with default settings.
func DefaultAppData() AppData {
	return AppData{
		Version:       SchemaVersion,
		Engines:       map[string]string{},
		EngineChecks:  map[string]EngineCheck{},
		Nodes:         []Node{},
		Subscriptions: []Subscription{},
		Groups:        []Group{},
		Settings:      DefaultSettings(),
	}
}

// Clone returns a deep copy, so callers can never alias store-internal state.
func (d AppData) Clone() AppData {
	c := d
	c.Nodes = make([]Node, len(d.Nodes))
	for i, n := range d.Nodes {
		n.Profile = append(json.RawMessage(nil), n.Profile...)
		n.Chain = append([]string(nil), n.Chain...)
		if n.Overrides != nil {
			o := *n.Overrides
			if o.Mux != nil {
				m := *o.Mux
				o.Mux = &m
			}
			if o.Fragment != nil {
				f := *o.Fragment
				o.Fragment = &f
			}
			n.Overrides = &o
		}
		c.Nodes[i] = n
	}
	c.Engines = make(map[string]string, len(d.Engines))
	for k, v := range d.Engines {
		c.Engines[k] = v
	}
	c.EngineChecks = make(map[string]EngineCheck, len(d.EngineChecks))
	for k, v := range d.EngineChecks {
		c.EngineChecks[k] = v
	}
	c.Subscriptions = make([]Subscription, len(d.Subscriptions))
	for i, sub := range d.Subscriptions {
		if sub.Usage != nil {
			u := *sub.Usage
			if u.Expire != nil {
				e := *u.Expire
				u.Expire = &e
			}
			sub.Usage = &u
		}
		sub.Warnings = append([]string(nil), sub.Warnings...)
		c.Subscriptions[i] = sub
	}
	c.Groups = make([]Group, len(d.Groups))
	for i, g := range d.Groups {
		g.Members = append([]string(nil), g.Members...)
		c.Groups[i] = g
	}
	c.Settings = d.Settings.Clone()
	return c
}

// Clone returns a deep copy of the settings.
func (s Settings) Clone() Settings {
	c := s
	c.Inbounds = append([]Inbound{}, s.Inbounds...)
	c.DNS = append([]string{}, s.DNS...)
	c.RuleSets = make([]RuleSet, len(s.RuleSets))
	for i, set := range s.RuleSets {
		c.RuleSets[i] = RuleSet{ID: set.ID, Name: set.Name, Rules: make([]RouteRule, len(set.Rules))}
		for j, r := range set.Rules {
			r.Entries = append([]string{}, r.Entries...)
			c.RuleSets[i].Rules[j] = r
		}
	}
	return c
}

// FindNode returns the node with the given ID.
func (d AppData) FindNode(id string) (Node, bool) {
	for _, n := range d.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}
