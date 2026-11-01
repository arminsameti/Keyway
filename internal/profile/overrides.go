package profile

import (
	"fmt"
	"regexp"
	"strings"
)

// Overrides are per-server tweaks that take precedence over the global
// settings. A nil field means "use the global setting".
type Overrides struct {
	Mux            *bool     `json:"mux,omitempty"`            // multiplexing on or off for this server
	MuxConcurrency int       `json:"muxConcurrency,omitempty"` // 0 = global
	Fragment       *Fragment `json:"fragment,omitempty"`       // split the TLS handshake to get past SNI filtering
	SNI            string    `json:"sni,omitempty"`            // replaces the server name sent in TLS
	Fingerprint    string    `json:"fingerprint,omitempty"`    // replaces the uTLS browser fingerprint
}

// Fragment describes how the first packets of a TLS connection are split.
// Xray uses all three fields; sing-box only needs to know it is on.
type Fragment struct {
	Packets  string `json:"packets,omitempty"`  // tlshello (default) or a range of packet numbers such as 1-3
	Length   string `json:"length,omitempty"`   // bytes per piece, e.g. 100-200
	Interval string `json:"interval,omitempty"` // milliseconds between pieces, e.g. 10-20
}

var (
	rangeRe      = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)
	fingerprints = map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true,
		"360": true, "qq": true, "random": true, "randomized": true}
)

// Defaults fills the empty fields of a fragment.
func (f Fragment) Defaults() Fragment {
	if f.Packets == "" {
		f.Packets = "tlshello"
	}
	if f.Length == "" {
		f.Length = "100-200"
	}
	if f.Interval == "" {
		f.Interval = "10-20"
	}
	return f
}

// IsZero reports whether the overrides change nothing.
func (o *Overrides) IsZero() bool {
	return o == nil || (o.Mux == nil && o.MuxConcurrency == 0 && o.Fragment == nil && o.SNI == "" && o.Fingerprint == "")
}

// Validate checks the overrides on their own; Profile.Validate adds what needs the protocol.
func (o *Overrides) Validate() error {
	if o == nil {
		return nil
	}
	if o.MuxConcurrency < 0 || o.MuxConcurrency > 1024 {
		return fmt.Errorf("mux concurrency must be 1-1024")
	}
	if strings.ContainsAny(o.SNI, " \t\r\n/") {
		return fmt.Errorf("the server name must be a plain host name")
	}
	if o.Fingerprint != "" && !fingerprints[o.Fingerprint] {
		return fmt.Errorf("unknown TLS fingerprint %q", o.Fingerprint)
	}
	if f := o.Fragment; f != nil {
		if f.Packets != "" && f.Packets != "tlshello" && !rangeRe.MatchString(f.Packets) {
			return fmt.Errorf("fragment packets must be tlshello or a number or range such as 1-3")
		}
		for _, v := range []string{f.Length, f.Interval} {
			if v != "" && !rangeRe.MatchString(v) {
				return fmt.Errorf("fragment length and interval must be a number or a range such as 100-200")
			}
		}
	}
	return nil
}

// Apply returns the profile with the TLS overrides applied. Mux and fragment
// stay on p.Overrides for the config builders.
func (o *Overrides) Apply(p Profile) (Profile, error) {
	if o.IsZero() {
		return p, nil
	}
	if err := o.Validate(); err != nil {
		return p, err
	}
	p.Overrides = o
	tls := p.Security.Kind == "tls" || p.Security.Kind == "reality"
	if o.SNI != "" {
		if !tls {
			return p, fmt.Errorf("a server name override needs a TLS or Reality server")
		}
		p.Security.SNI = o.SNI
	}
	if o.Fingerprint != "" {
		if !tls {
			return p, fmt.Errorf("a fingerprint override needs a TLS or Reality server")
		}
		p.Security.Fingerprint = o.Fingerprint
	}
	if o.Fragment != nil {
		if p.UDPBased() {
			return p, fmt.Errorf("fragmentation only works for TCP servers")
		}
		if !tls {
			return p, fmt.Errorf("fragmentation needs a TLS or Reality server")
		}
	}
	return p, nil
}
