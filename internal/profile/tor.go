package profile

import (
	"fmt"
	"regexp"
	"strings"
)

// Tor is a node with no server of its own: Keyway runs a Tor client, optionally
// through bridges, and the next hop (or the user's apps) dials its SOCKS port.
const Tor = "tor"

// Bridge modes of a Tor node.
const (
	TorBridgeNone      = "none"
	TorBridgeObfs4     = "obfs4"
	TorBridgeSnowflake = "snowflake"
	TorBridgeMeek      = "meek"
	TorBridgeCustom    = "custom"
)

const (
	maxTorLines   = 20
	maxTorLineLen = 512
)

// TorOpts is the profile of a Tor node.
type TorOpts struct {
	Bridges string   `json:"bridges"`         // none | obfs4 | snowflake | meek | custom
	Lines   []string `json:"lines,omitempty"` // custom bridge lines, as bridges.torproject.org gives them
}

// torLineRe is the shape of one bridge line: an optional transport name, an
// address:port (or a bare token for transports such as snowflake), an optional
// 40-hex fingerprint and optional key=value arguments.
var torLineRe = regexp.MustCompile(`^(?:[a-z][a-z0-9_]* )?(?:\[?[0-9A-Fa-f:.]+\]?:\d{1,5}|[A-Za-z0-9.-]+:\d{1,5})(?: [0-9A-Fa-f]{40})?(?: \S+=\S*)*$`)

// SafeTorValue rejects anything that could end the current torrc line.
func SafeTorValue(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("Tor: control characters are not allowed")
		}
	}
	return nil
}

// Validate checks the options of a Tor node.
func (o TorOpts) Validate() error {
	switch o.Bridges {
	case TorBridgeNone, TorBridgeObfs4, TorBridgeSnowflake, TorBridgeMeek:
		return nil
	case TorBridgeCustom:
	default:
		return fmt.Errorf("Tor: unknown bridge mode %q", o.Bridges)
	}
	if len(o.Lines) == 0 {
		return fmt.Errorf("Tor: paste at least one bridge line")
	}
	if len(o.Lines) > maxTorLines {
		return fmt.Errorf("Tor: at most %d bridge lines", maxTorLines)
	}
	for _, l := range o.Lines {
		if err := SafeTorValue(l); err != nil {
			return err
		}
		l = strings.TrimSpace(l)
		if len(l) > maxTorLineLen || !torLineRe.MatchString(l) {
			return fmt.Errorf("Tor: not a valid bridge line")
		}
	}
	return nil
}

func (p Profile) validateTor() error {
	if p.Tor == nil {
		return fmt.Errorf("Tor: missing settings")
	}
	return p.Tor.Validate()
}
