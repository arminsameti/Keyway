// Package filters parses ad-block, hosts and plain domain lists into domain sets.
package filters

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf8"
)

// Parsed is the domain content of one list. Suffix entries match the domain
// and its subdomains, Exact entries only the domain itself. The Allow sets
// hold the list's own @@ exceptions. Skipped counts lines that were neither
// comments nor usable rules.
type Parsed struct {
	Suffix, Exact, AllowSuffix, AllowExact map[string]struct{}
	Skipped                                int
}

// hostsSkip are hosts-file names that are never ad domains.
var hostsSkip = map[string]bool{
	"localhost": true, "local": true, "broadcasthost": true,
	"localhost.localdomain": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true,
	"ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// Parse reads an adblock-syntax, hosts-file or plain domain list. It errors
// only on a read failure or when no usable rule was found (for example an HTML
// error page).
func Parse(r io.Reader) (Parsed, error) {
	p := Parsed{
		Suffix: map[string]struct{}{}, Exact: map[string]struct{}{},
		AllowSuffix: map[string]struct{}{}, AllowExact: map[string]struct{}{},
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}
		if !p.addLine(line) {
			p.Skipped++
		}
	}
	if err := sc.Err(); err != nil {
		return Parsed{}, fmt.Errorf("read list: %w", err)
	}
	if len(p.Suffix)+len(p.Exact)+len(p.AllowSuffix)+len(p.AllowExact) == 0 {
		return Parsed{}, errors.New("no domains found")
	}
	return p, nil
}

// addLine files one rule and reports whether it was usable.
func (p *Parsed) addLine(line string) bool {
	if strings.ContainsAny(line, " \t") {
		return p.addHostsLine(line)
	}
	allow := strings.HasPrefix(line, "@@")
	line = strings.TrimPrefix(line, "@@")
	exact := false
	suffix := true
	switch {
	case strings.HasPrefix(line, "||"):
		line = line[2:]
	case strings.HasPrefix(line, "|"):
		line, exact, suffix = line[1:], true, false
	}
	if i := strings.IndexByte(line, '$'); i >= 0 {
		if line[i+1:] != "important" {
			return false
		}
		line = line[:i]
	}
	line = strings.TrimSuffix(line, "^")
	host, ok := NormalizeHost(line)
	if !ok || hostsSkip[host] {
		return false
	}
	switch {
	case allow && exact:
		p.AllowExact[host] = struct{}{}
	case allow:
		p.AllowSuffix[host] = struct{}{}
	case suffix:
		p.Suffix[host] = struct{}{}
	default:
		p.Exact[host] = struct{}{}
	}
	return true
}

// addHostsLine handles "0.0.0.0 a.com b.com # note". A whitespace-bearing line
// that is not an IP followed by names is not a rule.
func (p *Parsed) addHostsLine(line string) bool {
	f := strings.Fields(line)
	if net.ParseIP(f[0]) == nil {
		return false
	}
	added := false
	for _, name := range f[1:] {
		if name[0] == '#' {
			break
		}
		host, ok := NormalizeHost(name)
		if !ok || hostsSkip[host] {
			continue
		}
		p.Exact[host] = struct{}{}
		added = true
	}
	return added
}

// NormalizeHost lowercases s, trims a trailing dot and punycode-encodes
// non-ASCII labels. It rejects IP literals, empty labels, labels over 63
// bytes, names over 253 and any character outside [a-z0-9-_].
func NormalizeHost(s string) (string, bool) {
	// Bound the input before any per-rune work: a hostile list can carry a
	// megabyte-long line, and punycode is quadratic in its length.
	if len(s) > 253*4+1 {
		return "", false
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" || net.ParseIP(s) != nil {
		return "", false
	}
	labels := strings.Split(s, ".")
	for i, l := range labels {
		if l == "" {
			return "", false
		}
		for j := 0; j < len(l); j++ {
			if l[j] >= 0x80 {
				if utf8.RuneCountInString(l) > 63 {
					return "", false
				}
				l = "xn--" + punycodeEncode(l)
				break
			}
		}
		if len(l) > 63 {
			return "", false
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", false
			}
		}
		labels[i] = l
	}
	// A numeric last label is never a real TLD: this catches "1.2.3" style leftovers.
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "", false
	}
	out := strings.Join(labels, ".")
	if len(out) > 253 {
		return "", false
	}
	return out, true
}
