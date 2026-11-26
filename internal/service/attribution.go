package service

import (
	"strings"

	"keyway/internal/filters"
)

// attribution answers "which enabled list contains this host" from memory, so
// the rule tester never re-parses the raw lists. It is built at compile time
// from the union of the lists (a domain keeps the first list, in the user's
// order, that has it) and holds no per-list copies of the parsed sets. Entries
// a list's own @@ rules (or any other list's) remove are left out, as Merge
// removes them; the user's allowlist is not applied, so a host it unblocks is
// still attributed (that is what AllowedBy reports).
type attribution struct {
	names         []string
	suffix, exact map[string]int32
}

func newAttribution() *attribution {
	return &attribution{suffix: map[string]int32{}, exact: map[string]int32{}}
}

// add folds in the next list; pass the lists in the user's order.
func (a *attribution) add(name string, p filters.Parsed, removed map[string]struct{}) {
	i := int32(len(a.names))
	a.names = append(a.names, name)
	for d := range p.Suffix {
		if _, gone := removed[d]; gone {
			continue
		}
		if _, ok := a.suffix[d]; !ok {
			a.suffix[d] = i
		}
	}
	for d := range p.Exact {
		if _, gone := removed[d]; gone {
			continue
		}
		if _, ok := a.exact[d]; !ok {
			a.exact[d] = i
		}
	}
}

// listFor names the first list that contains host (the host itself or, for
// suffix entries, a parent of it).
func (a *attribution) listFor(host string) (string, bool) {
	if a == nil {
		return "", false
	}
	best := int32(-1)
	if i, ok := a.exact[host]; ok {
		best = i
	}
	for h := host; h != ""; {
		if i, ok := a.suffix[h]; ok && (best < 0 || i < best) {
			best = i
		}
		dot := strings.IndexByte(h, '.')
		if dot < 0 {
			break
		}
		h = h[dot+1:]
	}
	if best < 0 {
		return "", false
	}
	return a.names[best], true
}
