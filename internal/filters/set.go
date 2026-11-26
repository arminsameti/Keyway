package filters

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Set is the merged, compiled domain set: sorted and free of entries that a
// broader suffix already covers.
type Set struct{ Suffix, Exact []string }

// Widened records a user allowlist entry that also dropped a broader blocked
// suffix, so the UI can say "Allowing <Allowed> also unblocks <Unblocked>".
type Widened struct{ Allowed, Unblocked string }

// Len is the number of entries in the set.
func (s Set) Len() int { return len(s.Suffix) + len(s.Exact) }

// Match reports whether host is blocked, and by which entry ("domain:x" or
// "full:x"). Matching walks the host's parent labels; there are no substring
// checks.
func (s Set) Match(host string) (string, bool) {
	for h := host; h != ""; h = parent(h) {
		if has(s.Suffix, h) {
			return "domain:" + h, true
		}
		if h == host && has(s.Exact, h) {
			return "full:" + h, true
		}
	}
	return "", false
}

func has(sorted []string, v string) bool {
	i := sort.SearchStrings(sorted, v)
	return i < len(sorted) && sorted[i] == v
}

// parent drops the first label ("" when none is left).
func parent(h string) string {
	i := strings.IndexByte(h, '.')
	if i < 0 {
		return ""
	}
	return h[i+1:]
}

// covered reports whether name, or any parent of it, is in m. With strict it
// starts at the parent.
func covered(m map[string]struct{}, name string, strict bool) (string, bool) {
	h := name
	if strict {
		h = parent(h)
	}
	for ; h != ""; h = parent(h) {
		if _, ok := m[h]; ok {
			return h, true
		}
	}
	return "", false
}

// Merge unions the lists and applies exceptions and the user allowlist (see
// the filter-lists spec, section 5.3). The lists' own @@ rules remove exactly
// the named entry from both buckets. Each allowlist entry is a suffix: it
// removes itself and everything under it, and drops any broader blocked suffix
// that covers it (reported in Widened). The limit applies to the final set.
func Merge(lists []Parsed, allowed []string, max int) (Set, []Widened, error) {
	suffix, exact := map[string]struct{}{}, map[string]struct{}{}
	for _, l := range lists {
		for d := range l.Suffix {
			suffix[d] = struct{}{}
		}
		for d := range l.Exact {
			exact[d] = struct{}{}
		}
	}
	for _, l := range lists {
		for _, m := range []map[string]struct{}{l.AllowSuffix, l.AllowExact} {
			for d := range m {
				delete(suffix, d)
				delete(exact, d)
			}
		}
	}

	allow := map[string]struct{}{}
	for _, a := range allowed {
		if n, ok := NormalizeHost(a); ok {
			allow[n] = struct{}{}
		}
	}
	var widened []Widened
	for a := range allow {
		for h := parent(a); h != ""; h = parent(h) {
			if _, ok := suffix[h]; ok {
				widened = append(widened, Widened{Allowed: a, Unblocked: h})
			}
		}
	}
	// Delete only after every entry was checked against the unmodified set,
	// so each allowed entry is reported.
	for _, w := range widened {
		delete(suffix, w.Unblocked)
	}
	sort.Slice(widened, func(i, j int) bool {
		if widened[i].Allowed != widened[j].Allowed {
			return widened[i].Allowed < widened[j].Allowed
		}
		return widened[i].Unblocked < widened[j].Unblocked
	})
	if len(allow) > 0 {
		for _, m := range []map[string]struct{}{suffix, exact} {
			for d := range m {
				if _, ok := covered(allow, d, false); ok {
					delete(m, d)
				}
			}
		}
	}

	// De-duplicate against broader suffixes.
	var s Set
	for d := range suffix {
		if _, ok := covered(suffix, d, true); !ok {
			s.Suffix = append(s.Suffix, d)
		}
	}
	for d := range exact {
		if _, ok := covered(suffix, d, false); !ok {
			s.Exact = append(s.Exact, d)
		}
	}
	sort.Strings(s.Suffix)
	sort.Strings(s.Exact)

	if s.Len() > max {
		return Set{}, nil, fmt.Errorf("the chosen lists have %s domains, more than the %s Keyway can load; turn some off",
			groupDigits(s.Len()), groupDigits(max))
	}
	return s, widened, nil
}

// groupDigits formats n with thousands separators.
func groupDigits(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b []byte
	for i := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b = append(b, ',')
		}
		b = append(b, s[i])
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
