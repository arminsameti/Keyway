package core

import (
	"regexp"
	"strconv"
	"strings"
)

// versionRe is the only shape of version string accepted anywhere: it is used in
// file paths and download URLs, so it must never contain separators or "..".
var versionRe = regexp.MustCompile(`^v\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// NormalizeVersion adds the leading "v" if missing.
func NormalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// ValidVersion reports whether v is a well-formed Xray release tag (vMAJOR.MINOR.PATCH).
func ValidVersion(v string) bool { return versionRe.MatchString(v) }

func parts(v string) [3]int {
	var out [3]int
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		if i > 2 {
			break
		}
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out
}

// CompareVersions compares two release tags numerically (v25.10.0 > v25.9.0).
func CompareVersions(a, b string) int {
	pa, pb := parts(a), parts(b)
	for i := 0; i < 3; i++ {
		switch {
		case pa[i] < pb[i]:
			return -1
		case pa[i] > pb[i]:
			return 1
		}
	}
	return 0
}
