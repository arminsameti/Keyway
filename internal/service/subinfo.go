package service

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"keyway/internal/models"
)

const (
	maxTitleLen        = 80
	maxProviderUpdateH = 720 // same ceiling as the global setting
)

// parseUserinfo reads a Subscription-Userinfo header such as
// "upload=1; download=2; total=3; expire=1700000000". Providers leave fields
// out or send expire=0 for "never"; a header without any usable number is
// reported as absent.
func parseUserinfo(h string) (models.SubUsage, bool) {
	var u models.SubUsage
	found := false
	for _, part := range strings.Split(h, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n < 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			u.Upload, found = n, true
		case "download":
			u.Download, found = n, true
		case "total":
			u.Total, found = n, true
		case "expire":
			if n > 0 {
				e := time.Unix(n, 0).UTC()
				u.Expire = &e
			}
			found = true
		}
	}
	return u, found
}

// parseProfileTitle reads a Profile-Title header: plain text, percent-encoded,
// or "base64:" followed by the title. Control characters are dropped and the
// result is capped, since it ends up in the UI.
func parseProfileTitle(h string) string {
	h = strings.TrimSpace(h)
	if rest, ok := strings.CutPrefix(h, "base64:"); ok {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
		if err != nil {
			return ""
		}
		h = string(b)
	} else if dec, err := url.PathUnescape(h); err == nil {
		h = dec
	}
	h = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, h)
	if r := []rune(strings.TrimSpace(h)); len(r) > maxTitleLen {
		return string(r[:maxTitleLen])
	}
	return strings.TrimSpace(h)
}

// parseUpdateInterval reads Profile-Update-Interval (hours); 0 when absent or unusable.
func parseUpdateInterval(h string) int {
	n, err := strconv.Atoi(strings.TrimSpace(h))
	if err != nil || n <= 0 {
		return 0
	}
	return min(n, maxProviderUpdateH)
}

// subscriptionDue reports whether a subscription should be refreshed now.
// settingHours is the global interval (0 = automatic refresh is off, which also
// overrides a provider's wish); a provider's own interval replaces it.
func subscriptionDue(settingHours, providerHours int, updatedAt time.Time) bool {
	if settingHours <= 0 {
		return false
	}
	every := settingHours
	if providerHours > 0 {
		every = providerHours
	}
	return time.Since(updatedAt) >= time.Duration(every)*time.Hour
}
