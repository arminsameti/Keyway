package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"keyway/internal/models"
)

const (
	maxSubscriptionBody = 4 << 20
	fetchTimeout        = 30 * time.Second
	userAgent           = "v2rayN keyway"
)

var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// blockedIP reports addresses a user-supplied URL must never reach (SSRF guard).
func blockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || cgnat.Contains(ip)
}

// ValidateURL checks a subscription URL's shape.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return nil, &models.ValidationError{Msg: "invalid URL"}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, &models.ValidationError{Msg: "only http:// and https:// URLs are supported"}
	}
	return u, nil
}

// subResponse is a downloaded subscription: the body and the provider's headers.
type subResponse struct {
	Body   string
	Header http.Header
}

// safeFetch downloads a subscription. The dialer's Control hook runs after
// DNS resolution on every connection (including redirects), so a hostname that
// resolves to a loopback/private/link-local address is refused: this app's own
// local API and the LAN are not reachable through the subscription feature.
func safeFetch(ctx context.Context, raw string) (subResponse, error) {
	return fetchFrom(ctx, raw, blockedIP)
}

// fetchFrom is safeFetch with the address guard injected (tests reach httptest
// servers on loopback).
func fetchFrom(ctx context.Context, raw string, blocked func(net.IP) bool) (subResponse, error) {
	u, err := ValidateURL(raw)
	if err != nil {
		return subResponse{}, err
	}
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || blocked(ip) {
				return fmt.Errorf("refusing to connect to non-public address %s", host)
			}
			return nil
		},
	}
	client := &http.Client{
		Timeout:   fetchTimeout,
		Transport: &http.Transport{DialContext: dialer.DialContext, Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return subResponse{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return subResponse{}, fmt.Errorf("fetch subscription: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return subResponse{}, fmt.Errorf("subscription server answered %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBody+1))
	if err != nil {
		return subResponse{}, fmt.Errorf("read subscription: %w", err)
	}
	if len(b) > maxSubscriptionBody {
		return subResponse{}, errors.New("subscription is larger than 4 MiB")
	}
	return subResponse{Body: string(b), Header: resp.Header}, nil
}
