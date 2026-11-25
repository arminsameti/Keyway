package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	listUserAgent       = "Keyway"
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
	client := &http.Client{
		Timeout:       fetchTimeout,
		Transport:     &http.Transport{DialContext: guardedDialer(blocked).DialContext, Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: limitRedirects(false),
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

// guardedDialer refuses, after DNS resolution, any address blocked() rejects.
func guardedDialer(blocked func(net.IP) bool) *net.Dialer {
	return &net.Dialer{
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
}

var (
	errTooManyRedirects = errors.New("too many redirects")
	errRedirectNotHTTPS = errors.New("refusing redirect to a non-https URL")
)

// limitRedirects bounds a redirect chain at 5 hops; httpsOnly also refuses
// any hop that leaves https.
func limitRedirects(httpsOnly bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errTooManyRedirects
		}
		if httpsOnly && req.URL.Scheme != "https" {
			return errRedirectNotHTTPS
		}
		return nil
	}
}

// listRootCAs overrides the trusted roots for list downloads; tests set it to
// trust an httptest TLS server. Nil in production (system roots).
var listRootCAs *x509.CertPool

// listFetch describes one filter-list download. ETag and LastModified make it
// conditional; ProxyAddr, when set, is a local SOCKS5 inbound to route through.
type listFetch struct {
	URL, ETag, LastModified, ProxyAddr string
	MaxBytes                           int64
}

type listResponse struct {
	Body               []byte
	NotModified        bool
	ETag, LastModified string
}

// fetchList downloads a filter list over https. With ProxyAddr it goes through
// that proxy (whose hop is exempt from blocked, but may reach only ProxyAddr);
// if the proxy can't be used it retries once directly, with the guard.
func fetchList(ctx context.Context, f listFetch, blocked func(net.IP) bool) (listResponse, error) {
	u, err := ValidateURL(f.URL)
	if err != nil {
		return listResponse{}, err
	}
	if u.Scheme != "https" {
		return listResponse{}, &models.ValidationError{Msg: "list URLs must use https://"}
	}
	if f.ProxyAddr != "" {
		r, err := doListFetch(ctx, u, f, proxyTransport(f.ProxyAddr))
		if err == nil || !retryDirect(ctx, err) {
			return r, err
		}
	}
	return doListFetch(ctx, u, f, directTransport(blocked))
}

// retryDirect reports whether a proxied attempt failed before any HTTP answer
// (dial/handshake), as opposed to a status, size or redirect-policy error.
func retryDirect(ctx context.Context, err error) bool {
	var he httpStatusError
	return ctx.Err() == nil && !errors.As(err, &he) &&
		!errors.Is(err, errTooManyRedirects) && !errors.Is(err, errRedirectNotHTTPS) &&
		!errors.Is(err, errListTooLarge)
}

type httpStatusError struct{ status string }

func (e httpStatusError) Error() string { return "list server answered " + e.status }

var errListTooLarge = errors.New("list is larger than the size limit")

func listTLS() *tls.Config { return &tls.Config{RootCAs: listRootCAs, MinVersion: tls.VersionTLS12} }

func directTransport(blocked func(net.IP) bool) *http.Transport {
	return &http.Transport{DialContext: guardedDialer(blocked).DialContext, Proxy: nil, DisableKeepAlives: true, TLSClientConfig: listTLS()}
}

// proxyTransport dials only the proxy's own loopback address.
func proxyTransport(addr string) *http.Transport {
	d := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			if address != addr {
				return fmt.Errorf("refusing to connect to %s: only the local proxy is allowed", address)
			}
			return nil
		},
	}
	return &http.Transport{
		DialContext:       d.DialContext,
		Proxy:             http.ProxyURL(&url.URL{Scheme: "socks5", Host: addr}),
		DisableKeepAlives: true,
		TLSClientConfig:   listTLS(),
	}
}

func doListFetch(ctx context.Context, u *url.URL, f listFetch, tr *http.Transport) (listResponse, error) {
	client := &http.Client{Timeout: fetchTimeout, Transport: tr, CheckRedirect: limitRedirects(true)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return listResponse{}, err
	}
	req.Header.Set("User-Agent", listUserAgent)
	if f.ETag != "" {
		req.Header.Set("If-None-Match", f.ETag)
	}
	if f.LastModified != "" {
		req.Header.Set("If-Modified-Since", f.LastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return listResponse{}, fmt.Errorf("fetch list: %w", err)
	}
	defer resp.Body.Close()
	out := listResponse{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	switch resp.StatusCode {
	case http.StatusNotModified:
		out.NotModified = true
		return out, nil
	case http.StatusOK:
	default:
		return listResponse{}, httpStatusError{resp.Status}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return listResponse{}, fmt.Errorf("read list: %w", err)
	}
	if int64(len(b)) > f.MaxBytes {
		return listResponse{}, fmt.Errorf("list is larger than %d bytes: %w", f.MaxBytes, errListTooLarge)
	}
	out.Body = b
	return out, nil
}
