package service

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func allowAll(net.IP) bool { return false }

// trustServer makes fetchList trust the httptest TLS server's certificate.
func trustServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	listRootCAs = pool
	t.Cleanup(func() { listRootCAs = nil })
}

func TestFetchListConditional(t *testing.T) {
	var gotUA string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v2"`)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		io.WriteString(w, "||a.com^\n")
	}))
	defer srv.Close()
	trustServer(t, srv)

	r, err := fetchList(context.Background(), listFetch{URL: srv.URL, ETag: `"v1"`, MaxBytes: 1 << 20}, allowAll)
	if err != nil || !r.NotModified {
		t.Fatalf("want NotModified, got %+v err=%v", r, err)
	}
	if gotUA != "Keyway" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	r, err = fetchList(context.Background(), listFetch{URL: srv.URL, MaxBytes: 1 << 20}, allowAll)
	if err != nil || r.NotModified || string(r.Body) != "||a.com^\n" || r.ETag != `"v2"` || r.LastModified == "" {
		t.Fatalf("unexpected %+v err=%v", r, err)
	}
}

func TestFetchListCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, strings.Repeat("a", 11))
	}))
	defer srv.Close()
	trustServer(t, srv)
	_, err := fetchList(context.Background(), listFetch{URL: srv.URL, MaxBytes: 10}, allowAll)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("want size error, got %v", err)
	}
	if _, err := fetchList(context.Background(), listFetch{URL: srv.URL, MaxBytes: 11}, allowAll); err != nil {
		t.Fatalf("exactly MaxBytes must pass: %v", err)
	}
}

func TestFetchListHTTPSOnly(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	_, err := fetchList(context.Background(), listFetch{URL: srv.URL, MaxBytes: 10}, allowAll)
	if err == nil || !strings.Contains(err.Error(), "https") || hits.Load() != 0 {
		t.Fatalf("want https validation error with no request, got %v (hits %d)", err, hits.Load())
	}
}

func TestFetchListRefusesHTTPRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "x") }))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer srv.Close()
	trustServer(t, srv)
	_, err := fetchList(context.Background(), listFetch{URL: srv.URL, MaxBytes: 10}, allowAll)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("want redirect refusal, got %v", err)
	}
}

func TestFetchListBlockedAddress(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "x") }))
	defer srv.Close()
	trustServer(t, srv)
	if _, err := fetchList(context.Background(), listFetch{URL: srv.URL, MaxBytes: 10}, blockedIP); err == nil {
		t.Fatal("loopback must be refused by the real guard")
	}
}

// fakeSOCKS5 serves no-auth SOCKS5 CONNECT on loopback and counts tunnels.
func fakeSOCKS5(t *testing.T) (addr string, tunnels *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tunnels = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				h := make([]byte, 2)
				if _, err := io.ReadFull(c, h); err != nil {
					return
				}
				io.ReadFull(c, make([]byte, int(h[1])))
				c.Write([]byte{5, 0})
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				var host string
				switch req[3] {
				case 1:
					b := make([]byte, 4)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				case 3:
					l := make([]byte, 1)
					io.ReadFull(c, l)
					b := make([]byte, l[0])
					io.ReadFull(c, b)
					host = string(b)
				case 4:
					b := make([]byte, 16)
					io.ReadFull(c, b)
					host = net.IP(b).String()
				}
				p := make([]byte, 2)
				io.ReadFull(c, p)
				port := int(p[0])<<8 | int(p[1])
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				tunnels.Add(1)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	return ln.Addr().String(), tunnels
}

func TestFetchListProxy(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "||a.com^\n") }))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	trustServer(t, srv)
	proxy, tunnels := fakeSOCKS5(t)

	// The proxy hop is loopback; the guard must not apply to it, but must
	// still be what a direct dial would face.
	r, err := fetchList(context.Background(), listFetch{URL: srv.URL, ProxyAddr: proxy, MaxBytes: 1 << 20}, blockedIP)
	if err != nil || string(r.Body) != "||a.com^\n" {
		t.Fatalf("got %+v err=%v", r, err)
	}
	if tunnels.Load() != 1 || conns.Load() != 1 {
		t.Errorf("tunnels=%d server conns=%d, want 1/1", tunnels.Load(), conns.Load())
	}
}

func TestFetchListProxyNoRetryOnStatus(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	trustServer(t, srv)
	proxy, _ := fakeSOCKS5(t)
	_, err := fetchList(context.Background(), listFetch{URL: srv.URL, ProxyAddr: proxy, MaxBytes: 10}, allowAll)
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error, got %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("server hit %d times, want 1 (no direct retry)", hits.Load())
	}
}

func TestFetchListProxyFallback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	trustServer(t, srv)
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := dead.Addr().String()
	dead.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := fetchList(ctx, listFetch{URL: srv.URL, ProxyAddr: addr, MaxBytes: 10}, allowAll)
	if err != nil || string(r.Body) != "ok" {
		t.Fatalf("got %+v err=%v", r, err)
	}
	// The retry is guarded.
	if _, err := fetchList(ctx, listFetch{URL: srv.URL, ProxyAddr: addr, MaxBytes: 10}, blockedIP); err == nil {
		t.Fatal("direct retry must still apply the address guard")
	}
}
