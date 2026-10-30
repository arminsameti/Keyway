package api

import (
	"crypto/subtle"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// TokenHeader carries the per-launch API token.
	TokenHeader = "X-XF-Token"
	maxBody     = 1 << 20

	// The server only answers JSON (and QR PNGs) to the native app: nothing a
	// browser renders from it may load or run anything.
	csp = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

// chain applies middleware outermost-first.
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func recoverer(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					log.Error("handler panic", "path", r.URL.Path, "panic", v)
					fail(w, http.StatusInternalServerError, "internal error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func requestLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			log.Debug("request", "method", r.Method, "path", r.URL.Path, "dur", time.Since(start))
		})
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// hostCheck rejects requests whose Host header is not a loopback name on our
// port. This is what defeats DNS-rebinding: a rebinding page reaches this
// server, but with its own attacker-controlled Host value.
func hostCheck(allowed map[string]bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowed[strings.ToLower(r.Host)] {
				fail(w, http.StatusForbidden, "unexpected Host header")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// originCheck blocks cross-site browser requests (CSRF). Browsers always send
// Origin on cross-origin POSTs and Sec-Fetch-Site on modern requests.
func originCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, http.StatusForbidden, "cross-site request refused")
			return
		}
		if o := r.Header.Get("Origin"); o != "" {
			u, err := url.Parse(o)
			if err != nil || !strings.EqualFold(u.Host, r.Host) {
				fail(w, http.StatusForbidden, "cross-origin request refused")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// apiGuard protects /api/*: token required, and bodies must be JSON and small.
func apiGuard(token string) func(http.Handler) http.Handler {
	want := []byte(token)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.Header.Get(TokenHeader)), want) != 1 {
				fail(w, http.StatusUnauthorized, "missing or invalid API token")
				return
			}
			if r.ContentLength != 0 && r.Method != http.MethodGet && r.Method != http.MethodHead {
				mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || mt != "application/json" {
					fail(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
					return
				}
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
			next.ServeHTTP(w, r)
		})
	}
}
