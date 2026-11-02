// Package api is the thin HTTP layer: routing, security middleware and JSON
// mapping. All behaviour lives in internal/service.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"keyway/internal/core"
	"keyway/internal/models"
	"keyway/internal/service"
	"keyway/internal/sysproxy"
)

// Config configures the HTTP server.
type Config struct {
	Token  string // per-launch secret required on every /api/ call
	Port   int    // port the listener is bound to (for the Host allow-list)
	Logger *slog.Logger
}

// Server serves the JSON API used by the native app.
type Server struct {
	svc   *service.Service
	token string
	port  int
	log   *slog.Logger
}

// New builds the server.
func New(svc *service.Service, cfg Config) (*Server, error) {
	if cfg.Token == "" {
		return nil, errors.New("api: token must not be empty")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{svc: svc, token: cfg.Token, port: cfg.Port, log: cfg.Logger}, nil
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/state", s.state)
	mux.HandleFunc("GET /api/status", s.status)
	mux.HandleFunc("GET /api/logs", s.logs)
	mux.HandleFunc("GET /api/config", s.configView)

	mux.HandleFunc("GET /api/nodes", s.listNodes)
	mux.HandleFunc("POST /api/nodes", s.createNode)
	mux.HandleFunc("PUT /api/nodes/{id}", s.updateNode)
	mux.HandleFunc("POST /api/nodes/test", s.testServer)
	mux.HandleFunc("POST /api/import/preview", s.previewImport)
	mux.HandleFunc("POST /api/links/parse", s.parseLink)
	mux.HandleFunc("POST /api/chains/plan", s.planChain)
	mux.HandleFunc("GET /api/nodes/{id}/profile", s.nodeProfile)
	mux.HandleFunc("GET /api/jobs", s.listJobs)
	mux.HandleFunc("GET /api/jobs/{id}", s.getJob)
	mux.HandleFunc("DELETE /api/nodes/{id}", s.deleteNode)
	mux.HandleFunc("POST /api/nodes/delete", s.deleteNodes)
	mux.HandleFunc("GET /api/traffic", s.traffic)
	mux.HandleFunc("GET /api/tun/helper", s.tunHelper)
	mux.HandleFunc("POST /api/tun/helper", s.setTunHelper)
	mux.HandleFunc("GET /api/nodes/{id}/config", s.nodeConfig)
	mux.HandleFunc("POST /api/routing/import", s.routingImport)
	mux.HandleFunc("POST /api/routing/test", s.routingTest)
	mux.HandleFunc("POST /api/active", s.setActive)
	mux.HandleFunc("POST /api/import", s.importLinks)
	mux.HandleFunc("GET /api/qr", s.qr)

	mux.HandleFunc("GET /api/subscriptions", s.listSubscriptions)
	mux.HandleFunc("POST /api/subscriptions", s.addSubscription)
	mux.HandleFunc("POST /api/subscriptions/refresh", s.refreshAllSubscriptions)
	mux.HandleFunc("POST /api/subscriptions/{id}/refresh", s.refreshSubscription)
	mux.HandleFunc("DELETE /api/subscriptions/{id}", s.deleteSubscription)
	mux.HandleFunc("POST /api/subscription", s.addSubscription) // legacy alias

	mux.HandleFunc("GET /api/engines", s.enginesList)
	mux.HandleFunc("GET /api/engines/{name}/releases", s.engineReleases)
	mux.HandleFunc("POST /api/engines/{name}/download", s.engineDownload)
	mux.HandleFunc("POST /api/engines/{name}/use", s.engineUse)
	mux.HandleFunc("POST /api/engines/{name}/check", s.engineCheck)

	// Xray-only aliases kept for the transition to /api/engines.
	mux.HandleFunc("GET /api/cores", s.coresList)
	mux.HandleFunc("POST /api/cores/fetch", s.coresFetch)
	mux.HandleFunc("POST /api/cores/download", s.coresDownload)
	mux.HandleFunc("POST /api/cores/use", s.coresUse)

	mux.HandleFunc("GET /api/app-update", s.appUpdate)
	mux.HandleFunc("POST /api/app-update/check", s.appUpdateCheck)
	mux.HandleFunc("POST /api/app-update/download", s.appUpdateDownload)

	mux.HandleFunc("GET /api/settings", s.getSettings)
	mux.HandleFunc("POST /api/settings", s.putSettings)

	mux.HandleFunc("POST /api/connect", s.connect)
	mux.HandleFunc("POST /api/reconnect", s.connect)
	mux.HandleFunc("POST /api/disconnect", s.disconnect)
	mux.HandleFunc("POST /api/latency", s.latency)
	mux.HandleFunc("POST /api/pick-fastest", s.pickFastest)

	mux.HandleFunc("GET /api/sysproxy", s.getSysProxy)
	mux.HandleFunc("POST /api/sysproxy", s.setSysProxy)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fail(w, http.StatusNotFound, "not found")
	})

	hosts := map[string]bool{}
	for _, h := range []string{"127.0.0.1", "localhost", "[::1]"} {
		hosts[fmt.Sprintf("%s:%d", h, s.port)] = true
	}
	return chain(mux,
		recoverer(s.log),
		securityHeaders,
		requestLog(s.log),
		hostCheck(hosts),
		originCheck,
		apiGuard(s.token),
	)
}

// ---- response helpers ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ok answers 200 with {"ok":true, ...extra}.
func ok(w http.ResponseWriter, extra map[string]any) {
	out := make(map[string]any, len(extra)+1)
	for k, v := range extra {
		out[k] = v
	}
	out["ok"] = true
	writeJSON(w, http.StatusOK, out)
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": msg})
}

// statusFor maps an error to an HTTP status; upstream is used for unclassified
// errors from remote services (GitHub, subscription servers).
func statusFor(err error, fallback int) int {
	var ve *models.ValidationError
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &ve):
		return http.StatusBadRequest
	case errors.As(err, &mbe):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, service.ErrNodeNotFound):
		return http.StatusNotFound
	case errors.Is(err, service.ErrNoActiveNode), errors.Is(err, service.ErrNoNodes),
		errors.Is(err, service.ErrBusy), errors.Is(err, core.ErrNotInstalled):
		return http.StatusConflict
	case errors.Is(err, service.ErrAllFailed):
		return http.StatusBadGateway
	case errors.Is(err, sysproxy.ErrUnsupported):
		return http.StatusNotImplemented
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout
	}
	return fallback
}

func failErr(w http.ResponseWriter, err error, fallback int) {
	fail(w, statusFor(err, fallback), err.Error())
}

// decode reads a JSON body into v. An empty body is accepted when optional.
func decode(r *http.Request, v any, optional bool) error {
	err := json.NewDecoder(r.Body).Decode(v)
	if errors.Is(err, io.EOF) && optional {
		return nil
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return &models.ValidationError{Msg: "invalid JSON body: " + err.Error()}
	}
	return nil
}
