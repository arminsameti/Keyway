package api

import (
	"net/http"
	"strconv"
	"strings"

	qrcode "github.com/skip2/go-qrcode"

	"xray-friendly/internal/models"
)

const (
	qrMinSize     = 128
	qrMaxSize     = 1024
	qrDefaultSize = 256
)

// ---- read-only views ----

func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.State())
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Status())
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.Atoi(r.URL.Query().Get("since"))
	lines, next, running := s.svc.Logs(since)
	ok(w, map[string]any{"logs": lines, "next": next, "running": running})
}

func (s *Server) configView(w http.ResponseWriter, r *http.Request) {
	b, err := s.svc.ConfigJSON()
	if err != nil {
		fail(w, http.StatusNotFound, "no config yet; press Connect once")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (s *Server) listNodes(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"nodes": s.svc.Nodes()})
}

func (s *Server) qr(w http.ResponseWriter, r *http.Request) {
	raw, err := s.svc.RawLink(r.URL.Query().Get("id"))
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	size := qrDefaultSize
	if n, err := strconv.Atoi(r.URL.Query().Get("size")); err == nil && n >= qrMinSize && n <= qrMaxSize {
		size = n
	}
	png, err := qrcode.Encode(raw, qrcode.Medium, size)
	if err != nil {
		fail(w, http.StatusUnprocessableEntity, "cannot encode QR: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(png)
}

// ---- nodes ----

func (s *Server) deleteNode(w http.ResponseWriter, r *http.Request) {
	n, err := s.svc.DeleteNodes(r.PathValue("id"))
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"removed": n})
}

func (s *Server) deleteNodes(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IDs []string `json:"ids"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	n, err := s.svc.DeleteNodes(b.IDs...)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"removed": n})
}

func (s *Server) setActive(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if err := s.svc.SetActive(b.ID); err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, nil)
}

func (s *Server) importLinks(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text string `json:"text"`
		URL  string `json:"url"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	res, err := s.svc.Import(r.Context(), b.Text, b.URL)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"added": res.Added, "errors": res.Errors, "total": res.Total})
}

// ---- subscriptions ----

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"subscriptions": s.svc.State().Subscriptions})
}

func (s *Server) addSubscription(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	sub, added, errs, err := s.svc.AddSubscription(r.Context(), b.Name, b.URL)
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"subscription": sub, "added": added, "errors": nonNil(errs)})
}

func (s *Server) refreshSubscription(w http.ResponseWriter, r *http.Request) {
	added, removed, errs, err := s.svc.RefreshSubscription(r.Context(), r.PathValue("id"))
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"added": added, "removed": removed, "errors": nonNil(errs)})
}

func (s *Server) refreshAllSubscriptions(w http.ResponseWriter, r *http.Request) {
	added, removed, errs := s.svc.RefreshAllSubscriptions(r.Context())
	ok(w, map[string]any{"added": added, "removed": removed, "errors": nonNil(errs)})
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.RemoveSubscription(r.PathValue("id")); err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, nil)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- cores ----

func (s *Server) coresList(w http.ResponseWriter, r *http.Request) {
	v := s.svc.Cores()
	ok(w, map[string]any{"installed": v.Installed, "active": v.Active, "dir": v.Dir})
}

func (s *Server) coresFetch(w http.ResponseWriter, r *http.Request) {
	rs, err := s.svc.FetchReleases(r.Context())
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"releases": rs})
}

func (s *Server) coresDownload(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Version string `json:"version"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	v, err := s.svc.DownloadCore(r.Context(), b.Version)
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"active": v})
}

func (s *Server) coresUse(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Version string `json:"version"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	v, err := s.svc.UseCore(b.Version)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"active": v})
}

// ---- settings ----

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.State().Settings)
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in models.Settings
	if err := decode(r, &in, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	res, err := s.svc.UpdateSettings(r.Context(), in)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"reconnectRequired": res.ReconnectRequired, "restartRequired": res.RestartRequired})
}

// ---- connection ----

func (s *Server) connect(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.Connect(r.Context())
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	extra := map[string]any{"config": res.Config}
	if res.Warning != "" {
		extra["warning"] = res.Warning
	}
	ok(w, extra)
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Disconnect(r.Context()); err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, nil)
}

func (s *Server) latency(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode string `json:"mode"`
	}
	if err := decode(r, &b, true); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	lat, mode, err := s.svc.TestLatency(r.Context(), b.Mode)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"latency": lat, "mode": mode})
}

func (s *Server) pickFastest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reconnect bool   `json:"reconnect"`
		Mode      string `json:"mode"`
	}
	if err := decode(r, &b, true); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	res, err := s.svc.PickFastest(r.Context(), b.Reconnect, b.Mode)
	if err != nil {
		status := statusFor(err, http.StatusInternalServerError)
		out := map[string]any{"ok": false, "error": err.Error()}
		if res.Latency != nil {
			out["latency"] = res.Latency
		}
		writeJSON(w, status, out)
		return
	}
	ok(w, map[string]any{
		"id": res.ID, "name": res.Name, "latencyMs": res.LatencyMs,
		"latency": res.Latency, "mode": res.Mode, "reconnected": res.Reconnected,
	})
}

// ---- system proxy ----

func (s *Server) getSysProxy(w http.ResponseWriter, r *http.Request) {
	v := s.svc.SystemProxy(r.Context())
	ok(w, map[string]any{
		"supported": v.Supported, "services": v.Services, "primary": v.Primary,
		"enabled": v.Enabled, "states": v.States,
	})
}

func (s *Server) setSysProxy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		On       bool     `json:"on"`
		Services []string `json:"services"`
		Service  string   `json:"service"` // legacy single-service form
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if b.Service != "" {
		b.Services = append(b.Services, b.Service)
	}
	v, err := s.svc.SetSystemProxy(r.Context(), b.On, b.Services)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"supported": v.Supported, "enabled": v.Enabled, "states": v.States})
}

func (s *Server) traffic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Traffic())
}

// routingImport parses pasted routing rules without saving anything.
func (s *Server) routingImport(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text string `json:"text"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	rules, skipped, err := models.ParseRules(b.Text)
	if err != nil {
		failErr(w, &models.ValidationError{Msg: err.Error()}, http.StatusBadRequest)
		return
	}
	ok(w, map[string]any{"rules": rules, "skipped": skipped})
}

// routingTest reports which rule of the given (or the active) set a destination hits.
func (s *Server) routingTest(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Host  string             `json:"host"`
		Port  int                `json:"port"`
		Rules []models.RouteRule `json:"rules"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(b.Host) == "" {
		failErr(w, &models.ValidationError{Msg: "enter a domain or an IP address"}, http.StatusBadRequest)
		return
	}
	rules := b.Rules
	if rules == nil {
		rules = s.svc.State().Settings.ActiveRules()
	}
	ok(w, map[string]any{"match": models.MatchRoute(rules, b.Host, b.Port)})
}

// nodeConfig shows the configuration that would run for a node.
func (s *Server) nodeConfig(w http.ResponseWriter, r *http.Request) {
	p, err := s.svc.PreviewConfig(r.PathValue("id"))
	if err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	ok(w, map[string]any{"engines": p.Engines, "configs": p.Configs})
}

func (s *Server) tunHelper(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"helper": s.svc.TUNHelperStatus()})
}

// setTunHelper installs or removes one-time authorization; macOS asks for the password.
func (s *Server) setTunHelper(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Action string `json:"action"` // install | uninstall
	}
	if err := decode(r, &b, false); err != nil || (b.Action != "install" && b.Action != "uninstall") {
		failErr(w, &models.ValidationError{Msg: "action must be install or uninstall"}, http.StatusBadRequest)
		return
	}
	h, err := s.svc.SetTUNHelper(r.Context(), b.Action == "install")
	if err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	ok(w, map[string]any{"helper": h})
}
