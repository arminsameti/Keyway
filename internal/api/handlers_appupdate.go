package api

import "net/http"

// ---- Keyway's own updates ----

func (s *Server) appUpdate(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"update": s.svc.AppUpdate()})
}

func (s *Server) appUpdateCheck(w http.ResponseWriter, r *http.Request) {
	v, err := s.svc.CheckAppUpdate(r.Context())
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"update": v})
}

func (s *Server) appUpdateDownload(w http.ResponseWriter, r *http.Request) {
	v, err := s.svc.StartAppUpdateDownload()
	if err != nil {
		failErr(w, err, http.StatusConflict)
		return
	}
	ok(w, map[string]any{"update": v})
}
