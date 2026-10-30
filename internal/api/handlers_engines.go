package api

import (
	"net/http"

	"xray-friendly/internal/service"
)

// ---- import preview & manual servers ----

func (s *Server) previewImport(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Text string `json:"text"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	p := s.svc.PreviewImport(b.Text)
	ok(w, map[string]any{"items": p.Items, "ready": p.Ready, "subscriptions": p.Subscriptions, "skipped": p.Skipped})
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request) {
	var in service.NodeInput
	if err := decode(r, &in, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	n, err := s.svc.CreateNode(in)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"node": n})
}

func (s *Server) updateNode(w http.ResponseWriter, r *http.Request) {
	var in service.NodeInput
	if err := decode(r, &in, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	n, err := s.svc.UpdateNode(r.PathValue("id"), in)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"node": n})
}

func (s *Server) testServer(w http.ResponseWriter, r *http.Request) {
	var in service.NodeInput
	if err := decode(r, &in, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	ms, err := s.svc.TestServer(r.Context(), in)
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"latencyMs": ms})
}

// ---- engines ----

func (s *Server) enginesList(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"engines": s.svc.Engines()})
}

func (s *Server) engineReleases(w http.ResponseWriter, r *http.Request) {
	rs, err := s.svc.EngineReleases(r.Context(), r.PathValue("name"))
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"releases": rs})
}

func (s *Server) engineDownload(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Version string `json:"version"` // empty = latest stable
		Async   bool   `json:"async"`   // return a job to poll instead of waiting
	}
	if err := decode(r, &b, true); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if b.Async {
		jb, err := s.svc.StartEngineDownload(r.PathValue("name"), b.Version)
		if err != nil {
			failErr(w, err, http.StatusInternalServerError)
			return
		}
		ok(w, map[string]any{"job": jb})
		return
	}
	v, err := s.svc.DownloadEngine(r.Context(), r.PathValue("name"), b.Version)
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"active": v})
}

func (s *Server) engineUse(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Version string `json:"version"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	v, err := s.svc.UseEngine(r.PathValue("name"), b.Version)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"active": v})
}

func (s *Server) engineCheck(w http.ResponseWriter, r *http.Request) {
	v, err := s.svc.CheckEngine(r.Context(), r.PathValue("name"))
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"engine": v})
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"jobs": s.svc.Jobs()})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	jb, found := s.svc.Job(r.PathValue("id"))
	if !found {
		fail(w, http.StatusNotFound, "no such job")
		return
	}
	ok(w, map[string]any{"job": jb})
}

func (s *Server) parseLink(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Link string `json:"link"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	p, name, err := s.svc.ParseLink(b.Link)
	if err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	ok(w, map[string]any{"profile": p, "name": name})
}

// nodeProfile returns a node in editable form: {name, profile} for a server,
// {name, chain} for a chain.
func (s *Server) nodeProfile(w http.ResponseWriter, r *http.Request) {
	v, err := s.svc.NodeForEdit(r.PathValue("id"))
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	out := map[string]any{"name": v.Name}
	if v.Profile != nil {
		out["profile"] = v.Profile
	}
	if v.Chain != nil {
		out["chain"] = v.Chain
	}
	ok(w, out)
}

func (s *Server) planChain(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Chain []string `json:"chain"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	pl, err := s.svc.PlanChain(b.Chain)
	if err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	ok(w, map[string]any{"plan": pl})
}
