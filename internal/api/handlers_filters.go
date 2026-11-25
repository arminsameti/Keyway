package api

import (
	"net/http"
)

func (s *Server) filtersView(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Filters())
}

func (s *Server) filtersCatalog(w http.ResponseWriter, r *http.Request) {
	cat, err := s.svc.FilterCatalog(r.Context(), r.URL.Query().Get("refresh") == "1")
	if err != nil {
		fail(w, http.StatusBadGateway, "could not load the filter catalog: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, cat)
}

// filtersRefresh refreshes one list, or every enabled list when no id is given.
func (s *Server) filtersRefresh(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decode(r, &b, true); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if err := s.svc.RefreshFilters(r.Context(), b.ID); err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"filters": s.svc.Filters()})
}

// filtersPreview downloads a custom list URL and reports what it holds; nothing is saved.
func (s *Server) filtersPreview(w http.ResponseWriter, r *http.Request) {
	var b struct {
		URL string `json:"url"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	p, err := s.svc.PreviewFilterURL(r.Context(), b.URL)
	if err != nil {
		failErr(w, err, http.StatusBadGateway)
		return
	}
	ok(w, map[string]any{"domains": p.Domains, "skipped": p.Skipped, "sample": p.Sample})
}
