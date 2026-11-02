package api

import (
	"net/http"

	"keyway/internal/service"
)

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"groups": s.svc.Groups()})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	var in service.GroupInput
	if err := decode(r, &in, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	g, err := s.svc.CreateGroup(in)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"group": g})
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	var in service.GroupInput
	if err := decode(r, &in, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	g, err := s.svc.UpdateGroup(r.PathValue("id"), in)
	if err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, map[string]any{"group": g})
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteGroup(r.PathValue("id")); err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, nil)
}

func (s *Server) selectGroupMember(w http.ResponseWriter, r *http.Request) {
	var b struct {
		NodeID string `json:"nodeId"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if err := s.svc.SelectGroupMember(r.PathValue("id"), b.NodeID); err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, nil)
}

func (s *Server) testGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode      string `json:"mode"`
		Reconnect bool   `json:"reconnect"`
	}
	if err := decode(r, &b, true); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	res, err := s.svc.EvaluateGroup(r.Context(), r.PathValue("id"), b.Mode, b.Reconnect)
	if err != nil {
		out := map[string]any{"ok": false, "error": err.Error()}
		if res.Latency != nil {
			out["latency"] = res.Latency
		}
		writeJSON(w, statusFor(err, http.StatusInternalServerError), out)
		return
	}
	ok(w, map[string]any{
		"id": res.ID, "name": res.Name, "latencyMs": res.LatencyMs, "latency": res.Latency,
		"mode": res.Mode, "changed": res.Changed, "reconnected": res.Reconnected,
	})
}

func (s *Server) setActiveGroup(w http.ResponseWriter, r *http.Request) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decode(r, &b, false); err != nil {
		failErr(w, err, http.StatusBadRequest)
		return
	}
	if err := s.svc.SetActiveGroup(b.ID); err != nil {
		failErr(w, err, http.StatusInternalServerError)
		return
	}
	ok(w, nil)
}
