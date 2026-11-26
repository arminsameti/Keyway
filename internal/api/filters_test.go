package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func post(t *testing.T, h http.Handler, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "127.0.0.1:1234"
	req.Header.Set(TokenHeader, "tok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestRoutingTestShape(t *testing.T) {
	h := updateHandler(t)
	code, out := post(t, h, "/api/routing/test", `{"host":"example.com","port":443,"rules":[{"id":"r","enabled":true,"entries":["example.com"],"outbound":"direct"}]}`)
	if code != 200 {
		t.Fatalf("status %d: %v", code, out)
	}
	m, _ := out["match"].(map[string]any)
	if m["outbound"] != "direct" || m["ruleId"] != "r" || m["entry"] != "example.com" {
		t.Fatalf("old match shape broken: %v", out)
	}
	if _, has := out["allowedBy"]; !has {
		t.Fatalf("new fields missing: %v", out)
	}
}

func TestFiltersPreviewRejectsNonHTTPS(t *testing.T) {
	h := updateHandler(t)
	code, out := post(t, h, "/api/filters/preview", `{"url":"http://example.com/list.txt"}`)
	if code != 400 || out["error"] == nil {
		t.Fatalf("status %d: %v", code, out)
	}
}

func TestFiltersView(t *testing.T) {
	h := updateHandler(t)
	req := httptest.NewRequest("GET", "/api/filters", nil)
	req.Host = "127.0.0.1:1234"
	req.Header.Set(TokenHeader, "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"lists":[]`) {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
}
