package cors

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddleware_AllowedOrigin(t *testing.T) {
	cfg := Config{AllowedOrigins: []string{"http://localhost:3000"}}
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Errorf("expected origin reflected, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Allow-Credentials: true")
	}
}

func TestMiddleware_DisallowedOrigin(t *testing.T) {
	cfg := Config{AllowedOrigins: []string{"http://localhost:3000"}}
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("expected no CORS header for disallowed origin, got %q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestMiddleware_Preflight(t *testing.T) {
	cfg := Config{AllowedOrigins: []string{"http://localhost:3000"}}
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("preflight should not reach the inner handler")
	}))

	req := httptest.NewRequest("OPTIONS", "/api/v1/findings", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204 for preflight, got %d", rec.Code)
	}
}

func TestMiddleware_NoOrigin(t *testing.T) {
	cfg := Config{AllowedOrigins: []string{"http://localhost:3000"}}
	handler := Middleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	// No Origin header (same-origin request or non-browser client)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("expected no CORS headers when no Origin header sent")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
