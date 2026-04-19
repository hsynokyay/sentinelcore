package csrf

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func testMiddleware() func(http.Handler) http.Handler {
	cfg := Config{
		AllowedOrigins: []string{"http://localhost:3000", "https://app.sentinel.io"},
		SecureCookie:   func(r *http.Request) bool { return false },
	}
	return Middleware(cfg, zerolog.Nop())
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestCSRF_CookieAuth_ValidToken_ValidOrigin(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	token := "abc123def456"
	req := httptest.NewRequest("POST", "/api/v1/findings/1/status", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	req.Header.Set(HeaderName, token)
	req.Header.Set("Origin", "http://localhost:3000")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestCSRF_CookieAuth_MissingToken(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	req := httptest.NewRequest("POST", "/api/v1/findings/1/status", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	// No CSRF cookie or header
	req.Header.Set("Origin", "http://localhost:3000")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestCSRF_CookieAuth_WrongToken(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	req := httptest.NewRequest("POST", "/api/v1/findings/1/assign", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "correct-token"})
	req.Header.Set(HeaderName, "wrong-token")
	req.Header.Set("Origin", "http://localhost:3000")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for mismatched token, got %d", rec.Code)
	}
}

func TestCSRF_CookieAuth_InvalidOrigin(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	token := "valid-token"
	req := httptest.NewRequest("POST", "/api/v1/governance/emergency-stop", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	req.Header.Set(HeaderName, token)
	req.Header.Set("Origin", "https://evil.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid origin, got %d", rec.Code)
	}
}

func TestCSRF_CookieAuth_ValidReferer_NoOrigin(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	token := "valid-token"
	req := httptest.NewRequest("PATCH", "/api/v1/findings/1/status", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	req.Header.Set(HeaderName, token)
	// No Origin, but valid Referer
	req.Header.Set("Referer", "http://localhost:3000/findings")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 with valid Referer fallback, got %d", rec.Code)
	}
}

func TestCSRF_CookieAuth_NoOriginNoReferer(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	token := "valid-token"
	req := httptest.NewRequest("DELETE", "/api/v1/webhooks/1", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})
	req.Header.Set(HeaderName, token)
	// No Origin, no Referer

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 when no Origin and no Referer, got %d", rec.Code)
	}
}

func TestCSRF_BearerAuth_NoCookie_SkipsCSRF(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	req := httptest.NewRequest("POST", "/api/v1/projects/1/scans", nil)
	req.Header.Set("Authorization", "Bearer some-jwt-token")
	// No cookies at all

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for Bearer-only auth (CSRF skipped), got %d", rec.Code)
	}
}

func TestCSRF_GET_SkipsValidation(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	req.AddCookie(&http.Cookie{Name: "sentinel_access_token", Value: "jwt-token"})
	// No CSRF token at all — GET should pass

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for GET (exempt from CSRF), got %d", rec.Code)
	}
}

func TestCSRF_LoginExempt(t *testing.T) {
	mw := testMiddleware()
	handler := mw(okHandler())

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	// No cookies, no CSRF — login should pass

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for login (exempt), got %d", rec.Code)
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if len(token) != TokenLength*2 { // hex encoding doubles length
		t.Errorf("expected token length %d, got %d", TokenLength*2, len(token))
	}

	// Two tokens should be different
	token2, _ := GenerateToken()
	if token == token2 {
		t.Error("tokens should be unique")
	}
}
