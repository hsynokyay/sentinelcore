package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type countingChecker struct {
	allowed map[string]map[string]struct{}
}

func (c countingChecker) Can(role, perm string) bool {
	p, ok := c.allowed[role]
	if !ok {
		return false
	}
	_, ok = p[perm]
	return ok
}

func TestRequirePermission_AllowsWhenPrincipalHasPermission(t *testing.T) {
	checker := countingChecker{allowed: map[string]map[string]struct{}{
		"admin": {"scans.run": {}},
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	mw := RequirePermission("scans.run", checker, nil)(next)

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "admin", UserID: "u1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if !called {
		t.Fatal("next handler was not called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
}

func TestRequirePermission_DeniesWhenPrincipalLacksPermission(t *testing.T) {
	checker := countingChecker{allowed: map[string]map[string]struct{}{
		"developer": {"risks.read": {}},
	}}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})
	mw := RequirePermission("users.manage", checker, nil)(next)

	req := httptest.NewRequest("DELETE", "/api/v1/users/x", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "developer", UserID: "u1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if called {
		t.Fatal("next handler must not be called on deny")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"code":"FORBIDDEN"`) {
		t.Fatalf("body missing FORBIDDEN code: %s", rec.Body.String())
	}
}

func TestRequirePermission_DeniesWhenNoPrincipal(t *testing.T) {
	checker := countingChecker{}
	mw := RequirePermission("scans.run", checker, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next must not be called")
	}))
	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}

func TestRequirePermission_APIKeyWithScope(t *testing.T) {
	mw := RequirePermission("findings.read", countingChecker{}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest("GET", "/api/v1/findings", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "api_key", Scopes: []string{"findings.read", "scans.read"},
		KeyID: "k1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200 (key has scope)", rec.Code)
	}
}

func TestRequirePermission_APIKeyMissingScope(t *testing.T) {
	mw := RequirePermission("scans.run", countingChecker{}, nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next must not be called")
		}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "api_key", Scopes: []string{"findings.read"},
		KeyID: "k1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "INSUFFICIENT_SCOPE") {
		t.Fatalf("body missing INSUFFICIENT_SCOPE: %s", rec.Body.String())
	}
}
