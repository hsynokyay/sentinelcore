package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_PopulatesPrincipalForUserJWT(t *testing.T) {
	// Generate keys + manager.
	privPEM, pubPEM := generateTestKeys(t)
	mgr, err := NewJWTManager(privPEM, pubPEM)
	if err != nil {
		t.Fatalf("NewJWTManager: %v", err)
	}

	// Issue a token carrying a new-vocabulary role.
	token, _, err := mgr.IssueAccessToken("user-1", "org-1", "admin")
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Build the middleware without a session store (nil is allowed
	// per existing middleware.go).
	mw := AuthMiddleware(mgr, nil)

	// Handler captures the Principal from context.
	var got Principal
	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/risks", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if !ok {
		t.Fatal("Principal not set in context")
	}
	if got.Kind != "user" {
		t.Fatalf("Kind=%q want user", got.Kind)
	}
	if got.UserID != "user-1" || got.OrgID != "org-1" || got.Role != "admin" {
		t.Fatalf("principal mismatch: %+v", got)
	}
	if got.JTI == "" {
		t.Fatal("JTI should be populated")
	}
}

// Regression test: legacy UserContext is still populated so existing
// handlers that read GetUser(ctx) keep working.
func TestAuthMiddleware_StillPopulatesUserContext(t *testing.T) {
	privPEM, pubPEM := generateTestKeys(t)
	mgr, _ := NewJWTManager(privPEM, pubPEM)
	token, _, _ := mgr.IssueAccessToken("user-2", "org-2", "auditor")

	var uc *UserContext
	mw := AuthMiddleware(mgr, nil)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uc = GetUser(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if uc == nil {
		t.Fatal("UserContext should still be populated for backward compat")
	}
	if uc.UserID != "user-2" || uc.Role != "auditor" {
		t.Fatalf("user ctx mismatch: %+v", uc)
	}

	// Verify the imports satisfy.
	_ = context.Background()
}
