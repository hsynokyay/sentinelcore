package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

func TestCreateAPIKey_RejectsUnknownScope(t *testing.T) {
	pool, cleanup := testPoolForAPIKeys(t)
	defer cleanup()

	cache := testRBACCache(t, pool)

	h := &Handlers{pool: pool, rbacCache: cache, audit: nil}

	body, _ := json.Marshal(map[string]any{
		"name":   "test-key",
		"scopes": []string{"nonsense.permission"},
	})
	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: testUserID(t, pool), OrgID: testOrgID(t, pool), Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.CreateAPIKey(rec, req)

	if rec.Code != 400 {
		t.Fatalf("status=%d body=%s, want 400 UNKNOWN_SCOPE", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "UNKNOWN_SCOPE") {
		t.Errorf("body missing UNKNOWN_SCOPE: %s", rec.Body.String())
	}
}

func TestCreateAPIKey_HappyPath_PlaintextInResponse(t *testing.T) {
	pool, cleanup := testPoolForAPIKeys(t)
	defer cleanup()
	cache := testRBACCache(t, pool)

	h := &Handlers{pool: pool, rbacCache: cache, audit: nil}

	body, _ := json.Marshal(map[string]any{
		"name":   "happy-key",
		"scopes": []string{"risks.read", "scans.read"},
	})
	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: testUserID(t, pool), OrgID: testOrgID(t, pool), Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.CreateAPIKey(rec, req)

	if rec.Code != 201 {
		t.Fatalf("status=%d body=%s, want 201", rec.Code, rec.Body.String())
	}
	// JSON-contract assertion: "plaintext" (one word, lowercase).
	if !strings.Contains(rec.Body.String(), `"plaintext":`) {
		t.Errorf("response missing \"plaintext\" json tag; body=%s", rec.Body.String())
	}
}

func TestCreateAPIKey_ServiceAccountRequiresOwnerAdmin(t *testing.T) {
	pool, cleanup := testPoolForAPIKeys(t)
	defer cleanup()
	cache := testRBACCache(t, pool)
	h := &Handlers{pool: pool, rbacCache: cache}

	body, _ := json.Marshal(map[string]any{
		"name":               "svc-key",
		"scopes":             []string{"scans.read"},
		"is_service_account": true,
	})
	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader(body))
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: testUserID(t, pool), OrgID: testOrgID(t, pool), Role: "security_engineer",
	}))
	rec := httptest.NewRecorder()
	h.CreateAPIKey(rec, req)

	if rec.Code != 403 {
		t.Fatalf("status=%d body=%s, want 403", rec.Code, rec.Body.String())
	}
}

var _ = context.Background
