package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

type fakeCache struct{ allowed map[string]map[string]struct{} }

func (f fakeCache) PermissionsFor(role string) []string {
	var out []string
	for p := range f.allowed[role] {
		out = append(out, p)
	}
	return out
}

func TestMe_UserReturnsRoleAndPermissions(t *testing.T) {
	cache := fakeCache{allowed: map[string]map[string]struct{}{
		"admin": {"risks.read": {}, "scans.run": {}},
	}}
	h := &MeHandler{Cache: cache}

	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: "u1", OrgID: "o1", Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	var resp struct {
		User        map[string]string `json:"user"`
		Permissions []string          `json:"permissions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User["role"] != "admin" {
		t.Fatalf("role=%q", resp.User["role"])
	}
	if len(resp.Permissions) != 2 {
		t.Fatalf("want 2 permissions, got %v", resp.Permissions)
	}
}

func TestMe_APIKeyReturnsScopesAsPermissions(t *testing.T) {
	h := &MeHandler{Cache: fakeCache{}}
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "api_key", KeyID: "k1", OrgID: "o1",
		Scopes: []string{"findings.read", "scans.read"},
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var resp struct {
		Permissions []string `json:"permissions"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.Permissions) != 2 {
		t.Fatalf("want 2, got %v", resp.Permissions)
	}
}

func TestMe_NoPrincipalReturns401(t *testing.T) {
	h := &MeHandler{Cache: fakeCache{}}
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("status=%d, want 401", rec.Code)
	}
}
