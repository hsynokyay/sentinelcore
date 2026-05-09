package api

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/apikeys"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

func TestRotateAPIKey_NotFound(t *testing.T) {
	pool, cleanup := testPoolForAPIKeys(t)
	defer cleanup()
	cache := testRBACCache(t, pool)

	h := &Handlers{pool: pool, rbacCache: cache}

	req := httptest.NewRequest("POST", "/api/v1/api-keys/00000000-0000-0000-0000-00000000dead/rotate", nil)
	req.SetPathValue("id", "00000000-0000-0000-0000-00000000dead")
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: testUserID(t, pool), OrgID: testOrgID(t, pool), Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.RotateAPIKey(rec, req)

	if rec.Code != 404 {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "NOT_FOUND") {
		t.Errorf("body missing NOT_FOUND: %s", rec.Body.String())
	}
}

func TestRotateAPIKey_HappyPath(t *testing.T) {
	pool, cleanup := testPoolForAPIKeys(t)
	defer cleanup()
	cache := testRBACCache(t, pool)
	ctx := context.Background()

	orgID := testOrgID(t, pool)
	userID := testUserID(t, pool)

	// Create a key directly via apikeys.Create.
	created, err := apikeys.Create(ctx, pool, apikeys.CreateInput{
		OrgID: orgID, CreatedBy: userID, UserID: userID,
		Name: "rotate-http-test", Scopes: []string{"risks.read"},
		CreatorPermissions: map[string]struct{}{"risks.read": {}},
		KnownPermissions:   map[string]struct{}{"risks.read": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM core.api_keys WHERE id = $1`, created.ID)
	}()

	oldPlaintext := created.PlainText
	oldPrefix := created.Prefix

	h := &Handlers{pool: pool, rbacCache: cache}
	req := httptest.NewRequest("POST", "/api/v1/api-keys/"+created.ID+"/rotate", nil)
	req.SetPathValue("id", created.ID)
	req = req.WithContext(auth.WithPrincipal(req.Context(), auth.Principal{
		Kind: "user", UserID: userID, OrgID: orgID, Role: "admin",
	}))
	rec := httptest.NewRecorder()
	h.RotateAPIKey(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	// Response must include the new plaintext.
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	newPlaintext, _ := resp["plaintext"].(string)
	if newPlaintext == "" {
		t.Fatal("response missing plaintext")
	}
	if newPlaintext == oldPlaintext {
		t.Fatal("plaintext should change")
	}
	newPrefix, _ := resp["prefix"].(string)
	if newPrefix == oldPrefix {
		t.Fatal("prefix should change")
	}

	// Confirm the old plaintext no longer resolves.
	oldRK, err := apikeys.Resolve(ctx, pool, oldPlaintext)
	if err != nil {
		t.Errorf("Resolve(old) unexpected error: %v", err)
	}
	if oldRK != nil {
		t.Error("old plaintext should no longer resolve after rotate")
	}
	// Confirm the new plaintext resolves.
	newRK, err := apikeys.Resolve(ctx, pool, newPlaintext)
	if err != nil {
		t.Errorf("new plaintext should resolve after rotate: %v", err)
	}
	if newRK == nil {
		t.Error("new plaintext resolved to nil after rotate")
	}
}
