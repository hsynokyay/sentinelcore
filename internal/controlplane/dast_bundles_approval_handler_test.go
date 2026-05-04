package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

type approveStore struct {
	approved string
	rejected string
	pending  []*bundles.BundleSummary
	forceErr error
}

func (a *approveStore) Save(_ context.Context, _ *bundles.Bundle, _ string) (string, error) {
	return "", nil
}
func (a *approveStore) Load(_ context.Context, _, _ string) (*bundles.Bundle, error) {
	return nil, errors.New("ni")
}
func (a *approveStore) UpdateStatus(_ context.Context, _, _ string) error { return nil }
func (a *approveStore) Revoke(_ context.Context, _, _ string) error       { return nil }
func (a *approveStore) SoftDelete(_ context.Context, _ string) error      { return nil }
func (a *approveStore) IncUseCount(_ context.Context, _ string) error     { return nil }
func (a *approveStore) AddACL(_ context.Context, _, _ string, _ *string) error {
	return nil
}
func (a *approveStore) CheckACL(_ context.Context, _, _ string, _ *string) (bool, error) {
	return true, nil
}
func (a *approveStore) Approve(_ context.Context, id, _ string, _ int) error {
	if a.forceErr != nil {
		return a.forceErr
	}
	a.approved = id
	return nil
}
func (a *approveStore) Reject(_ context.Context, id, _, _ string) error {
	if a.forceErr != nil {
		return a.forceErr
	}
	a.rejected = id
	return nil
}
func (a *approveStore) ListPending(_ context.Context, _ string, _, _ int) ([]*bundles.BundleSummary, error) {
	return a.pending, nil
}

func ctxWithUser(uid, org string) context.Context {
	return context.WithValue(context.Background(), auth.UserContextKey, &auth.UserContext{UserID: uid, OrgID: org})
}

func TestApprove_HappyPath(t *testing.T) {
	store := &approveStore{}
	h := NewBundlesHandler(store)
	body, _ := json.Marshal(ApproveBundleRequest{TTLSeconds: 3600})
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/abc/approve", bytes.NewReader(body))
	req = req.WithContext(ctxWithUser("reviewer-1", "org-1"))
	rr := httptest.NewRecorder()
	h.Approve(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	if store.approved != "abc" {
		t.Errorf("expected bundle 'abc' approved, got %q", store.approved)
	}
}

func TestApprove_FourEyesViolation(t *testing.T) {
	store := &approveStore{forceErr: errors.New("4-eyes: recorder cannot approve own recording")}
	h := NewBundlesHandler(store)
	body, _ := json.Marshal(ApproveBundleRequest{TTLSeconds: 3600})
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/abc/approve", bytes.NewReader(body))
	req = req.WithContext(ctxWithUser("recorder-1", "org-1"))
	rr := httptest.NewRecorder()
	h.Approve(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestReject_HappyPath(t *testing.T) {
	store := &approveStore{}
	h := NewBundlesHandler(store)
	body, _ := json.Marshal(RejectBundleRequest{Reason: "stale credentials"})
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/xyz/reject", bytes.NewReader(body))
	req = req.WithContext(ctxWithUser("reviewer-1", "org-1"))
	rr := httptest.NewRecorder()
	h.Reject(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if store.rejected != "xyz" {
		t.Errorf("expected bundle 'xyz' rejected, got %q", store.rejected)
	}
}

func TestListPending_ReturnsBundles(t *testing.T) {
	store := &approveStore{
		pending: []*bundles.BundleSummary{{
			ID:              "b1",
			CustomerID:      "org-1",
			ProjectID:       "p1",
			TargetHost:      "app.bank.tld",
			Type:            "session_import",
			CreatedByUserID: "u1",
			CreatedAt:       time.Now(),
			ExpiresAt:       time.Now().Add(24 * time.Hour),
		}},
	}
	h := NewBundlesHandler(store)
	req := httptest.NewRequest("GET", "/api/v1/dast/bundles?limit=10", nil)
	req = req.WithContext(ctxWithUser("reviewer-1", "org-1"))
	rr := httptest.NewRecorder()
	h.ListPending(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp map[string][]PendingBundle
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp["bundles"]) != 1 || resp["bundles"][0].ID != "b1" {
		t.Errorf("unexpected bundles: %+v", resp["bundles"])
	}
}
