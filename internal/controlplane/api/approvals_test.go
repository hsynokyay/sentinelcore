package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// withAuthCtx attaches a UserContext to the request just like the auth middleware would,
// so handler tests can exercise post-auth code paths without spinning up the full middleware.
func withAuthCtx(r *http.Request, user *auth.UserContext) *http.Request {
	ctx := context.WithValue(context.Background(), auth.UserContextKey, user)
	return r.WithContext(ctx)
}

// TestCreateApprovalRequestHandler_Unauthenticated returns 401 when no user is in context.
func TestCreateApprovalRequestHandler_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/approvals", strings.NewReader(`{}`))
	h.CreateApprovalRequestHandler(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestCreateApprovalRequestHandler_Forbidden returns 403 for read-only roles.
func TestCreateApprovalRequestHandler_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/approvals", strings.NewReader(`{}`))
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "org-1", Role: "auditor"})
	h.CreateApprovalRequestHandler(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auditor, got %d", rec.Code)
	}
}

// TestCreateApprovalRequestHandler_BadInput rejects bodies missing required fields.
func TestCreateApprovalRequestHandler_BadInput(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCode int
	}{
		{"missing_request_type", `{"resource_type":"finding","resource_id":"abc","reason":"r"}`, 400},
		{"missing_reason", `{"request_type":"risk_closure","resource_type":"finding","resource_id":"abc"}`, 400},
		{"non_uuid_resource_id", `{"request_type":"risk_closure","resource_type":"finding","resource_id":"abc","reason":"r"}`, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handlers{}
			rec := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/v1/governance/approvals", strings.NewReader(tc.body))
			r = withAuthCtx(r, &auth.UserContext{UserID: "00000000-0000-0000-0000-000000000001", OrgID: "00000000-0000-0000-0000-000000000002", Role: "security_admin"})
			h.CreateApprovalRequestHandler(rec, r)
			if rec.Code != tc.wantCode {
				t.Errorf("expected %d, got %d (body=%s)", tc.wantCode, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestSubmitApprovalDecision_Forbidden returns 403 for roles missing decide permission.
func TestSubmitApprovalDecision_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/approvals/abc/decisions",
		strings.NewReader(`{"decision":"approve","reason":"ok"}`))
	r.SetPathValue("id", "abc")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "o-1", Role: "appsec_analyst"})
	h.SubmitApprovalDecision(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

// TestSubmitApprovalDecision_BadDecision rejects decisions other than approve/reject.
func TestSubmitApprovalDecision_BadDecision(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/approvals/abc/decisions",
		strings.NewReader(`{"decision":"maybe","reason":"ok"}`))
	r.SetPathValue("id", "abc")
	r = withAuthCtx(r, &auth.UserContext{UserID: "00000000-0000-0000-0000-000000000001", OrgID: "00000000-0000-0000-0000-000000000002", Role: "security_admin"})
	h.SubmitApprovalDecision(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestSubmitApprovalDecision_MissingReason returns 400 when no reason is supplied.
func TestSubmitApprovalDecision_MissingReason(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/approvals/abc/decisions",
		strings.NewReader(`{"decision":"approve"}`))
	r.SetPathValue("id", "abc")
	r = withAuthCtx(r, &auth.UserContext{UserID: "00000000-0000-0000-0000-000000000001", OrgID: "00000000-0000-0000-0000-000000000002", Role: "security_admin"})
	h.SubmitApprovalDecision(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}
