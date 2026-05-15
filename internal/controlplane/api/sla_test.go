package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// TestSLADashboard_Unauthenticated returns 401 when no user is in context.
func TestSLADashboard_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/sla/dashboard", nil)
	h.SLADashboard(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestSLADashboard_Forbidden returns 403 for roles missing governance.sla.read.
func TestSLADashboard_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/sla/dashboard", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "guest"})
	h.SLADashboard(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for analyst, got %d", rec.Code)
	}
}

// TestSLADashboard_BadOrgID surfaces a 400 when the session carries a bogus org id.
func TestSLADashboard_BadOrgID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/sla/dashboard", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "not-a-uuid", Role: "security_admin"})
	h.SLADashboard(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad org id, got %d", rec.Code)
	}
}

// TestListSLAViolations_Forbidden checks RBAC on the violations endpoint.
func TestListSLAViolations_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/sla/violations", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "guest"})
	h.ListSLAViolationsHandler(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for analyst, got %d", rec.Code)
	}
}

// TestGetProjectSLAPolicy_Forbidden checks RBAC on the policy GET endpoint.
func TestGetProjectSLAPolicy_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/sla/policies/abc", nil)
	r.SetPathValue("project_id", "abc")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "guest"})
	h.GetProjectSLAPolicyHandler(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for analyst, got %d", rec.Code)
	}
}

// TestGetProjectSLAPolicy_BadProjectID requires a valid UUID path param.
func TestGetProjectSLAPolicy_BadProjectID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/sla/policies/abc", nil)
	r.SetPathValue("project_id", "not-a-uuid")
	r = withAuthCtx(r, &auth.UserContext{UserID: "00000000-0000-0000-0000-000000000001", OrgID: "00000000-0000-0000-0000-000000000002", Role: "security_admin"})
	h.GetProjectSLAPolicyHandler(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad project id, got %d", rec.Code)
	}
}

// TestPutProjectSLAPolicy_ForbiddenForReadOnly auditor cannot write SLA policies.
func TestPutProjectSLAPolicy_ForbiddenForReadOnly(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/governance/sla/policies/abc",
		strings.NewReader(`{"sla_days":{"critical":1,"high":3,"medium":14,"low":60}}`))
	r.SetPathValue("project_id", "00000000-0000-0000-0000-000000000003")
	r = withAuthCtx(r, &auth.UserContext{UserID: "00000000-0000-0000-0000-000000000001", OrgID: "00000000-0000-0000-0000-000000000002", Role: "auditor"})
	h.PutProjectSLAPolicyHandler(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auditor, got %d", rec.Code)
	}
}

// TestPutProjectSLAPolicy_BadBody rejects nil sla_days map.
func TestPutProjectSLAPolicy_BadBody(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/v1/governance/sla/policies/abc",
		strings.NewReader(`{}`))
	r.SetPathValue("project_id", "00000000-0000-0000-0000-000000000003")
	r = withAuthCtx(r, &auth.UserContext{UserID: "00000000-0000-0000-0000-000000000001", OrgID: "00000000-0000-0000-0000-000000000002", Role: "security_admin"})
	h.PutProjectSLAPolicyHandler(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty body, got %d", rec.Code)
	}
}

// TestDeleteProjectSLAPolicy_ForbiddenForReadOnly enforces RBAC on delete.
func TestDeleteProjectSLAPolicy_ForbiddenForReadOnly(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/governance/sla/policies/abc", nil)
	r.SetPathValue("project_id", "00000000-0000-0000-0000-000000000003")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000002", Role: "auditor"})
	h.DeleteProjectSLAPolicyHandler(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auditor, got %d", rec.Code)
	}
}
