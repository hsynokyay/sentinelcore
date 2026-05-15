package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// TestListComplianceCatalogs_Unauthenticated returns 401 with no user.
func TestListComplianceCatalogs_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/catalogs", nil)
	h.ListComplianceCatalogs(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestListComplianceCatalogs_BadOrgID rejects a session with a malformed org id.
func TestListComplianceCatalogs_BadOrgID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/catalogs", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "not-a-uuid", Role: "security_admin"})
	h.ListComplianceCatalogs(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestListComplianceCatalogs_GuestForbidden — unknown role with no perms.
func TestListComplianceCatalogs_GuestForbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/catalogs", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "guest"})
	h.ListComplianceCatalogs(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for guest, got %d", rec.Code)
	}
}

// TestListComplianceCatalogItems_BadCatalogID requires a UUID path param.
func TestListComplianceCatalogItems_BadCatalogID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/catalogs/abc/items", nil)
	r.SetPathValue("catalog_id", "not-a-uuid")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.ListComplianceCatalogItems(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad catalog id, got %d", rec.Code)
	}
}

// TestListComplianceMappings_AnalystAllowed analysts can read mappings.
func TestListComplianceMappings_AnalystAllowed(t *testing.T) {
	// We cannot run the real query without a DB, but the RBAC gate must
	// pass for an analyst. Use a malformed org id so the next guard
	// returns 400 rather than reaching pool.Query (which is nil).
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/mappings", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "not-a-uuid", Role: "appsec_analyst"})
	h.ListComplianceMappings(rec, r)
	if rec.Code == http.StatusForbidden {
		t.Errorf("analyst should pass RBAC gate, got 403")
	}
}

// TestResolveComplianceControls_MissingCWE rejects empty cwe param.
func TestResolveComplianceControls_MissingCWE(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/resolve", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.ResolveComplianceControls(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing cwe, got %d", rec.Code)
	}
}

// TestResolveComplianceControls_BadCWE rejects non-integer cwe values.
func TestResolveComplianceControls_BadCWE(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/resolve?cwe=abc", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.ResolveComplianceControls(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-integer cwe, got %d", rec.Code)
	}
}

// TestResolveComplianceControls_AuditorAllowed auditors have read perms.
func TestResolveComplianceControls_AuditorAllowed(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/compliance/resolve?cwe=79", nil)
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "not-a-uuid", Role: "auditor"})
	h.ResolveComplianceControls(rec, r)
	if rec.Code == http.StatusForbidden {
		t.Errorf("auditor should pass RBAC gate, got 403")
	}
}

// TestCreateComplianceCatalog_Forbidden auditor cannot create catalogs.
func TestCreateComplianceCatalog_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/compliance/catalogs",
		strings.NewReader(`{"code":"X","name":"Y","version":"1"}`))
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "auditor"})
	h.CreateComplianceCatalog(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auditor, got %d", rec.Code)
	}
}

// TestCreateComplianceCatalog_BadBody rejects malformed JSON.
func TestCreateComplianceCatalog_BadBody(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/compliance/catalogs", strings.NewReader(`not-json`))
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.CreateComplianceCatalog(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad body, got %d", rec.Code)
	}
}

// TestCreateComplianceItem_BadCatalogID requires UUID path param.
func TestCreateComplianceItem_BadCatalogID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/compliance/catalogs/abc/items",
		strings.NewReader(`{"control_id":"X","title":"T"}`))
	r.SetPathValue("catalog_id", "not-a-uuid")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.CreateComplianceItem(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestCreateComplianceMapping_MissingTarget rejects body lacking target_control_id.
func TestCreateComplianceMapping_MissingTarget(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/compliance/mappings",
		strings.NewReader(`{"source_kind":"cwe","source_code":"CWE-79"}`))
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.CreateComplianceMapping(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing target_control_id, got %d", rec.Code)
	}
}

// TestCreateComplianceMapping_Forbidden auditors cannot write mappings.
func TestCreateComplianceMapping_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/compliance/mappings",
		strings.NewReader(`{"source_kind":"cwe","source_code":"CWE-79","target_control_id":"00000000-0000-0000-0000-000000000001"}`))
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "auditor"})
	h.CreateComplianceMapping(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auditor, got %d", rec.Code)
	}
}

// TestDeleteComplianceMapping_BadID rejects non-UUID path.
func TestDeleteComplianceMapping_BadID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/compliance/mappings/abc", nil)
	r.SetPathValue("id", "not-a-uuid")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "security_admin"})
	h.DeleteComplianceMapping(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// TestDeleteComplianceMapping_Forbidden auditors cannot delete.
func TestDeleteComplianceMapping_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/api/v1/compliance/mappings/abc", nil)
	r.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	r = withAuthCtx(r, &auth.UserContext{UserID: "u-1", OrgID: "00000000-0000-0000-0000-000000000001", Role: "auditor"})
	h.DeleteComplianceMapping(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for auditor, got %d", rec.Code)
	}
}
