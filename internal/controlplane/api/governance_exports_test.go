package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// TestCreateExport_Unauthenticated 401 when there is no user in context.
func TestCreateExport_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/exports",
		strings.NewReader(`{"kind":"risk_evidence_pack","scope":{"risk_ids":["00000000-0000-0000-0000-000000000001"]},"format":"zip_json"}`))
	h.CreateExport(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestCreateExport_Forbidden — appsec_analyst lacks write permission.
func TestCreateExport_Forbidden(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/exports",
		strings.NewReader(`{"kind":"risk_evidence_pack","scope":{"risk_ids":["00000000-0000-0000-0000-000000000001"]},"format":"zip_json"}`))
	r = withAuthCtx(r, &auth.UserContext{
		UserID: "00000000-0000-0000-0000-000000000010",
		OrgID:  "00000000-0000-0000-0000-000000000001",
		Role:   "appsec_analyst",
	})
	h.CreateExport(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for appsec_analyst, got %d", rec.Code)
	}
}

// TestCreateExport_BadKind rejects unknown kind values.
func TestCreateExport_BadKind(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/exports",
		strings.NewReader(`{"kind":"bogus","scope":{},"format":"zip_json"}`))
	r = withAuthCtx(r, &auth.UserContext{
		UserID: "00000000-0000-0000-0000-000000000010",
		OrgID:  "00000000-0000-0000-0000-000000000001",
		Role:   "security_admin",
	})
	h.CreateExport(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad kind, got %d", rec.Code)
	}
}

// TestCreateExport_BadFormat rejects unknown format values.
func TestCreateExport_BadFormat(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/exports",
		strings.NewReader(`{"kind":"risk_evidence_pack","scope":{},"format":"pdf"}`))
	r = withAuthCtx(r, &auth.UserContext{
		UserID: "00000000-0000-0000-0000-000000000010",
		OrgID:  "00000000-0000-0000-0000-000000000001",
		Role:   "security_admin",
	})
	h.CreateExport(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad format, got %d", rec.Code)
	}
}

// TestCreateExport_BadJSON rejects malformed payloads.
func TestCreateExport_BadJSON(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/governance/exports",
		strings.NewReader(`{not-json}`))
	r = withAuthCtx(r, &auth.UserContext{
		UserID: "00000000-0000-0000-0000-000000000010",
		OrgID:  "00000000-0000-0000-0000-000000000001",
		Role:   "security_admin",
	})
	h.CreateExport(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad json, got %d", rec.Code)
	}
}

// TestListExports_Unauthenticated 401 with no user.
func TestListExports_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/exports", nil)
	h.ListExports(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestGetExport_Unauthenticated 401 without auth.
func TestGetExport_Unauthenticated(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/exports/abc", nil)
	r.SetPathValue("id", "abc")
	h.GetExport(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

// TestGetExport_BadID validates the path UUID.
func TestGetExport_BadID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/exports/abc", nil)
	r.SetPathValue("id", "not-a-uuid")
	r = withAuthCtx(r, &auth.UserContext{
		UserID: "00000000-0000-0000-0000-000000000010",
		OrgID:  "00000000-0000-0000-0000-000000000001",
		Role:   "security_admin",
	})
	h.GetExport(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad id, got %d", rec.Code)
	}
}

// TestDownloadExport_BadID validates the path UUID.
func TestDownloadExport_BadID(t *testing.T) {
	h := &Handlers{}
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/v1/governance/exports/abc/download", nil)
	r.SetPathValue("id", "not-a-uuid")
	r = withAuthCtx(r, &auth.UserContext{
		UserID: "00000000-0000-0000-0000-000000000010",
		OrgID:  "00000000-0000-0000-0000-000000000001",
		Role:   "security_admin",
	})
	h.DownloadExport(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}
