package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// spyDenier records every EmitAuthzDenied call so the test can assert.
type spyDenier struct {
	calls []spyDenierCall
}
type spyDenierCall struct {
	Principal Principal
	Required  string
}

func (s *spyDenier) EmitAuthzDenied(_ context.Context, p Principal, required string) {
	s.calls = append(s.calls, spyDenierCall{Principal: p, Required: required})
}

func TestRequirePermission_EmitsDenierOnDeny(t *testing.T) {
	spy := &spyDenier{}
	checker := countingChecker{} // empty — everything denies
	mw := RequirePermission("scans.run", checker, spy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler must not run on deny")
	}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "developer", UserID: "u1", OrgID: "o1",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if len(spy.calls) != 1 {
		t.Fatalf("denier called %d times, want 1", len(spy.calls))
	}
	if spy.calls[0].Required != "scans.run" {
		t.Fatalf("required=%q want scans.run", spy.calls[0].Required)
	}
	if spy.calls[0].Principal.UserID != "u1" {
		t.Fatalf("principal.UserID=%q want u1", spy.calls[0].Principal.UserID)
	}
}

func TestRequirePermission_DoesNotEmitDenierOnAllow(t *testing.T) {
	spy := &spyDenier{}
	checker := countingChecker{allowed: map[string]map[string]struct{}{
		"admin": {"scans.run": {}},
	}}
	mw := RequirePermission("scans.run", checker, spy)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "user", Role: "admin",
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rec.Code)
	}
	if len(spy.calls) != 0 {
		t.Fatalf("denier should not be called on allow; got %d calls", len(spy.calls))
	}
}

func TestRequirePermission_EmitsDenierForAPIKeyMissingScope(t *testing.T) {
	spy := &spyDenier{}
	mw := RequirePermission("scans.run", countingChecker{}, spy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("must not run")
	}))

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	req = req.WithContext(WithPrincipal(req.Context(), Principal{
		Kind: "api_key", KeyID: "k1", OrgID: "o1",
		Scopes: []string{"findings.read"}, // lacks scans.run
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if len(spy.calls) != 1 {
		t.Fatalf("denier called %d times, want 1", len(spy.calls))
	}
	if spy.calls[0].Principal.Kind != "api_key" {
		t.Fatalf("kind=%q want api_key", spy.calls[0].Principal.Kind)
	}
	if spy.calls[0].Principal.KeyID != "k1" {
		t.Fatalf("key_id=%q want k1", spy.calls[0].Principal.KeyID)
	}
}
