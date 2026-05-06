package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

// fakeReRecordStore is a minimal ReRecordStore stub. The handler tests
// drive Load/Save/MarkSupersededBy through the real bundles.ReRecord
// orchestration so we exercise the full call path.
type fakeReRecordStore struct {
	loadBundle *bundles.Bundle
	loadErr    error
	saveID     string
	saveErr    error
	markErr    error
	saveCalls  int
	markCalls  int
}

func (f *fakeReRecordStore) Load(_ context.Context, _, _ string) (*bundles.Bundle, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	// Deep-ish copy so the handler can mutate.
	cp := *f.loadBundle
	return &cp, nil
}

func (f *fakeReRecordStore) Save(_ context.Context, _ *bundles.Bundle, _ string) (string, error) {
	f.saveCalls++
	if f.saveErr != nil {
		return "", f.saveErr
	}
	return f.saveID, nil
}

func (f *fakeReRecordStore) MarkSupersededBy(_ context.Context, _, _, _ string) error {
	f.markCalls++
	return f.markErr
}

func TestReRecordHandler_Success(t *testing.T) {
	store := &fakeReRecordStore{
		loadBundle: &bundles.Bundle{
			ID:             "11111111-1111-1111-1111-111111111111",
			ProjectID:      "22222222-2222-2222-2222-222222222222",
			TargetHost:     "app.bank.tld",
			PrincipalClaim: "sub",
			Type:           "session_import",
			TTLSeconds:     3600,
			Status:         "approved",
		},
		saveID: "33333333-3333-3333-3333-333333333333",
	}
	h := ReRecordHandler(store)

	body, _ := json.Marshal(map[string]string{"reason": "creds rotated"})
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/11111111-1111-1111-1111-111111111111/re-record",
		bytes.NewReader(body))
	req.SetPathValue("id", "11111111-1111-1111-1111-111111111111")
	req = req.WithContext(ctxWithUser("operator-1", "org-1"))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp reRecordResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.NewBundleID != store.saveID {
		t.Errorf("new_bundle_id = %q, want %q", resp.NewBundleID, store.saveID)
	}
	if resp.Status != "pending_review" {
		t.Errorf("status = %q, want pending_review", resp.Status)
	}
	if store.saveCalls != 1 {
		t.Errorf("Save called %d times, want 1", store.saveCalls)
	}
	if store.markCalls != 1 {
		t.Errorf("MarkSupersededBy called %d times, want 1", store.markCalls)
	}
}

func TestReRecordHandler_BadUUID(t *testing.T) {
	store := &fakeReRecordStore{}
	h := ReRecordHandler(store)
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/not-a-uuid/re-record", strings.NewReader(`{}`))
	req.SetPathValue("id", "not-a-uuid")
	req = req.WithContext(ctxWithUser("operator-1", "org-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if store.saveCalls != 0 || store.markCalls != 0 {
		t.Errorf("store mutated on bad uuid: save=%d mark=%d", store.saveCalls, store.markCalls)
	}
}

func TestReRecordHandler_NotFound(t *testing.T) {
	store := &fakeReRecordStore{loadErr: bundles.ErrBundleNotFound}
	h := ReRecordHandler(store)
	bid := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/"+bid+"/re-record", strings.NewReader(`{}`))
	req.SetPathValue("id", bid)
	req = req.WithContext(ctxWithUser("operator-1", "org-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReRecordHandler_AlreadySuperseded(t *testing.T) {
	store := &fakeReRecordStore{
		loadBundle: &bundles.Bundle{
			ID:         "11111111-1111-1111-1111-111111111111",
			TargetHost: "app.bank.tld",
			Type:       "session_import",
			TTLSeconds: 3600,
			Status:     "superseded",
		},
	}
	h := ReRecordHandler(store)
	bid := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/"+bid+"/re-record", strings.NewReader(`{}`))
	req.SetPathValue("id", bid)
	req = req.WithContext(ctxWithUser("operator-1", "org-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if store.saveCalls != 0 {
		t.Errorf("Save must not run on already-superseded source: calls=%d", store.saveCalls)
	}
}

func TestReRecordHandler_StoreError(t *testing.T) {
	store := &fakeReRecordStore{
		loadBundle: &bundles.Bundle{
			ID:         "11111111-1111-1111-1111-111111111111",
			TargetHost: "app.bank.tld",
			Type:       "session_import",
			TTLSeconds: 3600,
			Status:     "approved",
		},
		saveErr: errors.New("db down"),
	}
	h := ReRecordHandler(store)
	bid := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/"+bid+"/re-record", strings.NewReader(`{}`))
	req.SetPathValue("id", bid)
	req = req.WithContext(ctxWithUser("operator-1", "org-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReRecordHandler_NoAuth(t *testing.T) {
	store := &fakeReRecordStore{}
	h := ReRecordHandler(store)
	bid := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/"+bid+"/re-record", strings.NewReader(`{}`))
	req.SetPathValue("id", bid)
	// No user context.
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestReRecordHandler_NilStore(t *testing.T) {
	h := ReRecordHandler(nil)
	bid := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest("POST",
		"/api/v1/dast/bundles/"+bid+"/re-record", strings.NewReader(`{}`))
	req.SetPathValue("id", bid)
	req = req.WithContext(ctxWithUser("operator-1", "org-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
