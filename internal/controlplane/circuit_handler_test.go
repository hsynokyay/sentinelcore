package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// fakeCircuit is a minimal CircuitStore for handler tests.
type fakeCircuit struct {
	resetCalls int
	resetErr   error
}

func (f *fakeCircuit) IsOpen(_ context.Context, _ uuid.UUID) (bool, error) {
	return false, nil
}
func (f *fakeCircuit) RecordFailure(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}
func (f *fakeCircuit) Reset(_ context.Context, _ uuid.UUID) error {
	f.resetCalls++
	return f.resetErr
}

func TestCircuitResetHandler_Success(t *testing.T) {
	c := &fakeCircuit{}
	h := CircuitResetHandler(c)
	bid := "00000000-0000-0000-0000-000000000001"
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/"+bid+"/circuit/reset", nil)
	req.SetPathValue("id", bid)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if c.resetCalls != 1 {
		t.Fatalf("reset not called, got=%d", c.resetCalls)
	}
}

func TestCircuitResetHandler_BadUUID(t *testing.T) {
	c := &fakeCircuit{}
	h := CircuitResetHandler(c)
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/not-a-uuid/circuit/reset", nil)
	req.SetPathValue("id", "not-a-uuid")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if c.resetCalls != 0 {
		t.Fatalf("reset must not be called on bad uuid, got=%d", c.resetCalls)
	}
}

func TestCircuitResetHandler_StoreError(t *testing.T) {
	c := &fakeCircuit{resetErr: errors.New("db down")}
	h := CircuitResetHandler(c)
	bid := "00000000-0000-0000-0000-000000000001"
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/"+bid+"/circuit/reset", nil)
	req.SetPathValue("id", bid)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCircuitResetHandler_NilStore(t *testing.T) {
	h := CircuitResetHandler(nil)
	bid := "00000000-0000-0000-0000-000000000001"
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/"+bid+"/circuit/reset", nil)
	req.SetPathValue("id", bid)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestCircuitResetHandler_PathFallback(t *testing.T) {
	// Some test harnesses don't set PathValue. The handler must still derive
	// the id by stripping the trailing "/circuit/reset" suffix.
	c := &fakeCircuit{}
	h := CircuitResetHandler(c)
	bid := "00000000-0000-0000-0000-000000000002"
	req := httptest.NewRequest("POST", "/api/v1/dast/bundles/"+bid+"/circuit/reset", nil)
	// Intentionally do NOT call SetPathValue.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if c.resetCalls != 1 {
		t.Fatalf("reset not called via path fallback, got=%d", c.resetCalls)
	}
}
