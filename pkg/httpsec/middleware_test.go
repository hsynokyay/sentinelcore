package httpsec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestChain_SetsSecurityHeaders(t *testing.T) {
	h := Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		}),
		Defaults()...,
	)
	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	want := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}
	for k, v := range want {
		if got := rec.Result().Header.Get(k); got != v {
			t.Errorf("%s: got %q, want %q", k, got, v)
		}
	}
	if !strings.Contains(rec.Result().Header.Get("Permissions-Policy"), "camera=()") {
		t.Error("Permissions-Policy: missing camera=()")
	}
}

func TestChain_CapsRequestBody(t *testing.T) {
	var sawMaxBytesErr bool
	h := Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := io.ReadAll(r.Body)
			if IsBodyTooLarge(err) {
				sawMaxBytesErr = true
				w.WriteHeader(413)
				return
			}
			w.WriteHeader(200)
		}),
		WithMaxBodySize(10),
	)
	big := bytes.Repeat([]byte("x"), 100)
	req := httptest.NewRequest("POST", "/", bytes.NewReader(big))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Errorf("want 413, got %d", rec.Code)
	}
	if !sawMaxBytesErr {
		t.Error("handler didn't see MaxBytesError")
	}
}

func TestChain_UploadException(t *testing.T) {
	var sizeSeen int
	h := Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			sizeSeen = len(body)
			w.WriteHeader(200)
		}),
		WithMaxBodySize(10),
		WithUploadException(100, "/api/v1/upload/"),
	)
	big := bytes.Repeat([]byte("x"), 50)
	req := httptest.NewRequest("POST", "/api/v1/upload/foo", bytes.NewReader(big))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || sizeSeen != 50 {
		t.Errorf("upload path rejected: code=%d size=%d", rec.Code, sizeSeen)
	}
}

// --- step-up tests ---

type fakeReauthStore struct {
	last time.Time
	err  error
}

func (f *fakeReauthStore) LastReauth(_ context.Context, _ string) (time.Time, error) {
	return f.last, f.err
}

func TestRequireStepUp_Allows(t *testing.T) {
	cfg := StepUpConfig{
		Sessions: &fakeReauthStore{last: time.Now().Add(-1 * time.Minute)},
		GetJTI:   func(ctx context.Context) (string, bool) { return "jti", true },
		MaxAge:   5 * time.Minute,
	}
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(204)
	})
	h := RequireStepUp(cfg)(inner)
	req := httptest.NewRequest("DELETE", "/users/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 {
		t.Errorf("want 204, got %d", rec.Code)
	}
}

func TestRequireStepUp_RejectsStale(t *testing.T) {
	cfg := StepUpConfig{
		Sessions: &fakeReauthStore{last: time.Now().Add(-30 * time.Minute)},
		GetJTI:   func(ctx context.Context) (string, bool) { return "jti", true },
		MaxAge:   5 * time.Minute,
	}
	h := RequireStepUp(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run")
	}))
	req := httptest.NewRequest("DELETE", "/users/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("want 403, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "STEP_UP_REQUIRED") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestRequireStepUp_RejectsMissingJTI(t *testing.T) {
	cfg := StepUpConfig{
		Sessions: &fakeReauthStore{},
		GetJTI:   func(ctx context.Context) (string, bool) { return "", false },
	}
	h := RequireStepUp(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/admin/rotate", nil))
	if rec.Code != 401 {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

func TestRequireStepUp_FailsClosedOnStoreError(t *testing.T) {
	cfg := StepUpConfig{
		Sessions: &fakeReauthStore{err: errors.New("redis down")},
		GetJTI:   func(ctx context.Context) (string, bool) { return "jti", true },
	}
	h := RequireStepUp(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run when store is down")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("DELETE", "/x", nil))
	if rec.Code != 503 {
		t.Errorf("want 503, got %d", rec.Code)
	}
}
