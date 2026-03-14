package authbroker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestBearerStrategy(t *testing.T) {
	s := &BearerStrategy{}
	if s.Name() != "bearer" {
		t.Fatalf("expected name 'bearer', got %q", s.Name())
	}

	t.Run("success", func(t *testing.T) {
		session, err := s.Authenticate(context.Background(), AuthConfig{
			Credentials: map[string]string{"token": "my-secret-token"},
			TTL:         time.Hour,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session.Headers["Authorization"] != "Bearer my-secret-token" {
			t.Fatalf("unexpected header: %s", session.Headers["Authorization"])
		}
		if session.IsExpired() {
			t.Fatal("session should not be expired")
		}
	})

	t.Run("missing_token", func(t *testing.T) {
		_, err := s.Authenticate(context.Background(), AuthConfig{
			Credentials: map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for missing token")
		}
	})
}

func TestOAuth2CCStrategy(t *testing.T) {
	// Mock OAuth2 token endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "test-id" || r.FormValue("client_secret") != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "oauth-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	s := &OAuth2CCStrategy{HTTPClient: server.Client()}

	session, err := s.Authenticate(context.Background(), AuthConfig{
		Strategy: "oauth2_cc",
		Credentials: map[string]string{
			"client_id":     "test-id",
			"client_secret": "test-secret",
		},
		Endpoint: server.URL + "/token",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.Headers["Authorization"] != "Bearer oauth-token-123" {
		t.Fatalf("unexpected header: %s", session.Headers["Authorization"])
	}
}

func TestOAuth2CCStrategy_Failure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid credentials"))
	}))
	defer server.Close()

	s := &OAuth2CCStrategy{HTTPClient: server.Client()}
	_, err := s.Authenticate(context.Background(), AuthConfig{
		Credentials: map[string]string{
			"client_id":     "bad",
			"client_secret": "bad",
		},
		Endpoint: server.URL + "/token",
	})
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}
}

func TestFormLoginStrategy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.FormValue("username") == "admin" && r.FormValue("password") == "secret" {
			http.SetCookie(w, &http.Cookie{
				Name:  "session_id",
				Value: "abc123",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer server.Close()

	s := &FormLoginStrategy{HTTPClient: nil}
	session, err := s.Authenticate(context.Background(), AuthConfig{
		Strategy: "form_login",
		Credentials: map[string]string{
			"username": "admin",
			"password": "secret",
		},
		Endpoint: server.URL + "/login",
		TTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(session.Cookies) == 0 {
		t.Fatal("expected session cookies")
	}
}

func TestAPIKeyStrategy(t *testing.T) {
	s := &APIKeyStrategy{}

	t.Run("header", func(t *testing.T) {
		session, err := s.Authenticate(context.Background(), AuthConfig{
			Credentials: map[string]string{"api_key": "key-123"},
			ExtraParams: map[string]string{"location": "header", "name": "X-Custom-Key"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if session.Headers["X-Custom-Key"] != "key-123" {
			t.Fatalf("unexpected header: %v", session.Headers)
		}
	})

	t.Run("cookie", func(t *testing.T) {
		session, err := s.Authenticate(context.Background(), AuthConfig{
			Credentials: map[string]string{"api_key": "cookie-key"},
			ExtraParams: map[string]string{"location": "cookie", "name": "api_token"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(session.Cookies) != 1 || session.Cookies[0].Value != "cookie-key" {
			t.Fatalf("unexpected cookies: %v", session.Cookies)
		}
	})

	t.Run("missing_key", func(t *testing.T) {
		_, err := s.Authenticate(context.Background(), AuthConfig{
			Credentials: map[string]string{},
		})
		if err == nil {
			t.Fatal("expected error for missing API key")
		}
	})
}

func TestBroker_SessionLifecycle(t *testing.T) {
	broker := NewBroker(zerolog.Nop())

	// Create session
	session, err := broker.CreateSession(context.Background(), "scan-001", AuthConfig{
		Strategy:    "bearer",
		Credentials: map[string]string{"token": "test-token"},
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	if session.ScanJobID != "scan-001" {
		t.Fatalf("unexpected scan job ID: %s", session.ScanJobID)
	}

	// Get session
	got, err := broker.GetSession(session.ID)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if got.ID != session.ID {
		t.Fatal("session ID mismatch")
	}

	// Revoke session
	err = broker.RevokeSession(session.ID)
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}

	// Verify revoked
	_, err = broker.GetSession(session.ID)
	if err == nil {
		t.Fatal("expected error after revocation")
	}
}

func TestBroker_UnknownStrategy(t *testing.T) {
	broker := NewBroker(zerolog.Nop())

	_, err := broker.CreateSession(context.Background(), "scan-001", AuthConfig{
		Strategy: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown strategy")
	}
}

func TestBroker_RevokeScanSessions(t *testing.T) {
	broker := NewBroker(zerolog.Nop())

	cfg := AuthConfig{
		Strategy:    "bearer",
		Credentials: map[string]string{"token": "t"},
		TTL:         time.Hour,
	}

	broker.CreateSession(context.Background(), "scan-A", cfg)
	broker.CreateSession(context.Background(), "scan-A", cfg)
	broker.CreateSession(context.Background(), "scan-B", cfg)

	count := broker.RevokeScanSessions("scan-A")
	if count != 2 {
		t.Fatalf("expected 2 revoked, got %d", count)
	}
}

func TestSession_ApplyTo(t *testing.T) {
	session := &Session{
		Headers: map[string]string{"Authorization": "Bearer tok"},
		Cookies: []*http.Cookie{{Name: "sid", Value: "abc"}},
	}

	req, _ := http.NewRequest("GET", "https://example.com", nil)
	session.ApplyTo(req)

	if req.Header.Get("Authorization") != "Bearer tok" {
		t.Fatal("header not applied")
	}
	cookies := req.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sid" {
		t.Fatal("cookie not applied")
	}
}
