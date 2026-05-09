package authbroker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

type recordedFakeStore struct {
	bundle *bundles.Bundle
	err    error
}

func (s *recordedFakeStore) Save(_ context.Context, _ *bundles.Bundle, _ string) (string, error) { return "", nil }
func (s *recordedFakeStore) Load(_ context.Context, _, _ string) (*bundles.Bundle, error) {
	return s.bundle, s.err
}
func (s *recordedFakeStore) UpdateStatus(_ context.Context, _, _ string) error { return nil }
func (s *recordedFakeStore) Revoke(_ context.Context, _, _ string) error { return nil }
func (s *recordedFakeStore) SoftDelete(_ context.Context, _ string) error { return nil }
func (s *recordedFakeStore) IncUseCount(_ context.Context, _ string) error { return nil }
func (s *recordedFakeStore) AddACL(_ context.Context, _, _ string, _ *string) error { return nil }
func (s *recordedFakeStore) CheckACL(_ context.Context, _, _ string, _ *string) (bool, error) { return true, nil }
func (s *recordedFakeStore) Approve(_ context.Context, _, _ string, _ int) error { return nil }
func (s *recordedFakeStore) Reject(_ context.Context, _, _, _ string) error { return nil }
func (s *recordedFakeStore) ListPending(_ context.Context, _ string, _, _ int) ([]*bundles.BundleSummary, error) {
	return nil, nil
}

func TestRecordedLogin_HappyPath(t *testing.T) {
	store := &recordedFakeStore{
		bundle: &bundles.Bundle{
			ID: "b1", Type: "recorded_login",
			ExpiresAt: time.Now().Add(24 * time.Hour),
			CapturedSession: bundles.SessionCapture{
				Cookies: []bundles.Cookie{{Name: "sid", Value: "v"}},
				Headers: map[string]string{},
			},
		},
	}
	s := &RecordedLoginStrategy{Bundles: store}
	sess, err := s.Authenticate(context.Background(), AuthConfig{
		BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if len(sess.Cookies) != 1 || sess.Cookies[0].Name != "sid" {
		t.Errorf("unexpected cookies: %+v", sess.Cookies)
	}
}

func TestRecordedLogin_WrongType(t *testing.T) {
	store := &recordedFakeStore{
		bundle: &bundles.Bundle{
			ID: "b1", Type: "session_import",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		},
	}
	s := &RecordedLoginStrategy{Bundles: store}
	_, err := s.Authenticate(context.Background(), AuthConfig{
		BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
	})
	if err == nil {
		t.Fatal("expected wrong-type rejection")
	}
}

func TestRecordedLogin_Expired(t *testing.T) {
	store := &recordedFakeStore{
		bundle: &bundles.Bundle{
			ID: "b1", Type: "recorded_login",
			ExpiresAt: time.Now().Add(-time.Hour),
		},
	}
	s := &RecordedLoginStrategy{Bundles: store}
	_, err := s.Authenticate(context.Background(), AuthConfig{
		BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
	})
	if err == nil {
		t.Fatal("expected expired rejection")
	}
}

func TestRecordedLogin_LoadError(t *testing.T) {
	store := &recordedFakeStore{err: errors.New("db error")}
	s := &RecordedLoginStrategy{Bundles: store}
	_, err := s.Authenticate(context.Background(), AuthConfig{
		BundleID: "b1", CustomerID: "c1", ProjectID: "p1",
	})
	if err == nil {
		t.Fatal("expected load error")
	}
}

func TestRecordedLogin_Refresh_OneShotErrors(t *testing.T) {
	store := &recordedFakeStore{
		bundle: &bundles.Bundle{
			ID: "b1", Type: "recorded_login",
			ExpiresAt:          time.Now().Add(time.Hour),
			AutomatableRefresh: false,
		},
	}
	s := &RecordedLoginStrategy{Bundles: store}
	_, err := s.Refresh(context.Background(), nil, AuthConfig{BundleID: "b1", CustomerID: "c1"})
	if err == nil {
		t.Fatal("expected error: one-shot bundles cannot refresh")
	}
}

func TestRecordedLogin_Refresh_NoReplayer(t *testing.T) {
	store := &recordedFakeStore{
		bundle: &bundles.Bundle{
			ID: "b1", Type: "recorded_login",
			ExpiresAt:          time.Now().Add(time.Hour),
			AutomatableRefresh: true,
		},
	}
	s := &RecordedLoginStrategy{Bundles: store}
	_, err := s.Refresh(context.Background(), nil, AuthConfig{BundleID: "b1", CustomerID: "c1"})
	if err == nil {
		t.Fatal("expected error: replayer not configured")
	}
}
