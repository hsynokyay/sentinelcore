package authz

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sentinelcore/sentinelcore/pkg/auth"
)

// stubRoleStore implements RoleStore for testing.
type stubRoleStore struct {
	// grantedRoles maps userID -> set of roles the user has.
	grantedRoles map[string]map[Role]bool
	// err, if non-nil, is returned from every call.
	err error
}

func (s *stubRoleStore) HasRole(_ context.Context, userID string, role Role) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	if s.grantedRoles == nil {
		return false, nil
	}
	return s.grantedRoles[userID][role], nil
}

func (s *stubRoleStore) Grant(_ context.Context, _, _ string, _ Role) error { return nil }
func (s *stubRoleStore) Revoke(_ context.Context, _ string, _ Role) error   { return nil }
func (s *stubRoleStore) ListUserRoles(_ context.Context, _ string) ([]Role, error) {
	return nil, nil
}
func (s *stubRoleStore) ListUsersWithRole(_ context.Context, _ Role) ([]string, error) {
	return nil, nil
}

// withUser injects a UserContext into the request context using the exported key.
func withUser(r *http.Request, userID string) *http.Request {
	uc := &auth.UserContext{UserID: userID}
	ctx := context.WithValue(r.Context(), auth.UserContextKey, uc)
	return r.WithContext(ctx)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestRequireDASTRole_GrantedAllows verifies that a user with the required role
// gets a 200 response.
func TestRequireDASTRole_GrantedAllows(t *testing.T) {
	store := &stubRoleStore{
		grantedRoles: map[string]map[Role]bool{
			"user-abc": {RoleRecorder: true},
		},
	}
	mw := RequireDASTRole(store, RoleRecorder)
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUser(req, "user-abc")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

// TestRequireDASTRole_MissingForbidden verifies that a user without the required
// role gets a 403 response.
func TestRequireDASTRole_MissingForbidden(t *testing.T) {
	store := &stubRoleStore{
		grantedRoles: map[string]map[Role]bool{},
	}
	mw := RequireDASTRole(store, RoleRecorder)
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUser(req, "user-xyz")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

// TestRequireDASTRole_NoUserUnauthorized verifies that a request without an
// authenticated user context gets a 401 response.
func TestRequireDASTRole_NoUserUnauthorized(t *testing.T) {
	store := &stubRoleStore{}
	mw := RequireDASTRole(store, RoleRecorder)
	handler := mw(okHandler())

	// No user injected into context.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

// TestRequireDASTRole_StoreError verifies that a store error returns 500.
func TestRequireDASTRole_StoreError(t *testing.T) {
	store := &stubRoleStore{err: errors.New("db down")}
	mw := RequireDASTRole(store, RoleRecorder)
	handler := mw(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = withUser(req, "user-abc")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
}
