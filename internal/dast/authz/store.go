package authz

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RoleStore is the interface for reading and writing DAST role grants.
type RoleStore interface {
	Grant(ctx context.Context, userID, grantedByUserID string, role Role) error
	Revoke(ctx context.Context, userID string, role Role) error
	HasRole(ctx context.Context, userID string, role Role) (bool, error)
	ListUserRoles(ctx context.Context, userID string) ([]Role, error)
	ListUsersWithRole(ctx context.Context, role Role) ([]string, error)
}

// PostgresRoleStore implements RoleStore using a pgxpool.Pool.
type PostgresRoleStore struct {
	db *pgxpool.Pool
}

// NewPostgresRoleStore creates a new PostgresRoleStore backed by the given pool.
func NewPostgresRoleStore(db *pgxpool.Pool) *PostgresRoleStore {
	return &PostgresRoleStore{db: db}
}

// isValidRole returns true if role is one of the defined DAST roles.
func isValidRole(role Role) bool {
	for _, r := range AllRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// Grant inserts or re-activates a role grant for userID.
func (s *PostgresRoleStore) Grant(ctx context.Context, userID, grantedByUserID string, role Role) error {
	if !isValidRole(role) {
		return fmt.Errorf("authz: Grant: unknown role %q", role)
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO dast_user_roles (user_id, role, granted_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role) DO UPDATE
		SET granted_by = EXCLUDED.granted_by,
		    granted_at = now(),
		    revoked_at = NULL
	`, userID, string(role), grantedByUserID)
	if err != nil {
		return fmt.Errorf("authz: Grant: %w", err)
	}
	return nil
}

// Revoke sets revoked_at=now() for an active role grant.
func (s *PostgresRoleStore) Revoke(ctx context.Context, userID string, role Role) error {
	if !isValidRole(role) {
		return fmt.Errorf("authz: Revoke: unknown role %q", role)
	}
	_, err := s.db.Exec(ctx, `
		UPDATE dast_user_roles
		SET revoked_at = now()
		WHERE user_id = $1
		  AND role = $2
		  AND revoked_at IS NULL
	`, userID, string(role))
	if err != nil {
		return fmt.Errorf("authz: Revoke: %w", err)
	}
	return nil
}

// HasRole returns true if userID currently has the given role (not revoked).
func (s *PostgresRoleStore) HasRole(ctx context.Context, userID string, role Role) (bool, error) {
	if !isValidRole(role) {
		return false, fmt.Errorf("authz: HasRole: unknown role %q", role)
	}
	var count int
	err := s.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM dast_user_roles
		WHERE user_id = $1
		  AND role = $2
		  AND revoked_at IS NULL
	`, userID, string(role)).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("authz: HasRole: %w", err)
	}
	return count > 0, nil
}

// ListUserRoles returns all active roles for the given user.
func (s *PostgresRoleStore) ListUserRoles(ctx context.Context, userID string) ([]Role, error) {
	rows, err := s.db.Query(ctx, `
		SELECT role
		FROM dast_user_roles
		WHERE user_id = $1
		  AND revoked_at IS NULL
		ORDER BY role
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("authz: ListUserRoles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, fmt.Errorf("authz: ListUserRoles: %w", err)
		}
		roles = append(roles, Role(r))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz: ListUserRoles: %w", err)
	}
	return roles, nil
}

// ListUsersWithRole returns all user IDs that currently hold the given role.
func (s *PostgresRoleStore) ListUsersWithRole(ctx context.Context, role Role) ([]string, error) {
	if !isValidRole(role) {
		return nil, fmt.Errorf("authz: ListUsersWithRole: unknown role %q", role)
	}
	rows, err := s.db.Query(ctx, `
		SELECT user_id
		FROM dast_user_roles
		WHERE role = $1
		  AND revoked_at IS NULL
		ORDER BY user_id
	`, string(role))
	if err != nil {
		return nil, fmt.Errorf("authz: ListUsersWithRole: %w", err)
	}
	defer rows.Close()

	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, fmt.Errorf("authz: ListUsersWithRole: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("authz: ListUsersWithRole: %w", err)
	}
	return users, nil
}
