package apikeys

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// testOrgID returns a reproducible test org UUID (upserts the row).
func testOrgID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	const id = "00000000-0000-0000-0000-000000000001"
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO core.organizations (id, name, display_name) VALUES ($1, 'apikeys-test-org', 'APIKeys Test Org') ON CONFLICT (id) DO NOTHING`, id); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	return id
}

// testUserID returns a reproducible test user UUID (upserts the row).
func testUserID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	const id = "00000000-0000-0000-0000-000000000099"
	orgID := testOrgID(t, pool)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO core.users (id, org_id, username, email, display_name, role, password_hash)
         VALUES ($1, $2, 'apikeys-test-user', 'apikeys-test@example.com', 'APIKeys Test User', 'admin', '$2b$12$dummy')
         ON CONFLICT (id) DO UPDATE SET role = 'admin'`, id, orgID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}
