package api

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/policy"
)

func testPoolForAPIKeys(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	return pool, pool.Close
}

func testRBACCache(t *testing.T, pool *pgxpool.Pool) *policy.Cache {
	t.Helper()
	c := policy.NewCache()
	if err := c.Reload(context.Background(), pool); err != nil {
		t.Fatalf("cache reload: %v", err)
	}
	return c
}

// testOrgID / testUserID: look up or create a fixture org + user.
// Pattern: upsert a known UUID so tests are reproducible across runs.
func testOrgID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	const id = "00000000-0000-0000-0000-000000000001"
	_, err := pool.Exec(context.Background(),
		`INSERT INTO core.organizations (id, name, display_name) VALUES ($1, 'apikeys-test-org', 'APIKeys Test Org') ON CONFLICT (id) DO NOTHING`, id)
	if err != nil {
		t.Fatalf("insert org: %v", err)
	}
	return id
}

func testUserID(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	const id = "00000000-0000-0000-0000-000000000099"
	orgID := testOrgID(t, pool)
	_, err := pool.Exec(context.Background(),
		`INSERT INTO core.users (id, org_id, username, email, display_name, role, password_hash)
         VALUES ($1, $2, 'apikeys-test-user', 'apikeys-test@example.com', 'APIKeys Test User', 'admin', '$2b$12$dummy')
         ON CONFLICT (id) DO UPDATE SET role = 'admin'`, id, orgID)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}
