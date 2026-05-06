package replay

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool mirrors internal/dast/bundles/store_test.go: skip cleanly when
// TEST_DATABASE_URL is unset so unit-test runs in a no-DB environment do not
// fail.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping circuit integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	return pool
}

// mustInsertBundle inserts a minimal dast_auth_bundles row so the
// dast_replay_failures FK is satisfied. Pattern copied from the bundles and
// credentials integration tests.
func mustInsertBundle(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO dast_auth_bundles (
			id, customer_id, project_id, target_host,
			type, status,
			iv, ciphertext_ref, wrapped_dek, kms_key_id, kms_key_version,
			integrity_hmac, schema_version,
			created_by_user_id, expires_at
		) VALUES (
			$1, $2, $3, 'circuit-test.example.com',
			'session_import', 'pending_review',
			'\x00'::bytea, 'inline:', '\x00'::bytea, 'alias/test', 'v1',
			'\x00'::bytea, 1,
			$4, $5
		)`,
		id, uuid.New(), uuid.New(), uuid.New(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("mustInsertBundle: %v", err)
	}
	t.Cleanup(func() {
		// CASCADE on dast_replay_failures cleans up children.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM dast_auth_bundles WHERE id=$1`, id)
	})
}

func TestCircuit_OpensAfter3Failures(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := NewCircuitStore(pool)
	ctx := context.Background()
	id := uuid.New()
	mustInsertBundle(t, pool, id)

	for i := 0; i < 2; i++ {
		if err := s.RecordFailure(ctx, id, "boom", ""); err != nil {
			t.Fatal(err)
		}
		open, err := s.IsOpen(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if open {
			t.Fatalf("opened too early after %d failures", i+1)
		}
	}
	if err := s.RecordFailure(ctx, id, "boom", ""); err != nil {
		t.Fatal(err)
	}
	open, err := s.IsOpen(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !open {
		t.Fatal("expected open after 3rd failure")
	}
}

func TestCircuit_ResetClosesIt(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := NewCircuitStore(pool)
	ctx := context.Background()
	id := uuid.New()
	mustInsertBundle(t, pool, id)

	for i := 0; i < 3; i++ {
		if err := s.RecordFailure(ctx, id, "boom", ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Reset(ctx, id); err != nil {
		t.Fatal(err)
	}
	open, err := s.IsOpen(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("expected closed after reset")
	}
}

func TestCircuit_IsOpenWithoutRowIsClosed(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := NewCircuitStore(pool)
	ctx := context.Background()
	id := uuid.New()
	mustInsertBundle(t, pool, id)

	open, err := s.IsOpen(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if open {
		t.Fatal("expected closed when no failures recorded")
	}
}
