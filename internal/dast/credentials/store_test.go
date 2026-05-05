package credentials

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

// testPool mirrors internal/dast/bundles/store_test.go: skip cleanly when
// TEST_DATABASE_URL is unset so unit-test runs in a no-DB environment do
// not fail.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping credentials store integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	return pool
}

// seedBundle inserts a minimal dast_auth_bundles row so credential rows can
// satisfy the bundle_id FK. Returns the new bundle UUID.
func seedBundle(t *testing.T, pool *pgxpool.Pool, customerID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := pool.Exec(context.Background(), `
		INSERT INTO dast_auth_bundles (
			id, customer_id, project_id, target_host,
			type, status,
			iv, ciphertext_ref, wrapped_dek, kms_key_id, kms_key_version,
			integrity_hmac, schema_version,
			created_by_user_id, expires_at
		) VALUES (
			$1, $2, $3, 'creds-test.example.com',
			'session_import', 'pending_review',
			'\x00'::bytea, 'inline:', '\x00'::bytea, 'alias/test', 'v1',
			'\x00'::bytea, 1,
			$4, $5
		)`,
		id, customerID, uuid.New(), uuid.New(), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("seedBundle: %v", err)
	}
	t.Cleanup(func() {
		// ON DELETE CASCADE on dast_credential_secrets cleans up children.
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM dast_auth_bundles WHERE id=$1`, id)
	})
	return id
}

func newTestStore(t *testing.T, pool *pgxpool.Pool) *PostgresStore {
	t.Helper()
	master := []byte("test-master-key-32-bytes-of-entropy!")
	return NewPostgresStore(pool, kms.NewLocalProvider(master))
}

func TestPostgresStore_SaveLoadDeleteList(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := newTestStore(t, pool)

	cust := uuid.New()
	bun := seedBundle(t, pool, cust)
	ctx := context.Background()

	type op struct {
		name string
		run  func(t *testing.T)
	}

	plain := []byte("hunter2")

	ops := []op{
		{
			name: "Save_then_Load_roundtrips",
			run: func(t *testing.T) {
				if err := s.Save(ctx, cust, bun, "login_pwd", plain); err != nil {
					t.Fatalf("Save: %v", err)
				}
				got, err := s.Load(ctx, bun, "login_pwd")
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				if !bytes.Equal(got, plain) {
					t.Fatalf("plaintext mismatch: got %q, want %q", got, plain)
				}
			},
		},
		{
			name: "Save_existing_key_overwrites",
			run: func(t *testing.T) {
				newPlain := []byte("rotated-secret")
				if err := s.Save(ctx, cust, bun, "login_pwd", newPlain); err != nil {
					t.Fatalf("Save (rotate): %v", err)
				}
				got, err := s.Load(ctx, bun, "login_pwd")
				if err != nil {
					t.Fatalf("Load after rotate: %v", err)
				}
				if !bytes.Equal(got, newPlain) {
					t.Fatalf("rotated mismatch: got %q, want %q", got, newPlain)
				}
			},
		},
		{
			name: "ListKeys_returns_sorted_keys",
			run: func(t *testing.T) {
				if err := s.Save(ctx, cust, bun, "totp", []byte("123456")); err != nil {
					t.Fatalf("Save totp: %v", err)
				}
				if err := s.Save(ctx, cust, bun, "api_key", []byte("k")); err != nil {
					t.Fatalf("Save api_key: %v", err)
				}
				keys, err := s.ListKeys(ctx, bun)
				if err != nil {
					t.Fatalf("ListKeys: %v", err)
				}
				want := []string{"api_key", "login_pwd", "totp"}
				if len(keys) != len(want) {
					t.Fatalf("ListKeys: got %v, want %v", keys, want)
				}
				for i, k := range keys {
					if k != want[i] {
						t.Fatalf("ListKeys[%d]: got %q, want %q", i, k, want[i])
					}
				}
			},
		},
		{
			name: "Delete_then_Load_returns_NotFound",
			run: func(t *testing.T) {
				if err := s.Delete(ctx, bun, "login_pwd"); err != nil {
					t.Fatalf("Delete: %v", err)
				}
				_, err := s.Load(ctx, bun, "login_pwd")
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("expected ErrNotFound after delete; got %v", err)
				}
			},
		},
		{
			name: "Delete_missing_key_is_noop",
			run: func(t *testing.T) {
				if err := s.Delete(ctx, bun, "does-not-exist"); err != nil {
					t.Fatalf("Delete missing: %v", err)
				}
			},
		},
	}

	// Run sub-tests sequentially since they share state through the bundle row.
	for _, o := range ops {
		t.Run(o.name, o.run)
	}
}

// TestPostgresStore_AADBindsCredentialToBundle verifies that GCM AAD ties a
// credential ciphertext to its (bundle_id, vault_key) tuple. After mutating
// bundle_id in-DB, Load under the new bundle_id must fail authentication.
func TestPostgresStore_AADBindsCredentialToBundle(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	s := newTestStore(t, pool)

	cust := uuid.New()
	b1 := seedBundle(t, pool, cust)
	b2 := seedBundle(t, pool, cust)
	ctx := context.Background()

	if err := s.Save(ctx, cust, b1, "k", []byte("secret")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Tamper: move the row's bundle_id to b2 (vault_key unchanged). The
	// stored AAD was bound to b1|k; reading via b2|k must fail GCM auth.
	if _, err := pool.Exec(ctx,
		`UPDATE dast_credential_secrets
		    SET bundle_id = $1
		  WHERE bundle_id = $2 AND vault_key = 'k'`, b2, b1); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	if _, err := s.Load(ctx, b2, "k"); err == nil {
		t.Fatal("expected AAD mismatch error after row tamper, got nil")
	}
}
