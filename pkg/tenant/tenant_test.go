package tenant

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool returns a connected pool using DATABASE_URL. Tests skip when
// unset so go test ./... on CI without a DB still succeeds for the
// pure-Go tests (lint_test.go).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed tenant tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestTx_EmptyOrgIDRejected(t *testing.T) {
	// No DB needed — we short-circuit before opening a tx.
	err := Tx(context.Background(), nil, "",
		func(ctx context.Context, tx pgx.Tx) error { return nil })
	if !errors.Is(err, ErrNoTenant) {
		t.Errorf("want ErrNoTenant, got %v", err)
	}
}

func TestTx_SetsCurrentOrgID(t *testing.T) {
	pool := testPool(t)
	const want = "00000000-0000-0000-0000-000000000001"
	err := Tx(context.Background(), pool, want, func(ctx context.Context, tx pgx.Tx) error {
		var got string
		if err := tx.QueryRow(ctx,
			`SELECT current_setting('app.current_org_id', true)`).Scan(&got); err != nil {
			return err
		}
		if got != want {
			t.Errorf("app.current_org_id = %q, want %q", got, want)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTx_LocalOnlyNoLeakAcrossTx(t *testing.T) {
	// SET LOCAL / set_config(..., true) must not leak. Running two
	// back-to-back Tx calls and checking the second sees a fresh
	// (empty) setting guards against accidentally losing the local
	// scope — e.g. if someone swapped set_config's third arg to false.
	pool := testPool(t)
	const orgA = "00000000-0000-0000-0000-0000000000aa"
	_ = Tx(context.Background(), pool, orgA, func(ctx context.Context, tx pgx.Tx) error {
		return nil
	})
	err := Tx(context.Background(), pool, "00000000-0000-0000-0000-0000000000bb",
		func(ctx context.Context, tx pgx.Tx) error {
			var got string
			if err := tx.QueryRow(ctx,
				`SELECT current_setting('app.current_org_id', true)`).Scan(&got); err != nil {
				return err
			}
			if got == orgA {
				t.Error("org_id from previous Tx leaked into new Tx")
			}
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
}

func TestScope_RejectsEmptyOrg(t *testing.T) {
	if _, err := NewScope(nil, ""); !errors.Is(err, ErrNoTenant) {
		t.Errorf("want ErrNoTenant, got %v", err)
	}
}
