package slaworker_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/governance/slaworker"
)

// testPool returns a pgxpool connected to TEST_DATABASE_URL or skips the test.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping SLA worker integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// TestNew_NilPool ensures the constructor refuses to operate without a pool.
// This guarantees the package builds even when the DB is unavailable.
func TestNew_NilPool(t *testing.T) {
	w := slaworker.New(nil, nil)
	if err := w.RunOnce(context.Background()); err == nil {
		t.Fatal("expected error from RunOnce with nil pool")
	}
}

// TestRunOnce_EmptyPool exercises the worker against a real DB with no
// findings. Should be a no-op and return nil.
func TestRunOnce_EmptyPool(t *testing.T) {
	pool := testPool(t)
	w := slaworker.New(pool, nil)
	if err := w.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce on empty DB: %v", err)
	}
	res := w.LastResult()
	if res.Violations != 0 || res.Warnings != 0 {
		t.Errorf("expected 0 violations/warnings on empty DB, got %+v", res)
	}
}
