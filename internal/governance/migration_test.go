package governance_test

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool returns a pgxpool connected to TEST_DATABASE_URL or skips the test.
// Migration 024 must already be applied by the test harness (`make migrate-up`).
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping migration integration test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

// TestMigration024Applied verifies that migration 024 has added the
// expected schema extensions: project sensitivity, approval-request
// two-person columns, approval_decisions table.
func TestMigration024Applied(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// projects.sensitivity exists (column may be present even if no rows).
	var sensitivityCol int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema='core' AND table_name='projects'
		  AND column_name='sensitivity'
	`).Scan(&sensitivityCol); err != nil {
		t.Fatalf("query sensitivity column: %v", err)
	}
	if sensitivityCol != 1 {
		t.Errorf("expected core.projects.sensitivity column, got count=%d", sensitivityCol)
	}

	var colCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema='governance' AND table_name='approval_requests'
		  AND column_name IN ('required_approvals','current_approvals','target_transition','project_id')
	`).Scan(&colCount); err != nil {
		t.Fatalf("query approval_requests columns: %v", err)
	}
	if colCount != 4 {
		t.Errorf("expected 4 approval_requests new columns, got %d", colCount)
	}

	var decTbl int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema='governance' AND table_name='approval_decisions'
	`).Scan(&decTbl); err != nil {
		t.Fatalf("query approval_decisions table: %v", err)
	}
	if decTbl != 1 {
		t.Errorf("expected governance.approval_decisions table, got count=%d", decTbl)
	}

	// org_settings new columns exist.
	var osCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema='governance' AND table_name='org_settings'
		  AND column_name IN ('require_closure_approval','require_two_person_closure','approval_expiry_days','sla_warning_window_days')
	`).Scan(&osCount); err != nil {
		t.Fatalf("query org_settings columns: %v", err)
	}
	if osCount != 4 {
		t.Errorf("expected 4 org_settings new columns, got %d", osCount)
	}

	// Companion tables exist.
	for _, tbl := range []string{"project_sla_policies", "control_catalogs", "control_items", "control_mappings", "export_jobs"} {
		var n int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.tables
			WHERE table_schema='governance' AND table_name=$1
		`, tbl).Scan(&n); err != nil {
			t.Fatalf("query %s table: %v", tbl, err)
		}
		if n != 1 {
			t.Errorf("expected governance.%s table, got count=%d", tbl, n)
		}
	}
}
