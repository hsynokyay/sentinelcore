package risk

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Isolated test fixtures. These UUIDs are deliberately outside the seed
// data's UUID space so tests never collide with seed findings/clusters.
// ensureTestProject creates them (idempotently) on first use.
const (
	testOrgID     = "11111111-1111-1111-1111-111111111111" // matches seed org
	testTeamID    = "22222222-2222-2222-2222-222222222201" // matches seed team
	testProjectID = "a0000000-0000-4000-8000-000000000001"
	testScanJobID = "a0000000-0000-4000-8000-000000000002"
	testUserID    = "33333333-3333-3333-3333-333333333301" // matches seed user
)

// testPool connects to the local sentinelcore DB if available. Tests that
// need a database call testPool(t) and t.Skip when unavailable. It also
// ensures the dedicated test project + scan_job exist.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("RISK_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://sentinelcore:dev-password@localhost:5432/sentinelcore"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("no test DB available: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("test DB ping failed: %v", err)
	}
	ensureTestProject(t, pool)
	return pool
}

// ensureTestProject creates the dedicated risk-test project and scan_job
// if they do not yet exist. Both are isolated from seed fixtures so
// correlator runs cannot pick up seed findings.
func ensureTestProject(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		INSERT INTO core.projects (id, org_id, team_id, name, display_name, asset_criticality, status)
		VALUES ($1, $2, $3, 'risk-correlator-test', 'Risk Correlator Test', 'medium', 'active')
		ON CONFLICT (id) DO NOTHING
	`, testProjectID, testOrgID, testTeamID)
	if err != nil {
		t.Fatalf("ensure test project: %v", err)
	}

	_, err = pool.Exec(ctx, `
		INSERT INTO scans.scan_jobs (id, project_id, scan_type, trigger_type, status, created_by)
		VALUES ($1, $2, 'sast', 'manual', 'completed', $3)
		ON CONFLICT (id) DO NOTHING
	`, testScanJobID, testProjectID, testUserID)
	if err != nil {
		t.Fatalf("ensure test scan job: %v", err)
	}
}

// cleanupProject wipes all risk.* rows and all findings for the dedicated
// test project so a test starts from a deterministic state.
func cleanupProject(t *testing.T, pool *pgxpool.Pool, projectID string) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `DELETE FROM risk.cluster_evidence WHERE cluster_id IN (SELECT id FROM risk.clusters WHERE project_id = $1)`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.cluster_findings WHERE cluster_id IN (SELECT id FROM risk.clusters WHERE project_id = $1)`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.cluster_relations WHERE project_id = $1`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.clusters WHERE project_id = $1`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.correlation_runs WHERE project_id = $1`, projectID)
	// Test project is isolated from seed data — wipe all its findings.
	_, _ = pool.Exec(ctx, `DELETE FROM findings.findings WHERE project_id = $1`, projectID)
}

// insertTestFinding writes a synthetic finding directly into findings.findings
// so the correlator can pick it up. Returns the finding id.
func insertTestFinding(t *testing.T, pool *pgxpool.Pool, projectID string, f map[string]any) string {
	t.Helper()
	ctx := context.Background()

	title := "RISK_TEST: " + asString(f["title"])

	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO findings.findings (
			project_id, scan_job_id, finding_type, fingerprint,
			title, description, severity, confidence, status,
			cwe_id, owasp_category, rule_id, file_path, line_start,
			function_name, url, http_method, parameter
		)
		VALUES ($1, $2, $3, gen_random_uuid()::text,
		        $4, 'risk test finding', $5, 'medium', 'new',
		        $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING id
	`,
		projectID, testScanJobID, f["finding_type"], title, f["severity"],
		f["cwe_id"], f["owasp_category"], f["rule_id"],
		nilIfEmpty(f["file_path"]), nilIfZero(f["line_start"]),
		nilIfEmpty(f["function_name"]),
		nilIfEmpty(f["url"]), nilIfEmpty(f["http_method"]), nilIfEmpty(f["parameter"]),
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

func asString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func nilIfEmpty(v any) any {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok && s == "" {
		return nil
	}
	return v
}

func nilIfZero(v any) any {
	if v == nil {
		return nil
	}
	if n, ok := v.(int); ok && n == 0 {
		return nil
	}
	return v
}
