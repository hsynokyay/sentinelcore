package risk

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
)

// TestRebuild_SingleDASTFinding verifies the happy path: one DAST finding
// produces one cluster with the expected score and evidence.
func TestRebuild_SingleDASTFinding(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "dast",
		"title":          "SQL Injection via id",
		"severity":       "critical",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-DAST-SQLI-001",
		"url":            "https://stg.example.com/api/users/42",
		"http_method":    "GET",
		"parameter":      "id",
	})

	ctx := context.Background()
	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	var clusterCount, findingLinkCount, evidenceCount int
	var score int
	pool.QueryRow(ctx,
		`SELECT count(*) FROM risk.clusters WHERE project_id = $1`,
		testProjectID).Scan(&clusterCount)
	pool.QueryRow(ctx,
		`SELECT count(*) FROM risk.cluster_findings cf
		 JOIN risk.clusters c ON c.id = cf.cluster_id
		 WHERE c.project_id = $1`,
		testProjectID).Scan(&findingLinkCount)
	pool.QueryRow(ctx,
		`SELECT count(*) FROM risk.cluster_evidence e
		 JOIN risk.clusters c ON c.id = e.cluster_id
		 WHERE c.project_id = $1`,
		testProjectID).Scan(&evidenceCount)
	pool.QueryRow(ctx,
		`SELECT risk_score FROM risk.clusters WHERE project_id = $1 LIMIT 1`,
		testProjectID).Scan(&score)

	if clusterCount != 1 {
		t.Errorf("cluster count = %d, want 1", clusterCount)
	}
	if findingLinkCount != 1 {
		t.Errorf("cluster_findings count = %d, want 1", findingLinkCount)
	}
	if evidenceCount < 1 {
		t.Errorf("evidence count = %d, want >= 1 (SEVERITY_BASE)", evidenceCount)
	}
	if score < 60 {
		t.Errorf("score = %d, want >= 60 (critical base)", score)
	}
}

// TestRebuild_SASTDASTRuntimeConfirmation verifies the core cross-type
// link: a SAST and a DAST finding with the same CWE create two separate
// clusters joined by a runtime_confirmation relation, and both clusters
// get the +20 RUNTIME_CONFIRMED boost.
func TestRebuild_SASTDASTRuntimeConfirmation(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "sast",
		"title":          "SQL Injection in findUser",
		"severity":       "high",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-JAVA-SQL-001",
		"file_path":      "src/main/UserRepo.java",
		"line_start":     42,
		"function_name":  "findUser",
	})
	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "dast",
		"title":          "SQL Injection via id",
		"severity":       "high",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-DAST-SQLI-001",
		"url":            "https://stg.example.com/api/users",
		"http_method":    "GET",
		"parameter":      "id",
	})

	ctx := context.Background()
	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	var clusterCount, relationCount int
	pool.QueryRow(ctx,
		`SELECT count(*) FROM risk.clusters WHERE project_id = $1`,
		testProjectID).Scan(&clusterCount)
	pool.QueryRow(ctx,
		`SELECT count(*) FROM risk.cluster_relations
		 WHERE project_id = $1 AND relation_type = 'runtime_confirmation'`,
		testProjectID).Scan(&relationCount)

	if clusterCount != 2 {
		t.Errorf("cluster count = %d, want 2 (one SAST, one DAST)", clusterCount)
	}
	if relationCount != 1 {
		t.Errorf("runtime_confirmation relation count = %d, want 1", relationCount)
	}

	// Both clusters should score >= 65 (45 base + 20 runtime).
	rows, err := pool.Query(ctx,
		`SELECT risk_score FROM risk.clusters WHERE project_id = $1`,
		testProjectID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var score int
		rows.Scan(&score)
		if score < 65 {
			t.Errorf("cluster score = %d, want >= 65", score)
		}
	}
}

// TestRebuild_UserResolvedStaysResolved verifies user triage is sticky.
// A cluster explicitly marked user_resolved must NOT be auto-reactivated
// by a subsequent rebuild even when the underlying findings still exist.
func TestRebuild_UserResolvedStaysResolved(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	ctx := context.Background()

	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "dast",
		"title":          "X",
		"severity":       "medium",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-DAST-SQLI-001",
		"url":            "https://x.com/q",
		"http_method":    "GET",
		"parameter":      "id",
	})

	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}

	// User marks the cluster resolved.
	_, err := pool.Exec(ctx,
		`UPDATE risk.clusters SET status = 'user_resolved', resolved_at = now() WHERE project_id = $1`,
		testProjectID)
	if err != nil {
		t.Fatal(err)
	}

	// Second rebuild — finding still there, but status must NOT revert.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}

	var status string
	pool.QueryRow(ctx,
		`SELECT status FROM risk.clusters WHERE project_id = $1`,
		testProjectID).Scan(&status)
	if status != "user_resolved" {
		t.Errorf("status after rebuild = %q, want user_resolved", status)
	}
}

// TestRebuild_AutoResolveGracePeriod verifies the 3-run grace period.
// After 1 and 2 empty runs the cluster stays active; after 3 it becomes
// auto_resolved.
func TestRebuild_AutoResolveGracePeriod(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	ctx := context.Background()

	fID := insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "dast",
		"title":          "X",
		"severity":       "medium",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-DAST-SQLI-001",
		"url":            "https://x.com/q",
		"http_method":    "GET",
		"parameter":      "id",
	})

	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}

	// Delete the finding (simulate it disappearing from scans).
	if _, err := pool.Exec(ctx, `DELETE FROM findings.findings WHERE id = $1`, fID); err != nil {
		t.Fatal(err)
	}

	// Run 1 empty — still active.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}
	var status string
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "active" {
		t.Errorf("after 1 empty run, status = %q, want active", status)
	}

	// Run 2 empty — still active.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "active" {
		t.Errorf("after 2 empty runs, status = %q, want active", status)
	}

	// Run 3 empty — should auto-resolve.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "auto_resolved" {
		t.Errorf("after 3 empty runs, status = %q, want auto_resolved", status)
	}
}
