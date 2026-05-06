package governance_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// seedOrgAndProject creates an isolated org + project + default org_settings
// row and returns their UUIDs plus a cleanup callback that drops dependent
// rows. Skips the test (via testPool) when TEST_DATABASE_URL is unset.
func seedOrgAndProject(t *testing.T, pool *pgxpool.Pool, sensitivity string) (uuid.UUID, uuid.UUID, func()) {
	t.Helper()
	ctx := context.Background()

	orgID := uuid.New()
	projID := uuid.New()
	teamID := uuid.New()

	suffix := orgID.String()[:8]

	if _, err := pool.Exec(ctx, `
		INSERT INTO core.organizations (id, name, display_name, created_at, updated_at)
		VALUES ($1, $2, $3, now(), now())
	`, orgID, "test-org-"+suffix, "Test Org "+suffix); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO core.teams (id, org_id, name, display_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, now(), now())
	`, teamID, orgID, "test-team-"+suffix, "Test Team"); err != nil {
		t.Fatalf("seed team: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO core.projects (id, org_id, team_id, name, display_name, asset_criticality, status, sensitivity, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'Test Project', 'medium', 'active', $5, now(), now())
	`, projID, orgID, teamID, "test-proj-"+suffix, sensitivity); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO governance.org_settings (org_id, updated_at)
		VALUES ($1, now())
	`, orgID); err != nil {
		t.Fatalf("seed org_settings: %v", err)
	}

	cleanup := func() {
		// Findings, transitions, approvals first (FK dependents).
		_, _ = pool.Exec(ctx, `DELETE FROM governance.approval_decisions WHERE approval_request_id IN (SELECT id FROM governance.approval_requests WHERE org_id=$1)`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM governance.approval_requests WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM governance.finding_transitions WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM findings.findings WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM scans.scan_jobs WHERE project_id=$1`, projID)
		_, _ = pool.Exec(ctx, `DELETE FROM governance.org_settings WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.team_memberships WHERE team_id=$1`, teamID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.users WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.projects WHERE id=$1`, projID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.teams WHERE id=$1`, teamID)
		_, _ = pool.Exec(ctx, `DELETE FROM core.organizations WHERE id=$1`, orgID)
	}

	return orgID, projID, cleanup
}

// setOrgSetting toggles a boolean column in governance.org_settings.
func setOrgSetting(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, column string, value bool) {
	t.Helper()
	// Column name is whitelisted at compile site; safe to interpolate.
	q := fmt.Sprintf(`UPDATE governance.org_settings SET %s = $2, updated_at = now() WHERE org_id = $1`, column)
	if _, err := pool.Exec(context.Background(), q, orgID, value); err != nil {
		t.Fatalf("set org setting %s: %v", column, err)
	}
}

// setProjectSensitivity updates core.projects.sensitivity.
func setProjectSensitivity(t *testing.T, pool *pgxpool.Pool, projID uuid.UUID, sensitivity string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE core.projects SET sensitivity = $2, updated_at = now() WHERE id = $1`,
		projID, sensitivity); err != nil {
		t.Fatalf("set project sensitivity: %v", err)
	}
}

// seedUser creates a user in the given org and returns its UUID.
func seedUser(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, role string) uuid.UUID {
	t.Helper()
	uid := uuid.New()
	suffix := uid.String()[:8]
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO core.users (id, org_id, username, email, display_name, password_hash, role, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'x', $6, 'active', now(), now())
	`, uid, orgID, "user-"+suffix, "user-"+suffix+"@example.test", "User "+suffix, role); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return uid
}

// seedFinding inserts a finding and returns its UUID.
func seedFinding(t *testing.T, pool *pgxpool.Pool, orgID, projID uuid.UUID, status string) uuid.UUID {
	t.Helper()
	scanJobID := uuid.New()
	creator := seedUser(t, pool, orgID, "security_admin")

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO scans.scan_jobs (id, project_id, scan_type, trigger_type, status, created_by, created_at, updated_at)
		VALUES ($1, $2, 'sast', 'manual', 'completed', $3, now(), now())
	`, scanJobID, projID, creator); err != nil {
		t.Fatalf("seed scan_job: %v", err)
	}

	fid := uuid.New()
	suffix := fid.String()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO findings.findings (
			id, project_id, scan_job_id, finding_type, fingerprint,
			title, description, severity, confidence, status,
			org_id, first_seen_at, created_at, updated_at
		)
		VALUES ($1, $2, $3, 'sast', $4, 'test finding', 'desc', 'high', 'medium', $5, $6, now(), now(), now())
	`, fid, projID, scanJobID, suffix, status, orgID); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return fid
}
