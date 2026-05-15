package api

// cross_tenant_matrix_test.go — integration test harness that seeds
// two isolated tenants, executes handler-layer reads as each, and
// asserts NOTHING crosses the boundary.
//
// This is the safety net for the Wave 2 pkg/tenant migration. It runs
// against TEST_DATABASE_URL; without it the test skips cleanly.
//
// The matrix covers the high-risk tables RLS touches:
//   * core.projects
//   * findings.findings
//   * governance.webhook_configs

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/pkg/tenant"
)

type tenantFixture struct {
	OrgID     string
	UserID    string
	TeamID    string
	ProjectID string
}

func seedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, slug string) tenantFixture {
	t.Helper()
	f := tenantFixture{
		OrgID:     uuid.New().String(),
		UserID:    uuid.New().String(),
		TeamID:    uuid.New().String(),
		ProjectID: uuid.New().String(),
	}
	mustExec(t, ctx, pool,
		`INSERT INTO core.organizations (id, name, display_name, status)
		 VALUES ($1, $2, $3, 'active')
		 ON CONFLICT (id) DO NOTHING`,
		f.OrgID, "cx-"+slug, "cross-tenant-"+slug)
	mustExec(t, ctx, pool,
		`INSERT INTO core.teams (id, org_id, name, display_name)
		 VALUES ($1, $2, $3, $3)
		 ON CONFLICT (id) DO NOTHING`,
		f.TeamID, f.OrgID, "team-"+slug)
	mustExec(t, ctx, pool,
		`INSERT INTO core.users (id, org_id, email, full_name, role, status)
		 VALUES ($1, $2, $3, $4, 'security_engineer', 'active')
		 ON CONFLICT (id) DO NOTHING`,
		f.UserID, f.OrgID, slug+"@cx.example", "User "+slug)
	mustExec(t, ctx, pool,
		`INSERT INTO core.team_memberships (team_id, user_id, role)
		 VALUES ($1, $2, 'member')
		 ON CONFLICT DO NOTHING`,
		f.TeamID, f.UserID)
	mustExec(t, ctx, pool,
		`INSERT INTO core.projects (id, org_id, team_id, name, display_name, status)
		 VALUES ($1, $2, $3, $4, $4, 'active')
		 ON CONFLICT (id) DO NOTHING`,
		f.ProjectID, f.OrgID, f.TeamID, "proj-"+slug)
	return f
}

func mustExec(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("seed exec: %v\nSQL: %s", err, sql)
	}
}

func TestCrossTenantLeakageMatrix(t *testing.T) {
	pool := testPoolAuthz(t) // skips if TEST_DATABASE_URL unset
	defer pool.Close()
	ctx := context.Background()

	fA := seedTenant(t, ctx, pool, "a"+uuid.New().String()[:8])
	fB := seedTenant(t, ctx, pool, "b"+uuid.New().String()[:8])

	t.Cleanup(func() {
		for _, f := range []tenantFixture{fA, fB} {
			_, _ = pool.Exec(ctx, `DELETE FROM governance.webhook_configs WHERE org_id = $1`, f.OrgID)
			_, _ = pool.Exec(ctx, `DELETE FROM findings.findings WHERE org_id = $1`, f.OrgID)
			_, _ = pool.Exec(ctx, `DELETE FROM core.projects WHERE id = $1`, f.ProjectID)
			_, _ = pool.Exec(ctx, `DELETE FROM core.team_memberships WHERE team_id = $1`, f.TeamID)
			_, _ = pool.Exec(ctx, `DELETE FROM core.teams WHERE id = $1`, f.TeamID)
			_, _ = pool.Exec(ctx, `DELETE FROM core.users WHERE id = $1`, f.UserID)
			_, _ = pool.Exec(ctx, `DELETE FROM core.organizations WHERE id = $1`, f.OrgID)
		}
	})

	t.Run("projects_only_own", func(t *testing.T) {
		ids := projectIDs(t, ctx, pool, fA)
		if !containsOnly(ids, fA.ProjectID) {
			t.Errorf("orgA saw %v, want only [%s]", ids, fA.ProjectID)
		}
		ids = projectIDs(t, ctx, pool, fB)
		if !containsOnly(ids, fB.ProjectID) {
			t.Errorf("orgB saw %v, want only [%s]", ids, fB.ProjectID)
		}
	})

	t.Run("get_foreign_project_no_rows", func(t *testing.T) {
		var gotID string
		err := tenant.TxUser(ctx, pool, fA.OrgID, fA.UserID,
			func(ctx context.Context, tx pgx.Tx) error {
				return tx.QueryRow(ctx,
					`SELECT id FROM core.projects WHERE id = $1`, fB.ProjectID,
				).Scan(&gotID)
			})
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("want pgx.ErrNoRows, got %v (gotID=%s)", err, gotID)
		}
	})

	t.Run("findings_only_own", func(t *testing.T) {
		insertFinding(t, ctx, pool, fA)
		insertFinding(t, ctx, pool, fB)

		if n := countFindings(t, ctx, pool, fA); n != 1 {
			t.Errorf("orgA: want 1 finding, got %d", n)
		}
		if n := countFindings(t, ctx, pool, fB); n != 1 {
			t.Errorf("orgB: want 1 finding, got %d", n)
		}
	})

	t.Run("webhook_configs_only_own", func(t *testing.T) {
		urlA := "https://hook.example/" + fA.OrgID[:8]
		urlB := "https://hook.example/" + fB.OrgID[:8]
		insertWebhook(t, ctx, pool, fA, urlA)
		insertWebhook(t, ctx, pool, fB, urlB)

		urls := webhookURLs(t, ctx, pool, fA)
		for _, u := range urls {
			if u == urlB {
				t.Errorf("leak: orgA saw orgB webhook %q", u)
			}
		}
		urls = webhookURLs(t, ctx, pool, fB)
		for _, u := range urls {
			if u == urlA {
				t.Errorf("leak: orgB saw orgA webhook %q", u)
			}
		}
	})
}

// --- probe helpers ---

func projectIDs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f tenantFixture) []string {
	t.Helper()
	var out []string
	err := tenant.TxUser(ctx, pool, f.OrgID, f.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT id FROM core.projects`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				out = append(out, id)
			}
			return rows.Err()
		})
	if err != nil {
		t.Fatalf("projectIDs: %v", err)
	}
	return out
}

func insertFinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f tenantFixture) {
	t.Helper()
	mustExec(t, ctx, pool,
		`INSERT INTO findings.findings
		   (id, org_id, project_id, scan_job_id, finding_type, severity,
		    status, title, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, 'sast', 'low', 'new', $5, now(), now())`,
		uuid.New().String(), f.OrgID, f.ProjectID, uuid.New().String(),
		"cx-finding-"+f.OrgID[:8])
}

func countFindings(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f tenantFixture) int {
	t.Helper()
	var n int
	err := tenant.TxUser(ctx, pool, f.OrgID, f.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM findings.findings`).Scan(&n)
		})
	if err != nil {
		t.Fatalf("countFindings: %v", err)
	}
	return n
}

func insertWebhook(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f tenantFixture, url string) {
	t.Helper()
	mustExec(t, ctx, pool,
		`INSERT INTO governance.webhook_configs
		   (id, org_id, name, url, secret_encrypted, events, enabled, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, '', ARRAY['scan.completed']::text[], true, now(), now())`,
		uuid.New().String(), f.OrgID, "hook-"+f.OrgID[:8], url)
}

func webhookURLs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, f tenantFixture) []string {
	t.Helper()
	var out []string
	err := tenant.TxUser(ctx, pool, f.OrgID, f.UserID,
		func(ctx context.Context, tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT url FROM governance.webhook_configs`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var u string
				if err := rows.Scan(&u); err != nil {
					return err
				}
				out = append(out, u)
			}
			return rows.Err()
		})
	if err != nil {
		t.Fatalf("webhookURLs: %v", err)
	}
	return out
}

func containsOnly(got []string, want string) bool {
	return len(got) == 1 && got[0] == want
}
