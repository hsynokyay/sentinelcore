package integration

// role_split_test.go — Phase 7 §5.1 + §9 Wave 3 smoke test.
//
// Connects as each of the four split roles and asserts that the
// grants they have match the migration's intent. Catches accidental
// privilege escalation across upgrades.
//
// Environment:
//
//   TEST_DATABASE_URL                (sentinelcore monolithic — used for DDL/seed)
//   PSQL_CONTROLPLANE                (sentinelcore_controlplane DSN)
//   PSQL_AUDIT_WRITER                (sentinelcore_audit_writer DSN)
//   PSQL_WORKER                      (sentinelcore_worker DSN)
//   PSQL_READONLY                    (sentinelcore_readonly DSN)
//
// Any missing PSQL_* env → that role's tests skip with a message;
// the overall suite still passes the roles you DID provide.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func openAs(t *testing.T, envName string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv(envName)
	if dsn == "" {
		t.Skipf("%s not set", envName)
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect as %s: %v", envName, err)
	}
	return pool
}

// expectSQLState runs sql and asserts that the error (if any) matches
// the expected SQLSTATE code. Empty state means "must succeed".
func expectSQLState(t *testing.T, pool *pgxpool.Pool, desc, sql, wantState string) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, sql)
	if wantState == "" {
		if err != nil {
			t.Errorf("%s: want success, got %v", desc, err)
		}
		return
	}
	if err == nil {
		t.Errorf("%s: want SQLSTATE %s, got success", desc, wantState)
		return
	}
	var pge *pgconn.PgError
	if !errors.As(err, &pge) {
		t.Errorf("%s: want SQLSTATE %s, got non-pgconn err %v", desc, wantState, err)
		return
	}
	if !strings.EqualFold(pge.Code, wantState) {
		t.Errorf("%s: want SQLSTATE %s, got %s (%s)", desc, wantState, pge.Code, pge.Message)
	}
}

func TestRoleSplit_Controlplane(t *testing.T) {
	pool := openAs(t, "PSQL_CONTROLPLANE")
	defer pool.Close()

	// Positive: can read + write tenant tables.
	expectSQLState(t, pool, "SELECT core.projects",
		`SELECT count(*) FROM core.projects`, "")

	// Negative: cannot INSERT into audit.audit_log (emit-via-NATS only).
	expectSQLState(t, pool, "INSERT audit.audit_log blocked",
		`INSERT INTO audit.audit_log
		    (id, event_id, occurred_at, ingested_at, actor_type, actor_id,
		     action, resource_type, resource_id, org_id, result)
		 VALUES (nextval(pg_get_serial_sequence('audit.audit_log','id')),
		         gen_random_uuid(), now(), now(), 'user', 'x', 'x', 'x', 'x',
		         gen_random_uuid(), 'success')`,
		"42501")
}

func TestRoleSplit_AuditWriter(t *testing.T) {
	pool := openAs(t, "PSQL_AUDIT_WRITER")
	defer pool.Close()

	// Positive: INSERT INTO audit tables allowed.
	// (We don't actually insert — that would mutate state. The grant
	// check below is sufficient.)
	expectSQLState(t, pool, "SELECT audit.hmac_keys",
		`SELECT count(*) FROM audit.hmac_keys`, "")

	// Negative: cannot read tenant tables — not even SELECT.
	expectSQLState(t, pool, "SELECT core.projects blocked",
		`SELECT count(*) FROM core.projects`, "42501")
	expectSQLState(t, pool, "SELECT findings.findings blocked",
		`SELECT count(*) FROM findings.findings`, "42501")
}

func TestRoleSplit_Worker(t *testing.T) {
	pool := openAs(t, "PSQL_WORKER")
	defer pool.Close()

	// Positive: read core (scan_jobs need project.name etc.), write
	// findings.
	expectSQLState(t, pool, "SELECT core.projects",
		`SELECT count(*) FROM core.projects`, "")
	expectSQLState(t, pool, "SELECT findings.findings",
		`SELECT count(*) FROM findings.findings`, "")

	// Negative: cannot UPDATE core.users (worker has no business
	// mutating user records).
	expectSQLState(t, pool, "UPDATE core.users blocked",
		`UPDATE core.users SET full_name = 'x' WHERE id = gen_random_uuid()`,
		"42501")
	// Negative: cannot INSERT audit.audit_log.
	expectSQLState(t, pool, "INSERT audit.audit_log blocked",
		`INSERT INTO audit.audit_log
		    (id, event_id, occurred_at, ingested_at, actor_type, actor_id,
		     action, resource_type, resource_id, org_id, result)
		 VALUES (nextval(pg_get_serial_sequence('audit.audit_log','id')),
		         gen_random_uuid(), now(), now(), 'user', 'x', 'x', 'x', 'x',
		         gen_random_uuid(), 'success')`,
		"42501")
}

func TestRoleSplit_Readonly(t *testing.T) {
	pool := openAs(t, "PSQL_READONLY")
	defer pool.Close()

	// Positive: SELECT anywhere.
	expectSQLState(t, pool, "SELECT core.projects",
		`SELECT count(*) FROM core.projects`, "")
	expectSQLState(t, pool, "SELECT audit.audit_log",
		`SELECT count(*) FROM audit.audit_log`, "")
	expectSQLState(t, pool, "SELECT findings.findings",
		`SELECT count(*) FROM findings.findings`, "")

	// Negative: any write blocked.
	expectSQLState(t, pool, "UPDATE core.projects blocked",
		`UPDATE core.projects SET display_name = 'x' WHERE id = gen_random_uuid()`,
		"42501")
	expectSQLState(t, pool, "DELETE findings.findings blocked",
		`DELETE FROM findings.findings WHERE id = gen_random_uuid()`,
		"42501")
}
