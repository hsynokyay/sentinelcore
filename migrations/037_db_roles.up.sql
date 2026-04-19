BEGIN;

-- Phase 7 §5.1: Split the monolithic `sentinelcore` role into four
-- least-privilege roles so each service container holds only the
-- grants it actually needs. Compromise of the controlplane binary
-- no longer grants audit-write; compromise of the worker does not
-- grant audit-read.
--
-- The four roles are created with LOGIN but no password. Passwords
-- are set out-of-band by the deploy CLI:
--
--   sentinelcore-cli db-split-roles --apply
--
-- which fetches fresh material from Vault (or file fallback) and runs
-- ALTER ROLE ... PASSWORD against each one. This keeps secret
-- material out of migration files, which are tracked in git.
--
-- Existing schema ownership stays with the `sentinelcore` role (so
-- migrations keep working); grants below authorize the new roles to
-- access specific schemas and tables.

-- --- 1. Create the roles --------------------------------------------------

DO $$ BEGIN
    CREATE ROLE sentinelcore_controlplane LOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE ROLE sentinelcore_audit_writer LOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE ROLE sentinelcore_worker LOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE ROLE sentinelcore_readonly LOGIN;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- --- 2. controlplane — tenant CRUD, no audit write ------------------------
--
-- Runs the HTTP API. Reads and writes every tenant schema. Reads
-- audit for display endpoints (integrity checks, risk history) but
-- does NOT have INSERT on audit tables — emits events via NATS
-- instead, which the audit-service consumes under a different role.

GRANT USAGE ON SCHEMA
    core, scans, findings, governance, auth, risk
TO sentinelcore_controlplane;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA
    core, scans, findings, governance, auth, risk
TO sentinelcore_controlplane;

GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA
    core, scans, findings, governance, auth, risk
TO sentinelcore_controlplane;

-- Audit: SELECT only (for the display endpoints).
GRANT USAGE ON SCHEMA audit TO sentinelcore_controlplane;
GRANT SELECT ON audit.audit_log, audit.risk_events,
                audit.export_jobs, audit.integrity_checks,
                audit.hmac_keys
    TO sentinelcore_controlplane;
-- Export jobs are written by controlplane (user-initiated exports).
GRANT INSERT, UPDATE ON audit.export_jobs TO sentinelcore_controlplane;

-- --- 3. audit-writer — INSERT-only on audit -------------------------------
--
-- Runs the cmd/audit-service consumer. Reads NATS, writes audit rows.
-- No tenant schema access at all — a compromise here reveals audit
-- data (already visible to auditors) but cannot exfiltrate findings,
-- secrets, or projects.

GRANT USAGE ON SCHEMA audit TO sentinelcore_audit_writer;
GRANT SELECT ON audit.audit_log, audit.risk_events   -- for previous_hash chain lookup
    TO sentinelcore_audit_writer;
GRANT INSERT ON audit.audit_log, audit.risk_events,
                audit.integrity_checks
    TO sentinelcore_audit_writer;
GRANT SELECT ON audit.hmac_keys TO sentinelcore_audit_writer;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO sentinelcore_audit_writer;

-- --- 4. worker — scan/finding writer, read-only on core -------------------
--
-- Runs cmd/sast-worker, cmd/dast-worker, cmd/correlation-engine. Writes
-- scan output (findings, risk.clusters) but MUST NOT mutate core tables
-- (no org/project/user changes) or touch audit directly.

GRANT USAGE ON SCHEMA core, scans, findings, risk TO sentinelcore_worker;
GRANT SELECT ON ALL TABLES IN SCHEMA core TO sentinelcore_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA scans, findings, risk
    TO sentinelcore_worker;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA scans, findings, risk
    TO sentinelcore_worker;

-- Vuln-intel schema is a read-cache; workers populate, controlplane reads.
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'vuln_intel') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA vuln_intel TO sentinelcore_worker';
        EXECUTE 'GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA vuln_intel TO sentinelcore_worker';
    END IF;
END $$;

-- --- 5. readonly — SELECT everywhere, for reports + SIEM ------------------
--
-- Used by retention/SIEM pulls and the future report-export worker.
-- Useful for ad-hoc DBA queries: safer than handing out the owner role.

GRANT USAGE ON SCHEMA
    core, scans, findings, governance, auth, risk, audit
TO sentinelcore_readonly;

GRANT SELECT ON ALL TABLES IN SCHEMA
    core, scans, findings, governance, auth, risk, audit
TO sentinelcore_readonly;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name = 'vuln_intel') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA vuln_intel TO sentinelcore_readonly';
        EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA vuln_intel TO sentinelcore_readonly';
    END IF;
END $$;

-- --- 6. Default privileges ------------------------------------------------
--
-- ALTER DEFAULT PRIVILEGES ensures tables added by FUTURE migrations
-- inherit the same grants. Without these, every migration 041+ would
-- need to re-run the role grants.
--
-- Scope is "tables created by the sentinelcore role (the owner)" since
-- migrations run as sentinelcore. New tables in any of the schemas
-- automatically get the appropriate role grants.

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA
    core, scans, findings, governance, auth, risk
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinelcore_controlplane;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA
    core, scans, findings, governance, auth, risk
    GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO sentinelcore_controlplane;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA scans, findings, risk
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinelcore_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA core
    GRANT SELECT ON TABLES TO sentinelcore_worker;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA audit
    GRANT INSERT ON TABLES TO sentinelcore_audit_writer;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinelcore IN SCHEMA
    core, scans, findings, governance, auth, risk, audit
    GRANT SELECT ON TABLES TO sentinelcore_readonly;

-- --- 7. RLS-bypass waiver for audit-writer --------------------------------
--
-- audit-writer writes rows for every tenant (org_id comes from the
-- event, not the session). RLS on audit.audit_log filters by
-- app.current_org_id, which this role cannot reasonably set — it
-- processes a queue spanning all tenants.
--
-- BYPASSRLS on the role attribute is the clean solution. The role
-- still cannot write to tenant schemas, so the blast radius is
-- narrowed to the audit tables themselves.

ALTER ROLE sentinelcore_audit_writer BYPASSRLS;

-- Worker likewise writes across tenants (scan job pulls from NATS
-- span orgs) — same reasoning.
ALTER ROLE sentinelcore_worker BYPASSRLS;

-- controlplane is the only role that enforces RLS end-to-end. The
-- BYPASSRLS attribute is intentionally NOT granted here — all handler
-- paths must route through tenant.TxUser which sets app.current_org_id.

COMMIT;
