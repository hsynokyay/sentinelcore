BEGIN;

-- Row-level security for audit.audit_log.
--
-- These policies apply to ALL roles EXCEPT the table owner and the
-- PostgreSQL superuser. Today the `sentinelcore` role owns every
-- table, so enabling RLS here is staged — the policies kick in once
-- ops splits the audit writer/reader out to dedicated roles per
-- plan §1.5. Until then the policies are inert but vetted.
--
-- Writer policy: INSERT is allowed only when the session sets
--   SET app.writer_role = 'audit_worker'
-- The audit-service applies this pragma on every connection via an
-- AfterConnect hook (see cmd/audit-service/main.go).
--
-- Reader policy: SELECT is tenant-scoped via app.current_org_id.
-- Platform admins / auditors may flip app.audit_global_read=true to
-- read across tenants — every such session is itself auditable
-- (audit.global_access.granted emitted by the middleware that sets
-- the flag; wiring lands in chunk 8).

ALTER TABLE audit.audit_log ENABLE ROW LEVEL SECURITY;

-- Drop old permissive policies if any (idempotent re-apply).
DROP POLICY IF EXISTS audit_log_read_tenant   ON audit.audit_log;
DROP POLICY IF EXISTS audit_log_insert_worker ON audit.audit_log;

CREATE POLICY audit_log_read_tenant ON audit.audit_log
    FOR SELECT
    USING (
        org_id::text = current_setting('app.current_org_id', true)
        OR current_setting('app.audit_global_read', true) = 'true'
    );

CREATE POLICY audit_log_insert_worker ON audit.audit_log
    FOR INSERT
    WITH CHECK (current_setting('app.writer_role', true) = 'audit_worker');

-- integrity_checks: readable by anyone with audit.verify (gated at API
-- layer), INSERT restricted the same way as audit_log. Per-tenant
-- scoping doesn't apply — partition_name + outcome are platform-level
-- diagnostics.
ALTER TABLE audit.integrity_checks ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS integrity_read_all    ON audit.integrity_checks;
DROP POLICY IF EXISTS integrity_insert_role ON audit.integrity_checks;

CREATE POLICY integrity_read_all ON audit.integrity_checks
    FOR SELECT
    USING (true);  -- API layer gates read access; table is not tenant-scoped

CREATE POLICY integrity_insert_role ON audit.integrity_checks
    FOR INSERT
    WITH CHECK (current_setting('app.writer_role', true) = 'audit_worker');

-- hmac_keys is admin-only; no RLS policy, access is via role grants.
-- (Adding RLS would silently hide key rows from the audit-worker that
-- actually needs them. Left un-enabled.)

COMMIT;
