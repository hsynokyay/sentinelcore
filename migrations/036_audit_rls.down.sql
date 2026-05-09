BEGIN;

DROP POLICY IF EXISTS integrity_insert_role ON audit.integrity_checks;
DROP POLICY IF EXISTS integrity_read_all    ON audit.integrity_checks;
ALTER TABLE audit.integrity_checks DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_log_insert_worker ON audit.audit_log;
DROP POLICY IF EXISTS audit_log_read_tenant   ON audit.audit_log;
ALTER TABLE audit.audit_log DISABLE ROW LEVEL SECURITY;

COMMIT;
