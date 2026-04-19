BEGIN;

DROP POLICY IF EXISTS export_jobs_tenant ON audit.export_jobs;
ALTER TABLE audit.export_jobs DISABLE ROW LEVEL SECURITY;

DROP INDEX IF EXISTS audit.export_jobs_requested_by_idx;
DROP INDEX IF EXISTS audit.export_jobs_org_status_idx;
DROP TABLE IF EXISTS audit.export_jobs;

COMMIT;
