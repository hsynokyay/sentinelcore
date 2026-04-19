BEGIN;

DROP POLICY IF EXISTS correlation_runs_org_isolation ON findings.correlation_runs;
DROP POLICY IF EXISTS correlation_members_org_isolation ON findings.correlation_members;
DROP POLICY IF EXISTS correlation_groups_org_isolation ON findings.correlation_groups;

ALTER TABLE findings.findings
    DROP COLUMN IF EXISTS correlation_group_id,
    DROP COLUMN IF EXISTS actively_exploited,
    DROP COLUMN IF EXISTS exploit_available,
    DROP COLUMN IF EXISTS related_cve_ids;

DROP INDEX IF EXISTS findings.idx_findings_project_type;

DROP TABLE IF EXISTS findings.correlation_runs;
DROP TABLE IF EXISTS findings.cwe_hierarchy;
DROP TABLE IF EXISTS findings.correlation_members;
DROP TABLE IF EXISTS findings.correlation_groups;

COMMIT;
