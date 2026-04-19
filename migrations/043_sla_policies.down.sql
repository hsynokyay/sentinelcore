BEGIN;

DROP TRIGGER IF EXISTS sla_deadlines_guard ON governance.sla_deadlines;
DROP FUNCTION IF EXISTS governance.sla_deadlines_restrict();

DROP POLICY IF EXISTS org_isolation ON governance.sla_deadlines;
DROP POLICY IF EXISTS org_isolation ON governance.sla_policies;

DROP INDEX IF EXISTS governance.idx_sla_deadlines_project;
DROP INDEX IF EXISTS governance.idx_sla_deadlines_unresolved;
DROP TABLE IF EXISTS governance.sla_deadlines;

DROP INDEX IF EXISTS governance.idx_sla_policies_org;
DROP TABLE IF EXISTS governance.sla_policies;

COMMIT;
