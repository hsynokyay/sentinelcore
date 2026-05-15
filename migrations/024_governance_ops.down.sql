-- migrations/024_governance_ops.down.sql
-- Reverse 024_governance_ops.up.sql

DROP TABLE IF EXISTS governance.export_jobs;
DROP TABLE IF EXISTS governance.control_mappings;
DROP TABLE IF EXISTS governance.control_items;
DROP TABLE IF EXISTS governance.control_catalogs;
DROP TABLE IF EXISTS governance.project_sla_policies;
DROP TABLE IF EXISTS governance.approval_decisions;

ALTER TABLE governance.approval_requests
    DROP CONSTRAINT IF EXISTS approval_status_check;
ALTER TABLE governance.approval_requests
    ADD CONSTRAINT approval_status_check
    CHECK (status IN ('pending','approved','rejected','expired'));

ALTER TABLE governance.approval_requests
    DROP CONSTRAINT IF EXISTS approval_requests_required_approvals_check;

ALTER TABLE governance.approval_requests
    DROP COLUMN IF EXISTS required_approvals,
    DROP COLUMN IF EXISTS current_approvals,
    DROP COLUMN IF EXISTS target_transition,
    DROP COLUMN IF EXISTS project_id;

ALTER TABLE governance.org_settings
    DROP CONSTRAINT IF EXISTS org_settings_approval_expiry_check,
    DROP CONSTRAINT IF EXISTS org_settings_sla_warning_window_check;

ALTER TABLE governance.org_settings
    DROP COLUMN IF EXISTS require_closure_approval,
    DROP COLUMN IF EXISTS require_two_person_closure,
    DROP COLUMN IF EXISTS approval_expiry_days,
    DROP COLUMN IF EXISTS sla_warning_window_days;

ALTER TABLE core.projects
    DROP CONSTRAINT IF EXISTS projects_sensitivity_check;

ALTER TABLE core.projects
    DROP COLUMN IF EXISTS sensitivity;
