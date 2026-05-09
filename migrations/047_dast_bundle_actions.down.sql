DROP INDEX IF EXISTS dast_auth_bundles_action_count;
ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS action_count;
