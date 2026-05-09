-- 049_dast_replay_hardening.down.sql
ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS principal_claim;
DROP TABLE IF EXISTS dast_replay_failures;
