DROP INDEX IF EXISTS dast_auth_bundles_recording;
ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS recording_metadata;
