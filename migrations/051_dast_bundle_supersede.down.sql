-- 051_dast_bundle_supersede.down.sql
-- Reverts the supersede column and status enum extension.
--
-- DATA LOSS NOTE: any rows with status='superseded' must be migrated to
-- another value (e.g. 'soft_deleted') before this migration can succeed,
-- otherwise the new check constraint will fail.

ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS superseded_by;

ALTER TABLE dast_auth_bundles DROP CONSTRAINT IF EXISTS dast_auth_bundles_status_check;
ALTER TABLE dast_auth_bundles ADD CONSTRAINT dast_auth_bundles_status_check
    CHECK (status IN (
        'pending_review',
        'approved',
        'revoked',
        'refresh_required',
        'expired',
        'soft_deleted'
    ));
