-- 051_dast_bundle_supersede.up.sql
-- Adds an explicit "superseded" status and a forward link from a re-recorded
-- source bundle to its replacement.
--
-- See plan #6 (DAST internal GA) Task D.1 / spec §6.

ALTER TABLE dast_auth_bundles
    ADD COLUMN IF NOT EXISTS superseded_by UUID NULL REFERENCES dast_auth_bundles(id);

-- Extend the status check constraint to include 'superseded'.
ALTER TABLE dast_auth_bundles DROP CONSTRAINT IF EXISTS dast_auth_bundles_status_check;
ALTER TABLE dast_auth_bundles ADD CONSTRAINT dast_auth_bundles_status_check
    CHECK (status IN (
        'pending_review',
        'approved',
        'revoked',
        'refresh_required',
        'expired',
        'soft_deleted',
        'superseded'
    ));
