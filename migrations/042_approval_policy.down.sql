BEGIN;

DROP TRIGGER IF EXISTS approvers_no_delete ON governance.approval_approvers;
DROP TRIGGER IF EXISTS approvers_no_update ON governance.approval_approvers;
DROP FUNCTION IF EXISTS governance.approvers_immutable();

DROP POLICY IF EXISTS request_visibility ON governance.approval_approvers;
DROP POLICY IF EXISTS org_isolation      ON governance.approval_policies;

DROP TABLE IF EXISTS governance.approval_approvers;
DROP TABLE IF EXISTS governance.approval_policies;

ALTER TABLE governance.approval_requests
    DROP COLUMN IF EXISTS approvals_received,
    DROP COLUMN IF EXISTS rejections_received,
    DROP COLUMN IF EXISTS required_approvers;

-- Restore original status CHECK (without 'reviewed').
ALTER TABLE governance.approval_requests
    DROP CONSTRAINT IF EXISTS approval_status_check;
ALTER TABLE governance.approval_requests
    ADD CONSTRAINT approval_status_check
    CHECK (status IN ('pending','approved','rejected','expired'));

COMMIT;
