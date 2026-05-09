BEGIN;

-- Phase 9 §4.1: extend approval workflow with per-project policy +
-- multi-approver support + vote immutability.
--
-- Existing governance.approval_requests (from migration 014) gains:
--   approvals_received / rejections_received   — counters for quorum
--   required_approvers                         — captured at create
--                                                 time so a later
--                                                 policy change does
--                                                 not retro-adjust
--                                                 an in-flight req

ALTER TABLE governance.approval_requests
    ADD COLUMN IF NOT EXISTS approvals_received  INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rejections_received INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS required_approvers  INTEGER NOT NULL DEFAULT 1;

-- Extend the status CHECK to allow the intermediate 'reviewed' state
-- used by two-person flows. Drop first because ADD CONSTRAINT ... IF
-- NOT EXISTS is not supported on CHECK in Postgres < 17.
ALTER TABLE governance.approval_requests
    DROP CONSTRAINT IF EXISTS approval_status_check;
ALTER TABLE governance.approval_requests
    ADD CONSTRAINT approval_status_check
    CHECK (status IN ('pending','reviewed','approved','rejected','expired'));

-- Per-project approval policy. One row per project; missing row =
-- "no approval required, current behaviour".
CREATE TABLE governance.approval_policies (
    project_id          UUID PRIMARY KEY REFERENCES core.projects(id) ON DELETE CASCADE,
    org_id              UUID NOT NULL REFERENCES core.organizations(id),
    risk_closure        BOOLEAN NOT NULL DEFAULT false,
    finding_suppression BOOLEAN NOT NULL DEFAULT false,
    scan_target_change  BOOLEAN NOT NULL DEFAULT false,
    required_approvers  INTEGER NOT NULL DEFAULT 1 CHECK (required_approvers BETWEEN 1 AND 5),
    -- Role names must exist in auth.roles; validation is application-
    -- side because a FK to an array element isn't expressible.
    approver_roles      TEXT[] NOT NULL DEFAULT ARRAY['owner','admin'],
    auto_expire_hours   INTEGER NOT NULL DEFAULT 168, -- 7 days
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_approval_policies_org ON governance.approval_policies(org_id);

-- Per-request approver decisions. Primary key (request_id, approver_id)
-- so the same user cannot vote twice on the same request. Append-only
-- below means a vote cast cannot be rewritten post-hoc.
CREATE TABLE governance.approval_approvers (
    request_id   UUID NOT NULL REFERENCES governance.approval_requests(id) ON DELETE CASCADE,
    approver_id  UUID NOT NULL REFERENCES core.users(id),
    decision     TEXT NOT NULL CHECK (decision IN ('approve','reject')),
    reason       TEXT,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, approver_id)
);
CREATE INDEX idx_approvers_request ON governance.approval_approvers(request_id);

-- RLS: approval_policies scoped by org; approval_approvers inherits
-- visibility from the parent approval_requests row.
ALTER TABLE governance.approval_policies  ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.approval_approvers ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY org_isolation ON governance.approval_policies
        USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE POLICY request_visibility ON governance.approval_approvers
        USING (request_id IN (
            SELECT id FROM governance.approval_requests
            WHERE org_id = current_setting('app.current_org_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Append-only: once a row lands in approval_approvers it cannot be
-- mutated or deleted. Prevents vote flipping. Reuses the Phase 6
-- SECURITY DEFINER trigger idiom.
CREATE OR REPLACE FUNCTION governance.approvers_immutable()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'governance.approval_approvers is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS approvers_no_update ON governance.approval_approvers;
DROP TRIGGER IF EXISTS approvers_no_delete ON governance.approval_approvers;
CREATE TRIGGER approvers_no_update
    BEFORE UPDATE ON governance.approval_approvers
    FOR EACH ROW EXECUTE FUNCTION governance.approvers_immutable();
CREATE TRIGGER approvers_no_delete
    BEFORE DELETE ON governance.approval_approvers
    FOR EACH ROW EXECUTE FUNCTION governance.approvers_immutable();

COMMIT;
