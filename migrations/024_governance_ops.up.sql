-- migrations/024_governance_ops.up.sql
-- Phase 5: Governance & Compliance Operations schema extensions.
-- Adds:
--   * core.projects.sensitivity (standard/sensitive/regulated)
--   * org_settings closure-approval / two-person / expiry / sla-warn columns
--   * approval_requests two-person + target_transition + project_id columns
--   * governance.approval_decisions table (per-approver immutable decisions)
--   * governance.project_sla_policies (per-project SLA overrides)
--   * governance.control_catalogs / control_items / control_mappings
--   * governance.export_jobs
-- Idempotent: every statement uses IF NOT EXISTS / DO blocks.

-- §2.1 Project sensitivity + org settings extensions
ALTER TABLE core.projects
    ADD COLUMN IF NOT EXISTS sensitivity TEXT NOT NULL DEFAULT 'standard';

DO $$ BEGIN
    ALTER TABLE core.projects
        ADD CONSTRAINT projects_sensitivity_check
        CHECK (sensitivity IN ('standard','sensitive','regulated'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE governance.org_settings
    ADD COLUMN IF NOT EXISTS require_closure_approval BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS require_two_person_closure BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS approval_expiry_days INTEGER NOT NULL DEFAULT 7,
    ADD COLUMN IF NOT EXISTS sla_warning_window_days INTEGER NOT NULL DEFAULT 7;

DO $$ BEGIN
    ALTER TABLE governance.org_settings
        ADD CONSTRAINT org_settings_approval_expiry_check
        CHECK (approval_expiry_days BETWEEN 1 AND 30);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE governance.org_settings
        ADD CONSTRAINT org_settings_sla_warning_window_check
        CHECK (sla_warning_window_days BETWEEN 1 AND 30);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- §2.2 Approval decisions (two-person rule)
ALTER TABLE governance.approval_requests
    ADD COLUMN IF NOT EXISTS required_approvals INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS current_approvals INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS target_transition TEXT,
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES core.projects(id);

DO $$ BEGIN
    ALTER TABLE governance.approval_requests
        ADD CONSTRAINT approval_requests_required_approvals_check
        CHECK (required_approvals BETWEEN 1 AND 3);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Extend status check to include 'executed' (terminal state after auto transition).
ALTER TABLE governance.approval_requests DROP CONSTRAINT IF EXISTS approval_status_check;
ALTER TABLE governance.approval_requests
    ADD CONSTRAINT approval_status_check
    CHECK (status IN ('pending','approved','rejected','expired','executed'));

CREATE TABLE IF NOT EXISTS governance.approval_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_request_id UUID NOT NULL
        REFERENCES governance.approval_requests(id) ON DELETE CASCADE,
    decided_by UUID NOT NULL REFERENCES core.users(id),
    decision TEXT NOT NULL CHECK (decision IN ('approve','reject')),
    reason TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (approval_request_id, decided_by)
);

CREATE INDEX IF NOT EXISTS idx_approval_decisions_request
    ON governance.approval_decisions(approval_request_id);

ALTER TABLE governance.approval_decisions ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY approval_decisions_org_isolation
        ON governance.approval_decisions
        USING (approval_request_id IN (
            SELECT id FROM governance.approval_requests
            WHERE org_id = current_setting('app.current_org_id', true)::uuid
        ));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- §2.3 Per-project SLA policies
CREATE TABLE IF NOT EXISTS governance.project_sla_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES core.organizations(id),
    project_id UUID NOT NULL UNIQUE REFERENCES core.projects(id) ON DELETE CASCADE,
    sla_days JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID NOT NULL REFERENCES core.users(id),
    CHECK (jsonb_typeof(sla_days) = 'object'
           AND (sla_days ? 'critical') AND (sla_days ? 'high')
           AND (sla_days ? 'medium')  AND (sla_days ? 'low'))
);

CREATE INDEX IF NOT EXISTS idx_project_sla_policies_org
    ON governance.project_sla_policies(org_id);

ALTER TABLE governance.project_sla_policies ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY project_sla_policies_org_isolation
        ON governance.project_sla_policies
        USING (org_id = current_setting('app.current_org_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- §2.4 Compliance catalogs, items, mappings
CREATE TABLE IF NOT EXISTS governance.control_catalogs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES core.organizations(id),  -- NULL = built-in
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT,
    is_builtin BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, code, version)
);

CREATE TABLE IF NOT EXISTS governance.control_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    catalog_id UUID NOT NULL
        REFERENCES governance.control_catalogs(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    UNIQUE (catalog_id, control_id)
);
CREATE INDEX IF NOT EXISTS idx_control_items_catalog
    ON governance.control_items(catalog_id);

CREATE TABLE IF NOT EXISTS governance.control_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES core.organizations(id),   -- NULL = built-in
    source_kind TEXT NOT NULL CHECK (source_kind IN ('cwe','owasp','internal')),
    source_code TEXT NOT NULL,
    target_control_id UUID NOT NULL
        REFERENCES governance.control_items(id) ON DELETE CASCADE,
    confidence TEXT NOT NULL DEFAULT 'normative'
        CHECK (confidence IN ('normative','derived','custom')),
    source_version TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, source_kind, source_code, target_control_id)
);
CREATE INDEX IF NOT EXISTS idx_control_mappings_source
    ON governance.control_mappings(source_kind, source_code);
CREATE INDEX IF NOT EXISTS idx_control_mappings_org
    ON governance.control_mappings(org_id);

ALTER TABLE governance.control_catalogs ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    CREATE POLICY control_catalogs_read
        ON governance.control_catalogs FOR SELECT
        USING (org_id IS NULL
            OR org_id = current_setting('app.current_org_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
    CREATE POLICY control_catalogs_write
        ON governance.control_catalogs FOR ALL
        USING (org_id = current_setting('app.current_org_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE governance.control_items ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    CREATE POLICY control_items_read
        ON governance.control_items FOR SELECT
        USING (catalog_id IN (
            SELECT id FROM governance.control_catalogs
            WHERE org_id IS NULL
               OR org_id = current_setting('app.current_org_id', true)::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE governance.control_mappings ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    CREATE POLICY control_mappings_read
        ON governance.control_mappings FOR SELECT
        USING (org_id IS NULL
            OR org_id = current_setting('app.current_org_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$ BEGIN
    CREATE POLICY control_mappings_write
        ON governance.control_mappings FOR ALL
        USING (org_id = current_setting('app.current_org_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- §2.5 Export jobs
CREATE TABLE IF NOT EXISTS governance.export_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES core.organizations(id),
    requested_by UUID NOT NULL REFERENCES core.users(id),
    kind TEXT NOT NULL CHECK (kind IN ('risk_evidence_pack','project_evidence_pack','custom')),
    scope JSONB NOT NULL,
    format TEXT NOT NULL CHECK (format IN ('zip_json','json')),
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','failed','expired')),
    artifact_ref TEXT,
    artifact_hash TEXT,
    artifact_size BIGINT,
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_export_jobs_org_status
    ON governance.export_jobs(org_id, status);
CREATE INDEX IF NOT EXISTS idx_export_jobs_expires
    ON governance.export_jobs(expires_at)
    WHERE status = 'completed';

ALTER TABLE governance.export_jobs ENABLE ROW LEVEL SECURITY;
DO $$ BEGIN
    CREATE POLICY export_jobs_org_isolation
        ON governance.export_jobs
        USING (org_id = current_setting('app.current_org_id', true)::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
