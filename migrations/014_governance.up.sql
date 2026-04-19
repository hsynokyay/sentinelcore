-- migrations/014_governance.up.sql
-- Phase 4: Enterprise Governance schema

-- 1. New schema
CREATE SCHEMA IF NOT EXISTS governance;

-- 2. Org settings
CREATE TABLE IF NOT EXISTS governance.org_settings (
    org_id       UUID PRIMARY KEY REFERENCES core.organizations(id),
    require_approval_for_risk_acceptance  BOOLEAN DEFAULT false,
    require_approval_for_false_positive   BOOLEAN DEFAULT false,
    require_approval_for_scope_expansion  BOOLEAN DEFAULT false,
    default_finding_sla_days             JSONB DEFAULT '{"critical":3,"high":7,"medium":30,"low":90}',
    retention_policies                    JSONB DEFAULT '{"findings":{"retention_days":365,"grace_days":30},"evidence":{"retention_days":365,"grace_days":30},"audit_log":{"retention_days":730,"grace_days":90},"scan_job":{"retention_days":180,"grace_days":14},"notification":{"retention_days":90,"grace_days":7},"webhook_delivery":{"retention_days":30,"grace_days":7}}',
    updated_at   TIMESTAMPTZ DEFAULT now(),
    updated_by   UUID
);

-- 3. Approval requests
CREATE TABLE IF NOT EXISTS governance.approval_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES core.organizations(id),
    team_id       UUID REFERENCES core.teams(id),
    request_type  TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   UUID NOT NULL,
    requested_by  UUID NOT NULL REFERENCES core.users(id),
    reason        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    decided_by    UUID REFERENCES core.users(id),
    decision_reason TEXT,
    decided_at    TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT approval_status_check CHECK (status IN ('pending','approved','rejected','expired'))
);
CREATE INDEX IF NOT EXISTS idx_approval_org_status ON governance.approval_requests(org_id, status);
CREATE INDEX IF NOT EXISTS idx_approval_resource ON governance.approval_requests(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_approval_expiring ON governance.approval_requests(expires_at) WHERE status = 'pending';

-- 4. Finding assignments
CREATE TABLE IF NOT EXISTS governance.finding_assignments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   UUID NOT NULL REFERENCES findings.findings(id),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    team_id      UUID REFERENCES core.teams(id),
    assigned_to  UUID NOT NULL REFERENCES core.users(id),
    assigned_by  UUID NOT NULL REFERENCES core.users(id),
    due_at       TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'active',
    note         TEXT,
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT assignment_status_check CHECK (status IN ('active','completed','reassigned'))
);
CREATE INDEX IF NOT EXISTS idx_assignment_assignee ON governance.finding_assignments(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_assignment_finding ON governance.finding_assignments(finding_id);

-- 5. SLA violations
CREATE TABLE IF NOT EXISTS governance.sla_violations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   UUID NOT NULL REFERENCES findings.findings(id),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    severity     TEXT NOT NULL,
    sla_days     INTEGER NOT NULL,
    deadline_at  TIMESTAMPTZ NOT NULL,
    violated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    escalated    BOOLEAN DEFAULT false,
    updated_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sla_org_unresolved ON governance.sla_violations(org_id) WHERE resolved_at IS NULL;

-- 6. Notifications
CREATE TABLE IF NOT EXISTS governance.notifications (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    user_id      UUID NOT NULL,
    category     TEXT NOT NULL,
    title        TEXT NOT NULL,
    body         TEXT,
    resource_type TEXT,
    resource_id  UUID,
    read         BOOLEAN DEFAULT false,
    created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notif_user_unread ON governance.notifications(user_id) WHERE read = false;
CREATE INDEX IF NOT EXISTS idx_notif_user_created ON governance.notifications(user_id, created_at DESC);

-- 7. Webhook configs
CREATE TABLE IF NOT EXISTS governance.webhook_configs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    name         TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret_encrypted BYTEA,
    secret_key_id    TEXT,
    events       TEXT[] NOT NULL,
    enabled      BOOLEAN DEFAULT true,
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhook_org ON governance.webhook_configs(org_id);

-- 8. Webhook deliveries
CREATE TABLE IF NOT EXISTS governance.webhook_deliveries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id   UUID NOT NULL REFERENCES governance.webhook_configs(id),
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER DEFAULT 0,
    last_attempt TIMESTAMPTZ,
    next_retry   TIMESTAMPTZ,
    response_code INTEGER,
    response_body TEXT,
    created_at   TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT delivery_status_check CHECK (status IN ('pending','delivered','failed','exhausted'))
);
CREATE INDEX IF NOT EXISTS idx_delivery_pending ON governance.webhook_deliveries(status, next_retry)
    WHERE status IN ('pending', 'failed');

-- 9. Retention records
CREATE TABLE IF NOT EXISTS governance.retention_records (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id  UUID NOT NULL,
    lifecycle    TEXT NOT NULL DEFAULT 'active',
    retention_days INTEGER NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    archived_at  TIMESTAMPTZ,
    purge_after  TIMESTAMPTZ,
    purged_at    TIMESTAMPTZ,
    legal_hold   BOOLEAN DEFAULT false,
    legal_hold_by UUID,
    legal_hold_reason TEXT,
    created_at   TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT lifecycle_check CHECK (lifecycle IN ('active','archived','purge_pending','purged'))
);
CREATE INDEX IF NOT EXISTS idx_retention_lifecycle ON governance.retention_records(lifecycle, expires_at);
CREATE INDEX IF NOT EXISTS idx_retention_legal_hold ON governance.retention_records(org_id) WHERE legal_hold = true;
CREATE UNIQUE INDEX IF NOT EXISTS idx_retention_resource ON governance.retention_records(resource_type, resource_id);

-- 10. Emergency stops
CREATE TABLE IF NOT EXISTS governance.emergency_stops (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES core.organizations(id),
    scope       TEXT NOT NULL,
    scope_id    UUID,
    reason      TEXT NOT NULL,
    activated_by UUID NOT NULL REFERENCES core.users(id),
    activated_at TIMESTAMPTZ DEFAULT now(),
    deactivated_by UUID,
    deactivated_at TIMESTAMPTZ,
    active      BOOLEAN DEFAULT true,
    CONSTRAINT scope_check CHECK (scope IN ('all','team','project','scan_job'))
);
CREATE INDEX IF NOT EXISTS idx_emergency_active ON governance.emergency_stops(org_id) WHERE active = true;

-- 11. RLS
ALTER TABLE governance.org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.finding_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.sla_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhook_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.retention_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.emergency_stops ENABLE ROW LEVEL SECURITY;

-- RLS policies
DO $$ BEGIN
CREATE POLICY org_isolation ON governance.org_settings
    USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY team_isolation ON governance.approval_requests
    USING (team_id IN (SELECT tm.team_id FROM core.team_memberships tm
           WHERE tm.user_id = current_setting('app.current_user_id')::uuid)
        OR (team_id IS NULL AND org_id = current_setting('app.current_org_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY team_isolation ON governance.finding_assignments
    USING (team_id IN (SELECT tm.team_id FROM core.team_memberships tm
           WHERE tm.user_id = current_setting('app.current_user_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY team_isolation ON governance.sla_violations
    USING (org_id IN (SELECT DISTINCT t.org_id FROM core.team_memberships tm
           JOIN core.teams t ON t.id = tm.team_id
           WHERE tm.user_id = current_setting('app.current_user_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY user_notifications ON governance.notifications
    USING (user_id = current_setting('app.current_user_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.webhook_configs
    USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.webhook_deliveries
    USING (webhook_id IN (SELECT id FROM governance.webhook_configs
           WHERE org_id = current_setting('app.current_org_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.retention_records
    USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.emergency_stops
    USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 12. Modify existing tables
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES core.organizations(id);
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS assigned_to UUID REFERENCES core.users(id);
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS sla_deadline TIMESTAMPTZ;
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN DEFAULT false;

ALTER TABLE scans.scan_jobs ADD COLUMN IF NOT EXISTS emergency_stopped BOOLEAN DEFAULT false;
ALTER TABLE scans.scan_jobs ADD COLUMN IF NOT EXISTS stopped_by UUID;
ALTER TABLE scans.scan_jobs ADD COLUMN IF NOT EXISTS stopped_reason TEXT;
