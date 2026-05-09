BEGIN;

-- Phase 9 §4.2: active SLA tracking. Replaces the post-hoc
-- governance.sla_violations breach log (kept for backward compat)
-- with per-finding live deadlines driven by per-org + per-project
-- policies.
--
-- The original sla_violations table stays in place for now; the
-- sla-sweep worker writes BOTH rows for the transition window, then
-- a follow-up migration can drop sla_violations once all readers
-- are on sla_deadlines.

CREATE TABLE governance.sla_policies (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES core.organizations(id),
    project_id       UUID REFERENCES core.projects(id),     -- NULL = org default
    severity         TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    remediation_days INTEGER NOT NULL CHECK (remediation_days > 0),
    warn_days_before INTEGER NOT NULL DEFAULT 7 CHECK (warn_days_before >= 0),
    escalate_after_hours INTEGER CHECK (escalate_after_hours IS NULL OR escalate_after_hours > 0),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, project_id, severity)
);
CREATE INDEX idx_sla_policies_org ON governance.sla_policies(org_id);

-- Per-finding active deadline. Inserted once at finding creation;
-- deadline_at updates on severity change; resolved_at / breached_at
-- set by the sweep.
CREATE TABLE governance.sla_deadlines (
    finding_id   UUID PRIMARY KEY REFERENCES findings.findings(id) ON DELETE CASCADE,
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    project_id   UUID NOT NULL REFERENCES core.projects(id),
    severity     TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    policy_id    UUID NOT NULL REFERENCES governance.sla_policies(id),
    deadline_at  TIMESTAMPTZ NOT NULL,
    warn_at      TIMESTAMPTZ NOT NULL,
    resolved_at  TIMESTAMPTZ,
    breached_at  TIMESTAMPTZ,
    escalated_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sla_deadlines_unresolved
    ON governance.sla_deadlines(deadline_at)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_sla_deadlines_project ON governance.sla_deadlines(project_id);

-- Append-only on resolved_at + breached_at: once a sweep sets either,
-- it cannot be cleared. Protects the compliance trail.
CREATE OR REPLACE FUNCTION governance.sla_deadlines_restrict()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF OLD.finding_id IS DISTINCT FROM NEW.finding_id THEN
        RAISE EXCEPTION 'sla_deadlines.finding_id immutable'
            USING ERRCODE='insufficient_privilege';
    END IF;
    IF OLD.org_id IS DISTINCT FROM NEW.org_id THEN
        RAISE EXCEPTION 'sla_deadlines.org_id immutable'
            USING ERRCODE='insufficient_privilege';
    END IF;
    IF OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS NULL THEN
        RAISE EXCEPTION 'sla_deadlines.resolved_at cannot be cleared'
            USING ERRCODE='insufficient_privilege';
    END IF;
    IF OLD.breached_at IS NOT NULL AND NEW.breached_at IS NULL THEN
        RAISE EXCEPTION 'sla_deadlines.breached_at cannot be cleared'
            USING ERRCODE='insufficient_privilege';
    END IF;
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS sla_deadlines_guard ON governance.sla_deadlines;
CREATE TRIGGER sla_deadlines_guard
    BEFORE UPDATE ON governance.sla_deadlines
    FOR EACH ROW EXECUTE FUNCTION governance.sla_deadlines_restrict();

-- RLS
ALTER TABLE governance.sla_policies  ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.sla_deadlines ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    CREATE POLICY org_isolation ON governance.sla_policies
        USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE POLICY org_isolation ON governance.sla_deadlines
        USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

COMMIT;
