-- Phase 3: Correlation Engine
-- Migration 013: Add correlation tables and enrichment columns

BEGIN;

-- Correlation groups link related findings across scan types
CREATE TABLE IF NOT EXISTS findings.correlation_groups (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id         UUID NOT NULL REFERENCES core.projects(id),
    primary_finding_id UUID NOT NULL REFERENCES findings.findings(id),
    correlation_score  NUMERIC(4,3) NOT NULL,
    confidence         VARCHAR(10) NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    risk_score         NUMERIC(4,2) NOT NULL,
    status             VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'superseded', 'dismissed')),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_correlation_groups_project ON findings.correlation_groups(project_id);
CREATE INDEX idx_correlation_groups_primary ON findings.correlation_groups(primary_finding_id);
CREATE INDEX idx_correlation_groups_confidence ON findings.correlation_groups(confidence);

-- Members of a correlation group
CREATE TABLE IF NOT EXISTS findings.correlation_members (
    group_id    UUID NOT NULL REFERENCES findings.correlation_groups(id) ON DELETE CASCADE,
    finding_id  UUID NOT NULL REFERENCES findings.findings(id),
    finding_type TEXT NOT NULL CHECK (finding_type IN ('sast', 'dast', 'sca', 'secret')),
    axis_scores JSONB NOT NULL,
    added_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, finding_id)
);

CREATE INDEX idx_correlation_members_finding ON findings.correlation_members(finding_id);

-- CWE hierarchy for parent/child matching
CREATE TABLE IF NOT EXISTS findings.cwe_hierarchy (
    cwe_id      INTEGER PRIMARY KEY,
    parent_id   INTEGER,
    category    VARCHAR(100),
    name        TEXT NOT NULL,
    description TEXT
);

-- Correlation run history for auditability
CREATE TABLE IF NOT EXISTS findings.correlation_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id     UUID NOT NULL,
    project_id      UUID NOT NULL,
    input_findings  INTEGER NOT NULL,
    deduplicated    INTEGER NOT NULL,
    correlated      INTEGER NOT NULL,
    new_groups      INTEGER NOT NULL DEFAULT 0,
    updated_groups  INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_correlation_runs_project ON findings.correlation_runs(project_id);
CREATE INDEX idx_correlation_runs_scan ON findings.correlation_runs(scan_job_id);

-- Add enrichment columns to findings
ALTER TABLE findings.findings
    ADD COLUMN IF NOT EXISTS related_cve_ids TEXT[],
    ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS actively_exploited BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS correlation_group_id UUID;

-- Add project+type composite index for efficient cross-correlation queries
CREATE INDEX IF NOT EXISTS idx_findings_project_type
    ON findings.findings(project_id, finding_type);

-- RLS
ALTER TABLE findings.correlation_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings.correlation_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings.correlation_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY correlation_groups_org_isolation ON findings.correlation_groups
    USING (project_id IN (
        SELECT p.id FROM core.projects p
        JOIN core.teams t ON p.team_id = t.id
        WHERE t.org_id = current_setting('app.current_org_id')::uuid
    ));

CREATE POLICY correlation_members_org_isolation ON findings.correlation_members
    USING (group_id IN (
        SELECT cg.id FROM findings.correlation_groups cg
        JOIN core.projects p ON cg.project_id = p.id
        JOIN core.teams t ON p.team_id = t.id
        WHERE t.org_id = current_setting('app.current_org_id')::uuid
    ));

CREATE POLICY correlation_runs_org_isolation ON findings.correlation_runs
    USING (project_id IN (
        SELECT p.id FROM core.projects p
        JOIN core.teams t ON p.team_id = t.id
        WHERE t.org_id = current_setting('app.current_org_id')::uuid
    ));

COMMIT;
