-- Risk Correlation MVP: risk.* schema, findings.function_name column
-- See docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md §4

CREATE SCHEMA IF NOT EXISTS risk;

-- ---------------------------------------------------------------------------
-- risk.correlation_runs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.correlation_runs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    trigger              TEXT NOT NULL,
    triggered_by_scan    UUID,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at          TIMESTAMPTZ,
    status               TEXT NOT NULL DEFAULT 'running',
    error_message        TEXT,
    clusters_touched     INTEGER NOT NULL DEFAULT 0,
    clusters_created     INTEGER NOT NULL DEFAULT 0,
    clusters_resolved    INTEGER NOT NULL DEFAULT 0,
    findings_processed   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_risk_runs_project
    ON risk.correlation_runs(project_id, started_at DESC);
ALTER TABLE risk.correlation_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS correlation_runs_isolation ON risk.correlation_runs;
CREATE POLICY correlation_runs_isolation ON risk.correlation_runs
    USING (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.clusters
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.clusters (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    fingerprint          TEXT NOT NULL,
    fingerprint_version  SMALLINT NOT NULL DEFAULT 1,
    fingerprint_kind     TEXT NOT NULL,
    title                TEXT NOT NULL,
    vuln_class           TEXT NOT NULL,
    cwe_id               INTEGER,
    owasp_category       TEXT,
    language             TEXT,
    canonical_route      TEXT,
    canonical_param      TEXT,
    http_method          TEXT,
    file_path            TEXT,
    enclosing_method     TEXT,
    location_group       TEXT,
    severity             TEXT NOT NULL,
    risk_score           INTEGER NOT NULL DEFAULT 0
        CHECK (risk_score BETWEEN 0 AND 100),
    exposure             TEXT NOT NULL DEFAULT 'unknown',
    status               TEXT NOT NULL DEFAULT 'active',
    missing_run_count    INTEGER NOT NULL DEFAULT 0,
    finding_count        INTEGER NOT NULL DEFAULT 0,
    surface_count        INTEGER NOT NULL DEFAULT 0,
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_id          UUID REFERENCES risk.correlation_runs(id) ON DELETE SET NULL,
    resolved_at          TIMESTAMPTZ,
    resolved_by          UUID REFERENCES core.users(id) ON DELETE SET NULL,
    resolution_reason    TEXT,
    muted_until          TIMESTAMPTZ,
    CONSTRAINT clusters_project_fp_unique
        UNIQUE (project_id, fingerprint_version, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_risk_clusters_project_score
    ON risk.clusters(project_id, risk_score DESC, status);
CREATE INDEX IF NOT EXISTS idx_risk_clusters_vuln_class
    ON risk.clusters(project_id, vuln_class);
CREATE INDEX IF NOT EXISTS idx_risk_clusters_status
    ON risk.clusters(project_id, status);

ALTER TABLE risk.clusters ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS clusters_isolation ON risk.clusters;
CREATE POLICY clusters_isolation ON risk.clusters
    USING (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.cluster_findings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.cluster_findings (
    cluster_id           UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    finding_id           UUID NOT NULL REFERENCES findings.findings(id) ON DELETE CASCADE,
    role                 TEXT NOT NULL,
    first_seen_run_id    UUID REFERENCES risk.correlation_runs(id) ON DELETE SET NULL,
    last_seen_run_id     UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    added_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_cluster_findings_finding
    ON risk.cluster_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_cluster_findings_last_seen_run
    ON risk.cluster_findings(last_seen_run_id);

ALTER TABLE risk.cluster_findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cluster_findings_isolation ON risk.cluster_findings;
CREATE POLICY cluster_findings_isolation ON risk.cluster_findings
    USING (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.cluster_evidence
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.cluster_evidence (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id           UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    category             TEXT NOT NULL
        CHECK (category IN ('score_base', 'score_boost', 'score_penalty', 'link', 'context')),
    code                 TEXT NOT NULL,
    label                TEXT NOT NULL,
    weight               INTEGER,
    ref_type             TEXT,
    ref_id               TEXT,
    sort_order           INTEGER NOT NULL DEFAULT 0,
    source_run_id        UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cluster_evidence_cluster
    ON risk.cluster_evidence(cluster_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_cluster_evidence_run
    ON risk.cluster_evidence(source_run_id);

ALTER TABLE risk.cluster_evidence ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cluster_evidence_isolation ON risk.cluster_evidence;
CREATE POLICY cluster_evidence_isolation ON risk.cluster_evidence
    USING (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.cluster_relations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.cluster_relations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    source_cluster_id    UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    target_cluster_id    UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    relation_type        TEXT NOT NULL
        CHECK (relation_type IN ('runtime_confirmation', 'same_cwe', 'related_surface')),
    confidence           NUMERIC(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    rationale            TEXT NOT NULL,
    first_linked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_linked_run_id   UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    CONSTRAINT no_self_relation CHECK (source_cluster_id <> target_cluster_id),
    UNIQUE (source_cluster_id, target_cluster_id, relation_type)
);
CREATE INDEX IF NOT EXISTS idx_cluster_relations_source
    ON risk.cluster_relations(source_cluster_id);
CREATE INDEX IF NOT EXISTS idx_cluster_relations_target
    ON risk.cluster_relations(target_cluster_id);
CREATE INDEX IF NOT EXISTS idx_cluster_relations_project
    ON risk.cluster_relations(project_id, relation_type);

ALTER TABLE risk.cluster_relations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cluster_relations_isolation ON risk.cluster_relations;
CREATE POLICY cluster_relations_isolation ON risk.cluster_relations
    USING (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- findings.function_name: enables SAST location_group "m:" branch
-- ---------------------------------------------------------------------------
ALTER TABLE findings.findings
    ADD COLUMN IF NOT EXISTS function_name TEXT;
