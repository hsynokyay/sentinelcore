CREATE TABLE findings.findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    scan_job_id     UUID NOT NULL REFERENCES scans.scan_jobs(id),
    finding_type    TEXT NOT NULL CHECK (finding_type IN ('sast', 'dast', 'sca', 'secret')),
    fingerprint     TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    cwe_id          INTEGER,
    owasp_category  TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence      TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    cvss_score      NUMERIC(3,1),
    cvss_vector     TEXT,
    epss_score      NUMERIC(5,4),
    risk_score      NUMERIC(5,2),
    file_path       TEXT,
    line_start      INTEGER,
    line_end        INTEGER,
    column_start    INTEGER,
    code_snippet    TEXT,
    url             TEXT,
    http_method     TEXT,
    parameter       TEXT,
    dependency_name TEXT,
    dependency_version TEXT,
    cve_ids         TEXT[],
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN (
                        'new', 'confirmed', 'in_progress', 'mitigated',
                        'resolved', 'reopened', 'accepted_risk', 'false_positive')),
    correlated_finding_ids UUID[],
    correlation_confidence TEXT CHECK (correlation_confidence IN ('high', 'medium', 'low')),
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    scan_count      INTEGER NOT NULL DEFAULT 1,
    evidence_ref    TEXT,
    evidence_hash   TEXT,
    evidence_size   BIGINT,
    rule_id         TEXT,
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_project ON findings.findings(project_id);
CREATE INDEX idx_findings_fingerprint ON findings.findings(fingerprint);
CREATE INDEX idx_findings_cwe ON findings.findings(cwe_id);
CREATE INDEX idx_findings_severity ON findings.findings(severity);
CREATE INDEX idx_findings_status ON findings.findings(status);
CREATE INDEX idx_findings_dependency ON findings.findings(dependency_name, dependency_version)
    WHERE finding_type = 'sca';

CREATE TABLE findings.finding_state_transitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings.findings(id),
    from_status     TEXT NOT NULL,
    to_status       TEXT NOT NULL,
    reason          TEXT,
    changed_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings.finding_annotations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings.findings(id),
    author_id       UUID NOT NULL REFERENCES core.users(id),
    annotation_type TEXT NOT NULL CHECK (annotation_type IN (
                        'comment', 'triage_note', 'remediation_note', 'risk_acceptance')),
    content         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
