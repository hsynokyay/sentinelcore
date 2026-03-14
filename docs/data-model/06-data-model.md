# 6. Data Model

## 6.1 Database Architecture

SentinelCore uses PostgreSQL with **schema-level isolation** for domain separation and **row-level security (RLS)** for multi-team data access control.

### 6.1.1 Schema Layout

```
sentinelcore (database)
├── core           — Projects, teams, users, configuration
├── scans          — Scan jobs, scan history, worker state
├── findings       — Security findings, state transitions, annotations
├── evidence       — Evidence metadata (blobs in MinIO)
├── rules          — Detection rules, versions, categories
├── vuln_intel     — Vulnerability intelligence, CVEs, advisories
├── policies       — OPA policies, assignments, versions
├── audit          — Audit log entries, integrity chain
├── reports        — Report definitions, generated reports metadata
├── updates        — Update bundles, application history
├── auth           — Authentication configs, session metadata (no secrets)
└── cicd           — Pipeline configurations, webhook registrations
```

## 6.2 Core Schema

### 6.2.1 Organizations and Teams

```sql
CREATE TABLE core.organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE core.teams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES core.organizations(id),
    name            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE core.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES core.organizations(id),
    username        TEXT NOT NULL,
    email           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    identity_provider TEXT NOT NULL,        -- 'local', 'oidc', 'ldap', 'saml'
    external_id     TEXT,                   -- ID from external IdP
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled', 'locked')),
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, username)
);

CREATE TABLE core.team_memberships (
    team_id         UUID NOT NULL REFERENCES core.teams(id),
    user_id         UUID NOT NULL REFERENCES core.users(id),
    role            TEXT NOT NULL CHECK (role IN (
                        'team_admin', 'security_lead', 'analyst',
                        'developer', 'viewer')),
    granted_by      UUID NOT NULL REFERENCES core.users(id),
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
```

### 6.2.2 Projects

```sql
CREATE TABLE core.projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES core.organizations(id),
    team_id         UUID NOT NULL REFERENCES core.teams(id),
    name            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    description     TEXT,
    repository_url  TEXT,                   -- SCM repository URL
    default_branch  TEXT DEFAULT 'main',
    asset_criticality TEXT NOT NULL DEFAULT 'medium'
                    CHECK (asset_criticality IN ('critical', 'high', 'medium', 'low')),
    scan_config     JSONB NOT NULL DEFAULT '{}',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'archived', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- Scan targets approved for DAST scanning
CREATE TABLE core.scan_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    target_type     TEXT NOT NULL CHECK (target_type IN ('web_app', 'api', 'graphql')),
    base_url        TEXT NOT NULL,
    allowed_domains TEXT[] NOT NULL,         -- domain allowlist for scope enforcement
    allowed_paths   TEXT[],                  -- path prefix allowlist (optional)
    excluded_paths  TEXT[],                  -- path exclusion patterns
    allowed_ports   INTEGER[] NOT NULL DEFAULT '{80, 443}',
    max_rps         INTEGER NOT NULL DEFAULT 10,
    auth_config_id  UUID REFERENCES auth.auth_configs(id),
    verified_at     TIMESTAMPTZ,            -- when target ownership was last verified
    verified_by     UUID REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 6.3 Scans Schema

```sql
CREATE TABLE scans.scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    scan_type       TEXT NOT NULL CHECK (scan_type IN ('sast', 'dast', 'full')),
    scan_profile    TEXT NOT NULL DEFAULT 'standard'
                    CHECK (scan_profile IN ('passive', 'standard', 'aggressive')),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN (
                        'pending', 'scope_validating', 'dispatched', 'running',
                        'collecting', 'correlating', 'completed',
                        'failed', 'cancelled', 'timed_out')),
    trigger_type    TEXT NOT NULL CHECK (trigger_type IN (
                        'manual', 'scheduled', 'cicd', 'rescan', 'api')),
    trigger_source  JSONB,                  -- CI/CD metadata, schedule ref, etc.
    scan_target_id  UUID REFERENCES core.scan_targets(id),
    source_ref      JSONB,                  -- {commit_sha, branch, repo_url}
    config_override JSONB DEFAULT '{}',     -- per-scan config overrides
    worker_id       TEXT,                   -- assigned worker identifier
    progress        JSONB DEFAULT '{"phase": "pending", "percent": 0}',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    max_retries     INTEGER NOT NULL DEFAULT 2,
    timeout_seconds INTEGER NOT NULL DEFAULT 3600,
    created_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scan_jobs_project_status ON scans.scan_jobs(project_id, status);
CREATE INDEX idx_scan_jobs_status ON scans.scan_jobs(status) WHERE status NOT IN ('completed', 'failed', 'cancelled');

CREATE TABLE scans.scan_schedules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    scan_type       TEXT NOT NULL,
    scan_profile    TEXT NOT NULL DEFAULT 'standard',
    cron_expression TEXT NOT NULL,
    scan_target_id  UUID REFERENCES core.scan_targets(id),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 6.4 Findings Schema

```sql
CREATE TABLE findings.findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    scan_job_id     UUID NOT NULL REFERENCES scans.scan_jobs(id),
    finding_type    TEXT NOT NULL CHECK (finding_type IN ('sast', 'dast', 'sca', 'secret')),
    -- Identification
    fingerprint     TEXT NOT NULL,           -- stable hash for deduplication
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    -- Classification
    cwe_id          INTEGER,
    owasp_category  TEXT,
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence      TEXT NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
    -- Scoring
    cvss_score      NUMERIC(3,1),
    cvss_vector     TEXT,
    epss_score      NUMERIC(5,4),
    risk_score      NUMERIC(5,2),            -- composite risk score
    -- Location (SAST)
    file_path       TEXT,
    line_start      INTEGER,
    line_end        INTEGER,
    column_start    INTEGER,
    code_snippet    TEXT,
    -- Location (DAST)
    url             TEXT,
    http_method     TEXT,
    parameter       TEXT,
    -- SCA
    dependency_name TEXT,
    dependency_version TEXT,
    cve_ids         TEXT[],
    -- State
    status          TEXT NOT NULL DEFAULT 'new'
                    CHECK (status IN (
                        'new', 'confirmed', 'in_progress', 'mitigated',
                        'resolved', 'reopened', 'accepted_risk', 'false_positive')),
    -- Correlation
    correlated_finding_ids UUID[],
    correlation_confidence TEXT CHECK (correlation_confidence IN ('high', 'medium', 'low')),
    -- Metadata
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    scan_count      INTEGER NOT NULL DEFAULT 1,
    evidence_ref    TEXT,                    -- MinIO path to evidence
    rule_id         TEXT,                    -- rule that triggered this finding
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

-- Finding state transitions (immutable history)
CREATE TABLE findings.finding_state_transitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings.findings(id),
    from_status     TEXT NOT NULL,
    to_status       TEXT NOT NULL,
    reason          TEXT,
    changed_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Finding annotations by analysts
CREATE TABLE findings.finding_annotations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id      UUID NOT NULL REFERENCES findings.findings(id),
    author_id       UUID NOT NULL REFERENCES core.users(id),
    annotation_type TEXT NOT NULL CHECK (annotation_type IN (
                        'comment', 'triage_note', 'remediation_note', 'risk_acceptance')),
    content         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 6.5 Vulnerability Intelligence Schema

```sql
CREATE TABLE vuln_intel.vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          TEXT UNIQUE,
    source          TEXT NOT NULL CHECK (source IN ('nvd', 'osv', 'github', 'cisa_kev')),
    title           TEXT NOT NULL,
    description     TEXT,
    -- Scoring
    cvss_v31_score  NUMERIC(3,1),
    cvss_v31_vector TEXT,
    epss_score      NUMERIC(5,4),
    epss_percentile NUMERIC(5,4),
    -- Classification
    cwe_ids         INTEGER[],
    affected_products JSONB,                -- CPE entries or package identifiers
    -- Exploit intelligence
    exploit_available BOOLEAN NOT NULL DEFAULT false,
    exploit_sources  TEXT[],                -- references to known exploits
    actively_exploited BOOLEAN NOT NULL DEFAULT false, -- from CISA KEV
    -- Dates
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,
    kev_added_at    TIMESTAMPTZ,            -- when added to CISA KEV
    -- Metadata
    references      JSONB,
    raw_data        JSONB,                  -- original feed data for reference
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_vuln_cve ON vuln_intel.vulnerabilities(cve_id);
CREATE INDEX idx_vuln_source ON vuln_intel.vulnerabilities(source);
CREATE INDEX idx_vuln_exploited ON vuln_intel.vulnerabilities(actively_exploited)
    WHERE actively_exploited = true;

-- Package-to-CVE mapping for SCA correlation
CREATE TABLE vuln_intel.package_vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID NOT NULL REFERENCES vuln_intel.vulnerabilities(id),
    ecosystem       TEXT NOT NULL,           -- npm, pypi, maven, go, nuget, etc.
    package_name    TEXT NOT NULL,
    version_range   TEXT NOT NULL,           -- semver range of affected versions
    fixed_version   TEXT,                    -- first fixed version (if known)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_pkg_vuln_lookup ON vuln_intel.package_vulnerabilities(ecosystem, package_name);

-- Feed sync tracking
CREATE TABLE vuln_intel.feed_sync_status (
    feed_name       TEXT PRIMARY KEY,
    last_sync_at    TIMESTAMPTZ,
    last_sync_status TEXT NOT NULL DEFAULT 'never',
    records_synced  INTEGER DEFAULT 0,
    next_sync_at    TIMESTAMPTZ,
    error_message   TEXT
);
```

## 6.6 Audit Schema

```sql
CREATE TABLE audit.audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Actor
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'system', 'cicd')),
    actor_id        TEXT NOT NULL,
    actor_ip        INET,
    -- Action
    action          TEXT NOT NULL,           -- e.g., 'scan.created', 'finding.triaged'
    resource_type   TEXT NOT NULL,           -- e.g., 'scan_job', 'finding', 'policy'
    resource_id     TEXT NOT NULL,
    -- Context
    org_id          UUID,
    team_id         UUID,
    project_id      UUID,
    -- Details
    details         JSONB,                  -- action-specific metadata
    result          TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    -- Integrity
    previous_hash   TEXT NOT NULL,           -- hash of previous entry (chain)
    entry_hash      TEXT NOT NULL            -- HMAC-SHA256 of this entry
) PARTITION BY RANGE (timestamp);

-- Create monthly partitions (managed by pg_partman or manual DDL)
-- Partitions enable efficient retention management and query performance

CREATE INDEX idx_audit_timestamp ON audit.audit_log(timestamp);
CREATE INDEX idx_audit_actor ON audit.audit_log(actor_id, timestamp);
CREATE INDEX idx_audit_resource ON audit.audit_log(resource_type, resource_id, timestamp);
CREATE INDEX idx_audit_action ON audit.audit_log(action, timestamp);
```

## 6.7 Rules Schema

```sql
CREATE TABLE rules.rule_sets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    version         TEXT NOT NULL,           -- semver
    source          TEXT NOT NULL CHECK (source IN ('builtin', 'vendor', 'custom')),
    engine_type     TEXT NOT NULL CHECK (engine_type IN ('sast', 'dast')),
    description     TEXT,
    checksum        TEXT NOT NULL,           -- SHA-256 of rule set content
    signature       TEXT,                    -- Ed25519 signature (for vendor rules)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE rules.rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_set_id     UUID NOT NULL REFERENCES rules.rule_sets(id),
    rule_id         TEXT NOT NULL,           -- stable rule identifier (e.g., 'SQLI-001')
    engine_type     TEXT NOT NULL CHECK (engine_type IN ('sast', 'dast')),
    -- Classification
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    cwe_id          INTEGER,
    owasp_category  TEXT,
    -- Rule definition
    language        TEXT,                    -- for SAST: target language (null = all)
    rule_definition JSONB NOT NULL,          -- engine-specific rule content
    -- Metadata
    enabled         BOOLEAN NOT NULL DEFAULT true,
    tags            TEXT[] DEFAULT '{}',
    references      TEXT[],
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (rule_set_id, rule_id)
);
```

## 6.8 Policies Schema

```sql
CREATE TABLE policies.policy_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    version         INTEGER NOT NULL DEFAULT 1,
    policy_type     TEXT NOT NULL CHECK (policy_type IN (
                        'access', 'scan', 'gate', 'data', 'network')),
    rego_source     TEXT NOT NULL,           -- OPA Rego policy source
    description     TEXT,
    is_system       BOOLEAN NOT NULL DEFAULT false, -- system policies cannot be deleted
    created_by      UUID REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policies.policy_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies.policy_definitions(id),
    scope_type      TEXT NOT NULL CHECK (scope_type IN ('org', 'team', 'project')),
    scope_id        UUID NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    assigned_by     UUID NOT NULL REFERENCES core.users(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 6.9 Auth Schema

```sql
CREATE TABLE auth.auth_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    name            TEXT NOT NULL,
    auth_type       TEXT NOT NULL CHECK (auth_type IN (
                        'form_login', 'oauth2_client_credentials', 'oauth2_auth_code',
                        'api_key', 'bearer_token', 'cookie', 'custom_header', 'scripted')),
    config          JSONB NOT NULL,          -- auth-type-specific config (no secrets)
    vault_secret_path TEXT NOT NULL,         -- path in Vault where credentials are stored
    session_ttl     INTEGER NOT NULL DEFAULT 3600,
    created_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 6.10 Entity Relationship Summary

```
Organization 1──N Teams 1──N Projects 1──N Scan Targets
                    │                    │
                    N                    N
                    │                    │
              Team Memberships      Scan Jobs 1──N Findings
              (Users × Roles)            │            │
                                         │            N
                                         │      State Transitions
                                         │      Annotations
                                         │
                                    Evidence (MinIO)

Policy Definitions ──N Policy Assignments ──► (Org | Team | Project)

Rule Sets 1──N Rules ──► (used by SAST/DAST Workers)

Vulnerabilities 1──N Package Vulnerabilities ──► (correlated with SCA Findings)
```

## 6.11 Row-Level Security

All tables in the `findings`, `scans`, and `core` schemas enforce RLS policies:

```sql
-- Example: findings are only visible to users who are members of the owning team
ALTER TABLE findings.findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY findings_team_access ON findings.findings
    USING (
        project_id IN (
            SELECT p.id FROM core.projects p
            JOIN core.team_memberships tm ON tm.team_id = p.team_id
            WHERE tm.user_id = current_setting('app.current_user_id')::UUID
        )
    );
```

Each API request sets session variables (`app.current_user_id`, `app.current_org_id`) before executing queries, ensuring database-level access control independent of application logic.

## 6.12 Data Retention

| Data Type | Default Retention | Configurable |
|---|---|---|
| Scan results & findings | 2 years | Yes |
| Evidence artifacts | 1 year | Yes |
| Audit logs | 7 years | Yes (minimum 1 year) |
| Vulnerability intelligence | Indefinite (updated in place) | No |
| Reports | 2 years | Yes |
| Scan job metadata | 2 years | Yes |
