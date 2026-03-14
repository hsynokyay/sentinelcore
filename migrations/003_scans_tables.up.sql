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
    trigger_source  JSONB,
    scan_target_id  UUID REFERENCES core.scan_targets(id),
    source_ref      JSONB,
    config_override JSONB DEFAULT '{}',
    worker_id       TEXT,
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
