-- Phase 2: API-First DAST & Orchestration Expansion
-- Migration 002: Add DAST-related tables and schema changes

BEGIN;

-- Auth session tracking for DAST scans
CREATE TABLE IF NOT EXISTS auth.auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES scans.scan_jobs(id),
    strategy VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    refreshed_at TIMESTAMPTZ,
    metadata JSONB,
    CONSTRAINT auth_sessions_strategy_check
        CHECK (strategy IN ('bearer', 'oauth2_cc', 'form_login', 'api_key', 'scripted')),
    CONSTRAINT auth_sessions_status_check
        CHECK (status IN ('active', 'expired', 'revoked'))
);

CREATE INDEX idx_auth_sessions_scan_job ON auth.auth_sessions(scan_job_id);
CREATE INDEX idx_auth_sessions_status ON auth.auth_sessions(status) WHERE status = 'active';

-- Scan progress checkpoints for crash recovery
CREATE TABLE IF NOT EXISTS scans.scan_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id UUID NOT NULL REFERENCES scans.scan_jobs(id),
    worker_id VARCHAR(255) NOT NULL,
    checkpoint_data JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(scan_job_id, worker_id)
);

CREATE INDEX idx_scan_checkpoints_job ON scans.scan_checkpoints(scan_job_id);

-- Worker registration for result signing verification
CREATE TABLE IF NOT EXISTS scans.worker_registrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    worker_id VARCHAR(255) NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now(),
    worker_type VARCHAR(20) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    CONSTRAINT worker_type_check
        CHECK (worker_type IN ('sast', 'dast')),
    CONSTRAINT worker_status_check
        CHECK (status IN ('active', 'inactive', 'deregistered'))
);

CREATE INDEX idx_worker_registrations_type ON scans.worker_registrations(worker_type);
CREATE INDEX idx_worker_registrations_status ON scans.worker_registrations(status) WHERE status = 'active';

-- Add DAST-related columns to scan_jobs
ALTER TABLE scans.scan_jobs
    ADD COLUMN IF NOT EXISTS scope_document JSONB,
    ADD COLUMN IF NOT EXISTS pinned_ips TEXT[],
    ADD COLUMN IF NOT EXISTS scan_type VARCHAR(20) DEFAULT 'sast';

-- Add constraint for scan_type
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'scan_jobs_scan_type_check'
    ) THEN
        ALTER TABLE scans.scan_jobs
            ADD CONSTRAINT scan_jobs_scan_type_check
            CHECK (scan_type IN ('sast', 'dast', 'combined'));
    END IF;
END $$;

-- Add DAST-related columns to scan_targets
ALTER TABLE scans.scan_targets
    ADD COLUMN IF NOT EXISTS openapi_spec_ref TEXT,
    ADD COLUMN IF NOT EXISTS auth_config_id UUID;

-- RLS policies for new tables
ALTER TABLE auth.auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans.scan_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans.worker_registrations ENABLE ROW LEVEL SECURITY;

COMMIT;
