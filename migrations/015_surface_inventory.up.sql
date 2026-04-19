-- migrations/015_surface_inventory.up.sql
-- Phase 6: Attack surface inventory persistence

CREATE TABLE IF NOT EXISTS scans.surface_entries (
    id              TEXT PRIMARY KEY,          -- deterministic fingerprint (16 hex chars)
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    scan_job_id     UUID NOT NULL,
    surface_type    TEXT NOT NULL,             -- route, form, api_endpoint, clickable
    url             TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'GET',
    exposure        TEXT NOT NULL DEFAULT 'unknown', -- public, authenticated, both, unknown
    title           TEXT,
    metadata        JSONB DEFAULT '{}',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    scan_count      INTEGER NOT NULL DEFAULT 1,
    finding_ids     TEXT[] DEFAULT '{}',
    observation_count INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT surface_type_check CHECK (surface_type IN ('route', 'form', 'api_endpoint', 'clickable')),
    CONSTRAINT exposure_check CHECK (exposure IN ('public', 'authenticated', 'both', 'unknown'))
);

CREATE INDEX IF NOT EXISTS idx_surface_project ON scans.surface_entries(project_id);
CREATE INDEX IF NOT EXISTS idx_surface_type ON scans.surface_entries(surface_type);
CREATE INDEX IF NOT EXISTS idx_surface_exposure ON scans.surface_entries(exposure);
CREATE INDEX IF NOT EXISTS idx_surface_url ON scans.surface_entries(url);

-- RLS
ALTER TABLE scans.surface_entries ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
CREATE POLICY project_isolation ON scans.surface_entries
    USING (project_id IN (
        SELECT p.id FROM core.projects p
        JOIN core.teams t ON t.id = p.team_id
        JOIN core.team_memberships tm ON tm.team_id = t.id
        WHERE tm.user_id = current_setting('app.current_user_id')::uuid
    ));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
