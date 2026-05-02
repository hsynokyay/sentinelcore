-- Chunk 3: SAST source/artifact intake.
--
-- `scans.source_artifacts` stores metadata for source code bundles uploaded by
-- operators for SAST scans. The actual archive bytes live under
-- /app/artifacts/<id>.zip (bound to /opt/sentinelcore/data/artifacts on the
-- host). The API layer never returns the raw bytes — only metadata and a
-- reference ID the scan worker uses to locate the file.

CREATE TABLE IF NOT EXISTS scans.source_artifacts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    description      TEXT,
    format           TEXT NOT NULL CHECK (format IN ('zip')),
    storage_path     TEXT NOT NULL,
    size_bytes       BIGINT NOT NULL CHECK (size_bytes > 0),
    sha256_hex       TEXT NOT NULL,
    entry_count      INTEGER NOT NULL CHECK (entry_count >= 0),
    uncompressed_size BIGINT NOT NULL CHECK (uncompressed_size >= 0),
    uploaded_by      UUID NOT NULL REFERENCES core.users(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_source_artifacts_project ON scans.source_artifacts(project_id, created_at DESC);

-- RLS: org isolation via project relationship.
ALTER TABLE scans.source_artifacts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS source_artifacts_isolation ON scans.source_artifacts;
CREATE POLICY source_artifacts_isolation ON scans.source_artifacts
    USING (
        project_id IN (
            SELECT id FROM core.projects
             WHERE org_id = current_setting('app.org_id', true)::uuid
        )
    )
    WITH CHECK (
        project_id IN (
            SELECT id FROM core.projects
             WHERE org_id = current_setting('app.org_id', true)::uuid
        )
    );
