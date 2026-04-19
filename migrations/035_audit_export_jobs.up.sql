BEGIN;

-- Record of every audit export request. Required for compliance even
-- when the export itself is served inline (sync path); the row captures
-- WHO requested WHAT WHEN, linking to the audit_log entry that records
-- the same action.
--
-- Async execution (MinIO artifact + GPG encryption) is staged — the
-- status enum already carries 'queued' and 'running' but until the
-- audit-worker grows a job-executor goroutine and MinIO is wired in,
-- the write path goes queued → succeeded with object_key=NULL to
-- indicate the artifact was streamed inline.
CREATE TABLE audit.export_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    requested_by    TEXT NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    filters         JSONB NOT NULL,
    format          TEXT NOT NULL CHECK (format IN ('csv','ndjson')),
    encrypt_gpg     BOOLEAN NOT NULL DEFAULT false,
    gpg_recipient   TEXT,
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','succeeded','failed','expired')),
    progress_rows   BIGINT NOT NULL DEFAULT 0,
    total_rows      BIGINT,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    delivered_inline BOOLEAN NOT NULL DEFAULT false,   -- true when served sync
    object_key      TEXT,                               -- MinIO path, null if inline
    sha256          TEXT,                               -- hex, optional
    size_bytes      BIGINT,
    error_message   TEXT,
    expires_at      TIMESTAMPTZ,
    CONSTRAINT gpg_recipient_requires_encrypt
        CHECK (NOT encrypt_gpg OR gpg_recipient IS NOT NULL)
);

CREATE INDEX export_jobs_org_status_idx
    ON audit.export_jobs(org_id, status, requested_at DESC);

CREATE INDEX export_jobs_requested_by_idx
    ON audit.export_jobs(requested_by, requested_at DESC);

ALTER TABLE audit.export_jobs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS export_jobs_tenant ON audit.export_jobs;
CREATE POLICY export_jobs_tenant ON audit.export_jobs
    FOR ALL
    USING (org_id::text = current_setting('app.current_org_id', true))
    WITH CHECK (org_id::text = current_setting('app.current_org_id', true));

-- export_jobs is an operational table (status progresses queued→running→
-- succeeded), so it's intentionally NOT bound to audit.prevent_mutation.
-- Compliance-relevant transitions are themselves audited via
-- audit.export.requested / audit.export.downloaded emitted at the API
-- layer.

-- Permission catalog additions. Handlers gate on these; any role that
-- should see the export surface must be granted audit.export.
-- audit.verify gates the future /api/v1/audit/integrity endpoint.
INSERT INTO auth.permissions (id, description, category)
VALUES
    ('audit.export', 'Create and list audit exports',                    'audit'),
    ('audit.verify', 'Inspect audit chain integrity verification runs',  'audit')
ON CONFLICT (id) DO NOTHING;

-- Grant audit.export + audit.verify to the roles that already have
-- audit.read — owner, admin, auditor — so existing admin users can
-- exercise the new surface without a role edit.
INSERT INTO auth.role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM auth.roles r, auth.permissions p
WHERE r.id IN ('owner','admin','auditor')
  AND p.id IN ('audit.export','audit.verify')
ON CONFLICT DO NOTHING;

-- pg_notify so the RBAC cache in controlplane reloads without a restart.
SELECT pg_notify('role_permissions_changed', 'audit-phase6');

COMMIT;

