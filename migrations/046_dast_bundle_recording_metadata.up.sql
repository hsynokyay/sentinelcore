-- Recording-specific metadata (browser fingerprint, recorded-at, captcha
-- in flow, action count). Stored as JSONB to allow forward-compatible
-- field additions without schema changes. NULL for session_import bundles.
ALTER TABLE dast_auth_bundles
    ADD COLUMN recording_metadata JSONB;

CREATE INDEX dast_auth_bundles_recording
    ON dast_auth_bundles((recording_metadata->>'browser_user_agent'))
    WHERE type = 'recorded_login';
