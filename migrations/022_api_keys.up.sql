-- Platform Hardening: API keys for CI/CD automation.
--
-- API keys are scoped service tokens that let CI pipelines authenticate
-- without storing user passwords. Each key is hashed at rest (SHA-256);
-- the plaintext is shown exactly once at creation time.

CREATE TABLE IF NOT EXISTS core.api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES core.organizations(id),
    user_id     UUID NOT NULL REFERENCES core.users(id),
    name        TEXT NOT NULL,
    prefix      TEXT NOT NULL,       -- first 8 chars, for display
    key_hash    TEXT NOT NULL UNIQUE, -- SHA-256 of the full key
    scopes      TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    revoked     BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON core.api_keys(key_hash) WHERE revoked = false;
CREATE INDEX IF NOT EXISTS idx_api_keys_org ON core.api_keys(org_id);

-- RLS.
ALTER TABLE core.api_keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY api_keys_isolation ON core.api_keys
    USING (org_id = current_setting('app.org_id', true)::uuid);
