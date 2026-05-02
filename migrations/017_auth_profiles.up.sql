-- Chunk 2: Auth profile CRUD + encryption.
--
-- Extend auth.auth_configs with an encrypted secret payload column and a
-- plaintext description. The existing `config` jsonb column stores only
-- non-sensitive metadata (header names, token prefix, endpoint URL, username).
-- Sensitive values (bearer token, api key, password) live exclusively in
-- `encrypted_secret`, which is AES-256-GCM ciphertext keyed by
-- AUTH_PROFILE_ENCRYPTION_KEY. The API never returns either column.
--
-- Also widen the auth_type CHECK to include 'basic_auth', which Chunk 2
-- implements alongside bearer_token and api_key.

ALTER TABLE auth.auth_configs
    ADD COLUMN IF NOT EXISTS description      TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_secret BYTEA;

-- Drop the old CHECK and re-add it with basic_auth included.
ALTER TABLE auth.auth_configs DROP CONSTRAINT IF EXISTS auth_configs_auth_type_check;
ALTER TABLE auth.auth_configs
    ADD CONSTRAINT auth_configs_auth_type_check
    CHECK (auth_type IN (
        'bearer_token', 'api_key', 'basic_auth',
        'form_login', 'oauth2_client_credentials', 'oauth2_auth_code',
        'cookie', 'custom_header', 'scripted'
    ));

-- RLS: enforce project/org scoping via the project relationship.
ALTER TABLE auth.auth_configs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS auth_configs_isolation ON auth.auth_configs;
CREATE POLICY auth_configs_isolation ON auth.auth_configs
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

-- Helpful index for lookups by project.
CREATE INDEX IF NOT EXISTS idx_auth_configs_project_id ON auth.auth_configs(project_id);
