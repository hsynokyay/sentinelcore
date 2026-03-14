CREATE TABLE auth.auth_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    name            TEXT NOT NULL,
    auth_type       TEXT NOT NULL CHECK (auth_type IN (
                        'form_login', 'oauth2_client_credentials', 'oauth2_auth_code',
                        'api_key', 'bearer_token', 'cookie', 'custom_header', 'scripted')),
    config          JSONB NOT NULL,
    vault_secret_path TEXT,
    session_ttl     INTEGER NOT NULL DEFAULT 3600,
    created_by      UUID NOT NULL REFERENCES core.users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
