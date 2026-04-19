DROP POLICY IF EXISTS auth_configs_isolation ON auth.auth_configs;
ALTER TABLE auth.auth_configs DISABLE ROW LEVEL SECURITY;
DROP INDEX IF EXISTS auth.idx_auth_configs_project_id;

ALTER TABLE auth.auth_configs DROP CONSTRAINT IF EXISTS auth_configs_auth_type_check;
ALTER TABLE auth.auth_configs
    ADD CONSTRAINT auth_configs_auth_type_check
    CHECK (auth_type IN (
        'form_login', 'oauth2_client_credentials', 'oauth2_auth_code',
        'api_key', 'bearer_token', 'cookie', 'custom_header', 'scripted'
    ));

ALTER TABLE auth.auth_configs
    DROP COLUMN IF EXISTS encrypted_secret,
    DROP COLUMN IF EXISTS description;
