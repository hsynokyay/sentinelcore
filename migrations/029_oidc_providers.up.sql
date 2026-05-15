BEGIN;

-- Generic updated_at helper used by this migration and (hopefully) future ones.
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $fn$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$fn$ LANGUAGE plpgsql;

CREATE TABLE auth.oidc_providers (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    provider_slug      TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    issuer_url         TEXT NOT NULL,
    client_id          TEXT NOT NULL,
    client_secret      TEXT NOT NULL,
    scopes             TEXT[] NOT NULL DEFAULT ARRAY['openid','email','profile','groups'],
    default_role_id    TEXT NOT NULL REFERENCES auth.roles(id),
    sync_role_on_login BOOLEAN NOT NULL DEFAULT true,
    sso_logout_enabled BOOLEAN NOT NULL DEFAULT false,
    end_session_url    TEXT,
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, provider_slug),
    CONSTRAINT provider_slug_format CHECK (provider_slug ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' AND length(provider_slug) BETWEEN 1 AND 64),
    CONSTRAINT issuer_url_https CHECK (
        issuer_url ~ '^https://' OR
        issuer_url ~ '^http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/|$)'
    )
);

CREATE INDEX oidc_providers_org_enabled_idx
    ON auth.oidc_providers(org_id, enabled) WHERE enabled = true;

ALTER TABLE auth.oidc_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_providers_isolation ON auth.oidc_providers
    USING (org_id = current_setting('app.current_org_id', true)::uuid);

CREATE TRIGGER oidc_providers_set_updated_at
    BEFORE UPDATE ON auth.oidc_providers
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

COMMIT;
