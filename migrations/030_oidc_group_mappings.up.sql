BEGIN;

CREATE TABLE auth.oidc_group_mappings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES auth.oidc_providers(id) ON DELETE CASCADE,
    group_claim TEXT NOT NULL,
    role_id     TEXT NOT NULL REFERENCES auth.roles(id),
    priority    INT NOT NULL DEFAULT 100,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider_id, group_claim),
    CONSTRAINT group_claim_len CHECK (length(group_claim) BETWEEN 1 AND 256),
    CONSTRAINT priority_range  CHECK (priority BETWEEN 1 AND 10000)
);

CREATE INDEX oidc_group_mappings_provider_prio_idx
    ON auth.oidc_group_mappings(provider_id, priority, role_id);

ALTER TABLE auth.oidc_group_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY oidc_group_mappings_isolation ON auth.oidc_group_mappings
    USING (provider_id IN (
        SELECT id FROM auth.oidc_providers
        WHERE org_id = current_setting('app.current_org_id', true)::uuid
    ));

COMMIT;
