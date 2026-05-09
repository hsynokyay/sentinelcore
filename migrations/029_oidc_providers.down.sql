BEGIN;
DROP TRIGGER IF EXISTS oidc_providers_set_updated_at ON auth.oidc_providers;
DROP INDEX IF EXISTS auth.oidc_providers_org_enabled_idx;
DROP TABLE IF EXISTS auth.oidc_providers CASCADE;
-- Leave set_updated_at() in place — future migrations may rely on it.
COMMIT;
