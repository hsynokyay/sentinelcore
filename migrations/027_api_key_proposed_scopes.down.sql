BEGIN;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS proposed_scopes;
COMMIT;
