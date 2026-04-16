BEGIN;
ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS proposed_scopes TEXT[];
COMMENT ON COLUMN core.api_keys.proposed_scopes IS
    'Backfill staging: scopes the rolling backfill will assign to pre-existing '
    'keys that currently have empty scopes. NULL for keys not eligible for backfill '
    '(already have explicit scopes) or already migrated. Column is dropped in migration 029 '
    'once backfill is complete and tenants have had 30 days to react.';
COMMIT;
