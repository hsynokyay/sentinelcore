BEGIN;

ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS is_service_account BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS description         TEXT,
    ADD COLUMN IF NOT EXISTS rotated_at          TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS created_by          UUID REFERENCES core.users(id);

-- Backfill created_by = user_id for pre-existing rows (every key today is
-- user-owned by definition; service accounts didn't exist yet).
UPDATE core.api_keys SET created_by = user_id WHERE created_by IS NULL;

-- Now make user_id nullable (needed for tenant-owned service accounts).
ALTER TABLE core.api_keys ALTER COLUMN user_id DROP NOT NULL;

-- Preserve invariant: either a user owns the key, or it's a service account.
-- A NULL user_id with is_service_account=false would be an orphaned key.
ALTER TABLE core.api_keys ADD CONSTRAINT api_keys_principal_check
    CHECK (user_id IS NOT NULL OR is_service_account = true);

-- created_by must always be set; never NULL even for tenant-owned keys
-- (we always record who issued them for audit).
ALTER TABLE core.api_keys ALTER COLUMN created_by SET NOT NULL;

COMMIT;
