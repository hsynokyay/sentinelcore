-- WARNING: this rollback removes the columns. If any tenant-owned
-- service-account keys exist (user_id IS NULL), the down migration
-- will fail at the NOT NULL constraint restore.

BEGIN;

-- Refuse to drop user_id's NOT NULL restoration if tenant-owned keys exist.
DO $$
DECLARE
    orphan_count INT;
BEGIN
    SELECT count(*) INTO orphan_count
    FROM core.api_keys WHERE user_id IS NULL;
    IF orphan_count > 0 THEN
        RAISE EXCEPTION
            'Refusing to rollback: % tenant-owned service-account keys would be orphaned. '
            'Delete or reassign them before rolling back.', orphan_count;
    END IF;
END $$;

ALTER TABLE core.api_keys DROP CONSTRAINT IF EXISTS api_keys_principal_check;
ALTER TABLE core.api_keys ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS created_by;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS rotated_at;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS description;
ALTER TABLE core.api_keys DROP COLUMN IF EXISTS is_service_account;

COMMIT;
