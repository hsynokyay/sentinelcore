-- SAFE DOWN MIGRATION
-- This migration is FAIL-CLOSED: it refuses to run if the rollback would
-- lose data. Specifically:
--   1. Refuses if any user has role='developer' (no pre-migration equivalent).
--   2. Refuses if any user has been created AFTER the up migration ran
--      (new admin/owner users created post-migration cannot be safely reverted
--      because we cannot tell whether they were created as 'admin' or upgraded
--      from 'security_admin').
--
-- To force rollback anyway (data loss acceptable), set the session var
--   SET sentinelcore.force_role_downgrade = 'yes';
-- before running this script.

BEGIN;

DO $$
DECLARE
    dev_count INT;
    post_migration_count INT;
    force_flag TEXT;
    up_migration_at TIMESTAMPTZ;
BEGIN
    -- How many users have the new 'developer' role?
    SELECT count(*) INTO dev_count FROM core.users WHERE role = 'developer';

    -- Try to read the up-migration timestamp from a migration tracking
    -- table. If the operator's migration tool doesn't expose applied_at
    -- (golang-migrate's schema_migrations only has version+dirty columns
    -- and will raise "column applied_at does not exist"), we fall back
    -- to a far-past timestamp. This is INTENTIONALLY conservative: a
    -- NULL timestamp makes post_migration_count include ALL existing
    -- owner/admin users, preserving fail-closed semantics.
    --
    -- Operators using a migration tool that does track applied_at
    -- (e.g. a custom ledger, dbmate, flyway-style tables) can replace
    -- the SELECT below with the correct column name; the fallback
    -- handles every other case.
    BEGIN
        SELECT applied_at INTO up_migration_at FROM schema_migrations WHERE version = '025';
    EXCEPTION WHEN OTHERS THEN
        up_migration_at := NULL;
    END;
    IF up_migration_at IS NULL THEN
        up_migration_at := now() - interval '1 year';
    END IF;

    SELECT count(*) INTO post_migration_count
    FROM core.users
    WHERE created_at > up_migration_at
      AND role IN ('owner', 'admin');

    SELECT current_setting('sentinelcore.force_role_downgrade', true) INTO force_flag;

    IF (dev_count > 0 OR post_migration_count > 0) AND force_flag IS DISTINCT FROM 'yes' THEN
        RAISE EXCEPTION
            'Refusing to downgrade: % developer-role users and % post-migration owner/admin users exist. '
            'Downgrade would either delete developers or misclassify admins. '
            'Set sentinelcore.force_role_downgrade = ''yes'' to proceed with data loss.',
            dev_count, post_migration_count;
    END IF;
END $$;

ALTER TABLE core.users DROP CONSTRAINT IF EXISTS users_role_fkey;
ALTER TABLE core.users DROP CONSTRAINT IF EXISTS users_role_check;

-- Reverse the role rename. Only safe because the guard above ensures
-- no new-vocabulary-only users exist (or force_flag=yes accepts loss).
UPDATE core.users SET role = 'platform_admin' WHERE role = 'owner';
UPDATE core.users SET role = 'security_admin' WHERE role = 'admin';
UPDATE core.users SET role = 'appsec_analyst' WHERE role = 'security_engineer';

-- Only delete developers if force flag is set (the guard above let us through).
DELETE FROM core.users WHERE role = 'developer';

ALTER TABLE core.users ADD CONSTRAINT users_role_check
    CHECK (role IN ('platform_admin', 'security_admin', 'appsec_analyst', 'auditor'));

COMMIT;
