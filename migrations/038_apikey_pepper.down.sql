BEGIN;

DROP TABLE IF EXISTS auth.apikey_peppers;
DROP INDEX IF EXISTS core.api_keys_verifier_idx;
ALTER TABLE core.api_keys
    DROP COLUMN IF EXISTS key_verifier,
    DROP COLUMN IF EXISTS pepper_version;

COMMIT;
