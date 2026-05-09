BEGIN;
DROP INDEX IF EXISTS auth.aes_keys_purpose_idx;
DROP TABLE IF EXISTS auth.aes_keys;
COMMIT;
