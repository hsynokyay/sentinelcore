BEGIN;

-- Phase 7 §5.2: API key hash upgrade SHA-256 → HMAC-SHA256 + pepper.
--
-- New verifier column runs parallel to the existing key_hash column
-- for the 90-day transition window. Auth lookups try key_verifier
-- first; on miss, fall back to key_hash and opportunistically
-- backfill the verifier the next time the key is validated.
--
-- Once the backfill sweep completes (or transition window expires),
-- a follow-up migration drops key_hash and its index.

ALTER TABLE core.api_keys
    ADD COLUMN IF NOT EXISTS key_verifier   TEXT,
    ADD COLUMN IF NOT EXISTS pepper_version INTEGER;

CREATE INDEX IF NOT EXISTS api_keys_verifier_idx
    ON core.api_keys(key_verifier)
    WHERE key_verifier IS NOT NULL;

-- Catalog of pepper versions, mirror of audit.hmac_keys. Separate
-- table so pepper rotation cadence is independent of audit-chain
-- rotation (different threat models, different schedules).
CREATE TABLE auth.apikey_peppers (
    version     INTEGER PRIMARY KEY CHECK (version > 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    vault_path  TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64)
);

-- Seed row — actual pepper material comes from env SC_APIKEY_PEPPER_B64
-- at app startup. Startup code overwrites the zero-sentinel fingerprint
-- with sha256(pepper_bytes) so a stale Vault fetch is detectable.
INSERT INTO auth.apikey_peppers (version, vault_path, fingerprint)
VALUES (1, 'env:SC_APIKEY_PEPPER_B64',
        '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (version) DO NOTHING;

COMMIT;
