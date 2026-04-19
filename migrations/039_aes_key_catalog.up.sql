BEGIN;

-- Phase 7 §5.3: Unified AES master key catalog.
--
-- Replaces the fragmented today-state where every secret-holding
-- feature (SSO client_secret, webhook HMAC, auth-profile secret,
-- future integration tokens) wires its own key source ad-hoc. A
-- single catalog gives one rotation surface + one audit trail.
--
-- Key material still lives outside the DB (env var today, Vault
-- tomorrow). This table is a CATALOG that lets the envelope reader
-- look up `enc:v<N>:<purpose>:<b64>` ciphertexts and find the
-- correct key version + source.

CREATE TABLE auth.aes_keys (
    version     INTEGER NOT NULL CHECK (version > 0),
    purpose     TEXT NOT NULL CHECK (purpose IN (
                    'sso','webhook','auth_profile','integration','generic'
                )),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    vault_path  TEXT NOT NULL,
    fingerprint TEXT NOT NULL CHECK (length(fingerprint) = 64),
    PRIMARY KEY (version, purpose)
);

CREATE INDEX aes_keys_purpose_idx
    ON auth.aes_keys(purpose, version DESC);

-- Seed row for SSO — the existing SSO_ENC_KEY_B64 env var, already
-- in production. Fingerprint is the zero sentinel; startup code
-- overwrites it with sha256 of the decoded key bytes.
INSERT INTO auth.aes_keys (version, purpose, vault_path, fingerprint)
VALUES (1, 'sso', 'env:SSO_ENC_KEY_B64',
        '0000000000000000000000000000000000000000000000000000000000000000')
ON CONFLICT (version, purpose) DO NOTHING;

COMMIT;
