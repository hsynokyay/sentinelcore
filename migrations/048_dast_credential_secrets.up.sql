-- 048: KMS-backed credential store for DAST replay credential injection.
-- Each row holds an envelope-encrypted secret keyed by (bundle_id, vault_key).
-- Plaintext is never stored; the wrapped DEK is unwrapped on Load via the
-- KMS provider configured in the controlplane.

CREATE TABLE IF NOT EXISTS dast_credential_secrets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id     UUID NOT NULL REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    vault_key     TEXT NOT NULL,
    customer_id   UUID NOT NULL,
    iv            BYTEA NOT NULL,
    ciphertext    BYTEA NOT NULL,
    aead_tag      BYTEA NOT NULL,
    wrapped_dek   BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bundle_id, vault_key)
);

CREATE INDEX IF NOT EXISTS idx_dcs_bundle ON dast_credential_secrets (bundle_id);

ALTER TABLE dast_credential_secrets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dcs_customer_isolation ON dast_credential_secrets;
CREATE POLICY dcs_customer_isolation ON dast_credential_secrets
  USING (customer_id = current_setting('app.customer_id', true)::uuid);
