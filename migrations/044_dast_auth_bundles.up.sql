CREATE TABLE dast_auth_bundles (
    id                   UUID PRIMARY KEY,
    customer_id          UUID NOT NULL,
    project_id           UUID NOT NULL,
    target_host          TEXT NOT NULL,
    target_principal     TEXT,

    type                 TEXT NOT NULL CHECK (type IN ('session_import','recorded_login')),
    status               TEXT NOT NULL CHECK (status IN ('pending_review','approved','revoked','refresh_required','expired','soft_deleted')),

    iv                   BYTEA NOT NULL,
    ciphertext_ref       TEXT NOT NULL,
    aead_tag             BYTEA,
    wrapped_dek          BYTEA NOT NULL,
    kms_key_id           TEXT NOT NULL,
    kms_key_version      TEXT NOT NULL,
    integrity_hmac       BYTEA NOT NULL,
    schema_version       INT NOT NULL,

    created_by_user_id   UUID NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by_user_id  UUID,
    approved_at          TIMESTAMPTZ,
    last_used_at         TIMESTAMPTZ,
    expires_at           TIMESTAMPTZ NOT NULL,
    revoked_at           TIMESTAMPTZ,
    soft_deleted_at      TIMESTAMPTZ,
    hard_delete_after    TIMESTAMPTZ,

    captcha_in_flow      BOOLEAN NOT NULL DEFAULT false,
    automatable_refresh  BOOLEAN NOT NULL DEFAULT false,
    ttl_seconds          INT NOT NULL DEFAULT 86400,
    refresh_count        INT NOT NULL DEFAULT 0,
    consecutive_failures INT NOT NULL DEFAULT 0,

    use_count            BIGINT NOT NULL DEFAULT 0,
    metadata_jsonb       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX dast_auth_bundles_project_status
    ON dast_auth_bundles(project_id, status)
    WHERE status IN ('approved', 'pending_review');

CREATE INDEX dast_auth_bundles_expiry
    ON dast_auth_bundles(expires_at)
    WHERE status = 'approved';

CREATE INDEX dast_auth_bundles_customer
    ON dast_auth_bundles(customer_id);

CREATE TABLE dast_auth_bundle_acls (
    bundle_id  UUID NOT NULL REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    project_id UUID NOT NULL,
    scope_id   UUID,
    PRIMARY KEY (bundle_id, project_id, scope_id)
);

CREATE INDEX dast_auth_bundle_acls_project ON dast_auth_bundle_acls(project_id);
