CREATE TABLE updates.signing_key_certificates (
    serial          TEXT PRIMARY KEY,
    purpose         TEXT NOT NULL CHECK (purpose IN (
                        'platform_signing', 'rule_signing', 'vuln_intel_signing')),
    public_key      TEXT NOT NULL,
    valid_from      TIMESTAMPTZ NOT NULL,
    valid_until     TIMESTAMPTZ NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    root_fingerprint TEXT NOT NULL,
    replaces_serial TEXT REFERENCES updates.signing_key_certificates(serial),
    certificate_json TEXT NOT NULL,
    signature       TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'expired', 'revoked', 'superseded')),
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_signing_certs_purpose_status
    ON updates.signing_key_certificates(purpose, status);

CREATE TABLE updates.revocation_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entry_type      TEXT NOT NULL CHECK (entry_type IN (
                        'certificate', 'bundle', 'root_key')),
    revoked_serial  TEXT,
    revoked_bundle_type TEXT,
    revoked_bundle_version TEXT,
    revoked_at      TIMESTAMPTZ NOT NULL,
    reason          TEXT NOT NULL,
    advisory_id     TEXT,
    revocation_sequence INTEGER NOT NULL,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_revocation_serial ON updates.revocation_entries(revoked_serial)
    WHERE entry_type = 'certificate';

CREATE TABLE updates.update_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_type     TEXT NOT NULL,
    version         TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('staged', 'applied', 'rolled_back', 'failed')),
    signing_key_serial TEXT,
    manifest_hash   TEXT,
    verification_chain JSONB,
    applied_by      UUID REFERENCES core.users(id),
    applied_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE updates.trust_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type      TEXT NOT NULL CHECK (event_type IN (
                        'trust_established', 'signing_key_rotated',
                        'signing_key_revoked', 'bundle_revoked',
                        'root_key_pinned', 'lockdown_enabled',
                        'lockdown_disabled', 'verification_failed')),
    details         JSONB NOT NULL,
    actor_id        UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE updates.trust_state (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_by      UUID,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO updates.trust_state (key, value) VALUES
    ('lockdown', 'false'),
    ('root_key_fingerprint', ''),
    ('installed_version_platform', '0.0.0'),
    ('installed_version_rules', '0.0.0'),
    ('installed_version_vuln_intel', '0.0.0'),
    ('revocation_sequence', '0'),
    ('bootstrap_completed', 'false');
