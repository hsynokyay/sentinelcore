BEGIN;

-- Append-only enforcement for audit.audit_log. Trigger fires BEFORE any
-- UPDATE/DELETE and raises — even superusers hit this. Dropping the
-- trigger itself IS an auditable action (session_user logged in pg audit
-- logs by default). The trigger is intentionally independent of RLS:
-- RLS filters rows a query sees; this prevents mutation once a row is seen.
CREATE OR REPLACE FUNCTION audit.prevent_mutation()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'audit.audit_log is append-only (attempted %)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Bind to both the parent partitioned table AND the existing default partition.
-- Newly-created partitions (migration 033) inherit triggers from the parent.
DROP TRIGGER IF EXISTS audit_log_no_update ON audit.audit_log;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

DROP TRIGGER IF EXISTS audit_log_no_delete ON audit.audit_log;
CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

-- Idempotency guarantee on the write path. The consumer may see a
-- NATS redelivery with the same event_id; the UNIQUE constraint makes
-- the second INSERT fail cheaply (caught and ack'd by consumer).
CREATE UNIQUE INDEX IF NOT EXISTS audit_log_event_id_uniq
    ON audit.audit_log (event_id);

-- HMAC key catalogue. Key MATERIAL lives in Vault (or the transitional
-- AUDIT_HMAC_KEY_B64 env var); this table tracks what versions exist
-- and where to look for them. fingerprint lets the verifier detect a
-- stale Vault fetch.
CREATE TABLE audit.hmac_keys (
    version     INTEGER PRIMARY KEY CHECK (version > 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at  TIMESTAMPTZ,
    vault_path  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,      -- sha256(key_material) hex
    CONSTRAINT  hmac_keys_vault_nonempty CHECK (length(vault_path) > 0),
    CONSTRAINT  hmac_keys_fp_len        CHECK (length(fingerprint) = 64)
);

-- Seed the transitional version 1 row. The actual key material is sourced
-- at runtime from AUDIT_HMAC_KEY_B64; the vault_path below is a marker
-- for operators: "replace this row when the real Vault is wired".
INSERT INTO audit.hmac_keys (version, vault_path, fingerprint)
VALUES (1, 'env:AUDIT_HMAC_KEY_B64',
        'pending-first-key-fetch-will-update-at-startup')
ON CONFLICT (version) DO NOTHING;

-- Verification run log. Separate table so the verifier's own state is
-- auditable + replayable without touching audit_log rows.
CREATE TABLE audit.integrity_checks (
    id                 BIGSERIAL PRIMARY KEY,
    started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at        TIMESTAMPTZ,
    partition_name     TEXT NOT NULL,
    row_count          BIGINT,
    first_row_id       BIGINT,
    last_row_id        BIGINT,
    outcome            TEXT NOT NULL CHECK (outcome IN ('pass','fail','partial','error')),
    failed_row_id      BIGINT,
    failed_key_version INTEGER,
    error_message      TEXT,
    checked_by         TEXT NOT NULL DEFAULT 'cron'
);

CREATE INDEX integrity_checks_outcome_idx
    ON audit.integrity_checks (outcome, started_at DESC)
    WHERE outcome <> 'pass';

CREATE INDEX integrity_checks_partition_time_idx
    ON audit.integrity_checks (partition_name, started_at DESC);

-- integrity_checks is append-only too: history of verification runs is
-- evidence for compliance, not operational state.
CREATE TRIGGER integrity_checks_no_update
    BEFORE UPDATE ON audit.integrity_checks
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();
CREATE TRIGGER integrity_checks_no_delete
    BEFORE DELETE ON audit.integrity_checks
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

COMMIT;
