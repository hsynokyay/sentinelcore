-- 049_dast_replay_hardening.up.sql
-- Replay hardening: per-bundle circuit breaker counters and a recorded
-- principal claim hint for identity-binding checks during replay.

CREATE TABLE IF NOT EXISTS dast_replay_failures (
    bundle_id            UUID PRIMARY KEY REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_failure_at      TIMESTAMPTZ,
    last_error           TEXT
);

ALTER TABLE dast_auth_bundles
    ADD COLUMN IF NOT EXISTS principal_claim TEXT NOT NULL DEFAULT 'sub';
