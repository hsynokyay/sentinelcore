-- Migration 050 — DAST forensics screenshot references
--
-- Adds a JSONB column to `dast_replay_failures` so the replay engine can
-- record MinIO object keys for envelope-encrypted screenshots captured at
-- failure time (see plan #6, PR C / spec §5).
--
-- DEPENDENCY: This migration REQUIRES migration 049 from plan #5 ("DAST
-- replay hardening") to be applied first, because that migration creates
-- the `dast_replay_failures` table. Applied out of order this ALTER will
-- fail with `relation "dast_replay_failures" does not exist`.
--
-- Apply order: 046 (recording_metadata) → 049 (replay_failures) → 050.

ALTER TABLE dast_replay_failures
    ADD COLUMN IF NOT EXISTS screenshot_refs JSONB NOT NULL DEFAULT '[]'::jsonb;
