-- Rollback migration 050 — drop screenshot_refs column.
--
-- Safe to apply if the column exists; no-op otherwise. The column itself
-- only contained MinIO object keys (no inline binary data); the encrypted
-- screenshot blobs live in the `dast-forensics` MinIO bucket and are
-- governed by the forensics-cleanup-worker 7-day retention loop.

ALTER TABLE dast_replay_failures DROP COLUMN IF EXISTS screenshot_refs;
