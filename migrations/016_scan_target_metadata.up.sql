-- Add operator-facing metadata to scan targets.
-- These fields are UX-only and do not affect scan execution semantics.
ALTER TABLE core.scan_targets
    ADD COLUMN IF NOT EXISTS label       TEXT,
    ADD COLUMN IF NOT EXISTS environment TEXT,
    ADD COLUMN IF NOT EXISTS notes       TEXT;

-- Backfill label from base_url host for pre-existing rows so the UI never shows
-- an empty list item.
UPDATE core.scan_targets
   SET label = base_url
 WHERE label IS NULL;
