ALTER TABLE core.scan_targets
    DROP COLUMN IF EXISTS notes,
    DROP COLUMN IF EXISTS environment,
    DROP COLUMN IF EXISTS label;
