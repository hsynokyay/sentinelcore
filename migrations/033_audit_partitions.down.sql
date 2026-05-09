BEGIN;

-- Detach + drop the monthly partitions seeded by the up migration.
-- DEFAULT partition is left intact because the up migration didn't
-- create it.
DO $$
DECLARE p RECORD;
BEGIN
    FOR p IN SELECT partition_name FROM audit.list_partitions() LOOP
        EXECUTE format('ALTER TABLE audit.audit_log DETACH PARTITION audit.%I',
                       p.partition_name);
        EXECUTE format('DROP TABLE audit.%I', p.partition_name);
    END LOOP;
END $$;

DROP FUNCTION IF EXISTS audit.list_partitions();
DROP FUNCTION IF EXISTS audit.ensure_partition(DATE);

COMMIT;
