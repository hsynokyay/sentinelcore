BEGIN;

-- audit.ensure_partition creates the monthly child partition for a given
-- month and its per-partition indexes. Idempotent (IF NOT EXISTS on both
-- the partition and the indexes) so the daily cron can call it safely.
--
-- Partition naming: audit.audit_log_YYYYMM (e.g. audit_log_202604).
-- RANGE: [month_start, month_start + 1 month).
CREATE OR REPLACE FUNCTION audit.ensure_partition(month_start DATE)
RETURNS VOID
SECURITY DEFINER
SET search_path = audit, pg_catalog
AS $$
DECLARE
    part_name TEXT := format('audit_log_%s', to_char(month_start, 'YYYYMM'));
    start_ts  TEXT := quote_literal(month_start);
    end_ts    TEXT := quote_literal((month_start + INTERVAL '1 month')::date);
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit.%I PARTITION OF audit.audit_log
            FOR VALUES FROM (%s) TO (%s)',
        part_name, start_ts, end_ts);

    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS %I ON audit.%I (timestamp)',
        part_name || '_ts_idx', part_name);
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS %I ON audit.%I (action, timestamp)',
        part_name || '_action_idx', part_name);
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS %I ON audit.%I (actor_id, timestamp)',
        part_name || '_actor_idx', part_name);
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS %I ON audit.%I (resource_type, resource_id, timestamp)',
        part_name || '_resource_idx', part_name);
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS %I ON audit.%I (org_id, timestamp)',
        part_name || '_org_idx', part_name);
END;
$$ LANGUAGE plpgsql;

-- Seed current month + 12 future months so the first audit-worker write
-- on month boundary never hits the default partition.
DO $$
DECLARE m DATE;
BEGIN
    FOR i IN 0..12 LOOP
        m := (date_trunc('month', now()) + (i || ' months')::interval)::date;
        PERFORM audit.ensure_partition(m);
    END LOOP;
END $$;

-- audit.list_partitions returns the active (non-default) monthly child
-- partitions of audit.audit_log, newest first. Used by the verifier
-- scheduler to iterate partitions without re-deriving names.
CREATE OR REPLACE FUNCTION audit.list_partitions()
RETURNS TABLE(partition_name TEXT) AS $$
    SELECT c.relname::text
    FROM pg_inherits i
    JOIN pg_class c ON c.oid = i.inhrelid
    JOIN pg_class p ON p.oid = i.inhparent
    JOIN pg_namespace n ON n.oid = p.relnamespace
    WHERE n.nspname = 'audit'
      AND p.relname = 'audit_log'
      AND c.relname LIKE 'audit_log_%'
      AND c.relname <> 'audit_log_default'
    ORDER BY c.relname DESC;
$$ LANGUAGE SQL STABLE;

COMMIT;
