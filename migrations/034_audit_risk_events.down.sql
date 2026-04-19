BEGIN;

DROP POLICY IF EXISTS risk_events_insert_worker ON audit.risk_events;
DROP POLICY IF EXISTS risk_events_read_tenant   ON audit.risk_events;
ALTER TABLE audit.risk_events DISABLE ROW LEVEL SECURITY;

DROP TRIGGER IF EXISTS risk_events_no_delete ON audit.risk_events;
DROP TRIGGER IF EXISTS risk_events_no_update ON audit.risk_events;

DROP INDEX IF EXISTS audit.risk_events_material_idx;
DROP INDEX IF EXISTS audit.risk_events_org_time_idx;
DROP INDEX IF EXISTS audit.risk_events_risk_time_idx;

DROP TABLE IF EXISTS audit.risk_events;

COMMIT;
