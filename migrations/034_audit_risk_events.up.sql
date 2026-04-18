BEGIN;

-- Denormalised lifecycle timeline for risks. Built by the audit-worker
-- consumer from specific risk.* actions in audit.audit_log. Rebuildable
-- from the source via TRUNCATE + replay (see docs/audit-operator-runbook).
--
-- There is DELIBERATELY no foreign key to a risk.clusters table:
--   - risk.clusters is a Phase 2 schema that may or may not be applied
--     on a given deployment; this migration ships the audit pipe
--     decoupled from the risks feature landing.
--   - Audit rows must OUTLIVE the rows they describe. If a cluster is
--     later deleted (should not happen — append-only elsewhere too —
--     but defence-in-depth) the timeline rows stay as evidence.
--
-- The API handler deep-links from risk_events back to audit_log via
-- (audit_log_id, audit_log_ts) so compliance can produce chain proof
-- for any timeline entry.
CREATE TABLE audit.risk_events (
    id              BIGSERIAL PRIMARY KEY,
    risk_id         UUID NOT NULL,
    org_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    actor_type      TEXT NOT NULL,
    actor_id        TEXT NOT NULL,
    audit_log_id    BIGINT NOT NULL,
    audit_log_ts    TIMESTAMPTZ NOT NULL,
    before_value    JSONB,
    after_value     JSONB,
    note            TEXT,
    is_material     BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT valid_event_type CHECK (event_type IN (
        'created','seen_again','score_changed','status_changed',
        'relation_added','relation_removed','evidence_changed',
        'resolved','reopened','muted','unmuted','assigned','note_added'
    ))
);

CREATE INDEX risk_events_risk_time_idx
    ON audit.risk_events(risk_id, occurred_at DESC);

CREATE INDEX risk_events_org_time_idx
    ON audit.risk_events(org_id, occurred_at DESC);

-- Materiality partial index: the UI shows only material events by default,
-- reserving the "all events" filter for forensic deep dives.
CREATE INDEX risk_events_material_idx
    ON audit.risk_events(risk_id, occurred_at DESC)
    WHERE is_material = true;

-- Append-only. Plan §1.3 rationale: the projection is rebuildable but
-- individual rows are not mutable evidence.
CREATE TRIGGER risk_events_no_update
    BEFORE UPDATE ON audit.risk_events
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();
CREATE TRIGGER risk_events_no_delete
    BEFORE DELETE ON audit.risk_events
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

-- RLS: tenant-scoped via org_id. Same policy shape as audit_log, staged
-- for the writer/reader role split.
ALTER TABLE audit.risk_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY risk_events_read_tenant ON audit.risk_events
    FOR SELECT
    USING (
        org_id::text = current_setting('app.current_org_id', true)
        OR current_setting('app.audit_global_read', true) = 'true'
    );

CREATE POLICY risk_events_insert_worker ON audit.risk_events
    FOR INSERT
    WITH CHECK (current_setting('app.writer_role', true) = 'audit_worker');

COMMIT;
