CREATE TABLE audit.audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_id        UUID NOT NULL DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('user', 'service', 'system', 'cicd')),
    actor_id        TEXT NOT NULL,
    actor_ip        INET,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    org_id          UUID,
    team_id         UUID,
    project_id      UUID,
    details         JSONB,
    result          TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    previous_hash   TEXT NOT NULL DEFAULT '',
    entry_hash      TEXT NOT NULL DEFAULT '',
    hmac_key_version INTEGER
) PARTITION BY RANGE (timestamp);

-- Create initial partition for current month and next month
CREATE TABLE audit.audit_log_default PARTITION OF audit.audit_log DEFAULT;

CREATE INDEX idx_audit_timestamp ON audit.audit_log(timestamp);
CREATE INDEX idx_audit_actor ON audit.audit_log(actor_id, timestamp);
CREATE INDEX idx_audit_resource ON audit.audit_log(resource_type, resource_id, timestamp);
CREATE INDEX idx_audit_action ON audit.audit_log(action, timestamp);
