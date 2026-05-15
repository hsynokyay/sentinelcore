# Phase 6 — Audit & Traceability Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Turn the existing `audit.audit_log` shell into a tamper-evident, enterprise-defensible audit surface. Add a dedicated risk lifecycle timeline. Ship a practical export pipeline for compliance teams.

**Architecture (one page):**

```
handler                    NATS (audit.events)              PostgreSQL
  │                              │                            │
  ▼                              ▼                            ▼
audit.Emit(ctx, event)  ──>  JetStream consumer (audit-worker)
                                │                            │
                                ├── HMAC chain compute       │
                                ├── append INSERT            ├── audit.audit_log  (partitioned, INSERT-only role)
                                ├── materialise to            │  └── monthly partitions, HMAC chain, indexes
                                │   audit.risk_events  ──>   ├── audit.risk_events
                                │   (if action starts risk.) │
                                └── publish to SIEM fanout    ├── audit.integrity_checks (hourly verifier log)
                                    (optional)                └── audit.export_jobs (async export orchestration)

hourly cron:  integrity-checker  ──>  audit.audit_log (verify chain, log to audit.integrity_checks)
daily  cron:  partition-manager  ──>  audit.audit_log  (create next partition, archive old)
```

Key design choices, all locked:

1. **One canonical write path.** Every audit event is published to NATS by `pkg/audit.Emitter.Emit()`; **all DB writes happen in `cmd/audit-worker/`**. Handlers never `INSERT` into `audit.audit_log` directly. This gives us (a) at-least-once delivery survives DB blips, (b) idempotent consumer keyed on `event_id` UUID, (c) single place to compute the HMAC chain (serialised, no concurrency bugs), (d) free SIEM fan-out.
2. **Append-only enforced three ways:** RBAC (audit-worker DB role has `INSERT` only, no UPDATE/DELETE), trigger (`audit.prevent_mutation()` fires on any UPDATE or DELETE and `RAISE EXCEPTION`), and partition retention (old partitions detached + archived, never mutated).
3. **HMAC chain per partition, not per table.** `entry_hash = HMAC_SHA256(key_vN, canonical(entry_without_hash) || previous_hash)`. `previous_hash` references the previous row IN THE SAME MONTHLY PARTITION. Cross-partition continuity is proved by hashing the last row of the previous partition into the first row of the next (boundary row). This keeps verification parallelisable per partition.
4. **Risk lifecycle is a denormalised view, not a new source of truth.** `audit.risk_events` is populated by the audit-worker from specific `risk.*` actions. This gives per-risk timeline queries in O(log n) while keeping the generic audit log the single write target. Drop + rebuild is safe because `audit.audit_log` is the source.
5. **Exports are always async for large results.** Sync endpoint returns ≤ 10k rows with streaming response; anything larger is rejected with a hint to use the job endpoint. Job artifacts live in MinIO with 7-day TTL + GPG encryption option for compliance teams.
6. **No secrets ever in `details`.** The emitter's `Emit` path runs a redactor that strips fields matching `(?i)(secret|password|token|key|hash|cookie|authorization|bearer)` and truncates remaining string values to 512 chars. Redaction is logged (count only) in a sibling field so reviewers know something was stripped.

**Tech stack:** Go 1.26, PostgreSQL 16 (RANGE partitioning, RLS, triggers, pgcrypto), NATS JetStream, MinIO (export artifacts), HashiCorp Vault (HMAC keys + GPG key), existing `pkg/db` / `pkg/nats` / `pkg/auth`.

**Phase dependencies:**

- Phase 1 RBAC (for `audit.read`, `audit.export`, `audit.verify` permissions)
- Phase 3 SSO (for `auth.sso_login_events` — stays a *diagnostic* ring buffer; Phase 6 adds proper audit rows for the same actions)
- Phase 4 Governance (triage/approval actions are event sources; no schema conflict)

---

## File Structure

### New files

```
migrations/032_audit_integrity.up.sql            # HMAC trigger, append-only trigger, integrity table
migrations/032_audit_integrity.down.sql
migrations/033_audit_partitions.up.sql           # 12 monthly partitions + management funcs
migrations/033_audit_partitions.down.sql
migrations/034_audit_risk_events.up.sql          # audit.risk_events denormalised timeline
migrations/034_audit_risk_events.down.sql
migrations/035_audit_export_jobs.up.sql          # async export job table
migrations/035_audit_export_jobs.down.sql
migrations/036_audit_rls.up.sql                  # RLS policies + INSERT-only role grants
migrations/036_audit_rls.down.sql

pkg/audit/
  redactor.go                 # redactDetails(map[string]any) map[string]any
  redactor_test.go
  hmac.go                     # HMACChain compute + verify
  hmac_test.go
  canonical.go                # canonical JSON serialisation (RFC 8785 subset)
  canonical_test.go
  actions.go                  # typed constants for action taxonomy (enforced at compile time)
  actions_test.go             # invariant: every constant is in action_taxonomy.md

internal/audit/consumer/
  consumer.go                 # NATS subscription, chain write, risk_events projection, SIEM fanout
  consumer_test.go            # DB-gated integration test with miniNATS + pg
  projector.go                # maps AuditEvent → risk_events row when applicable
  projector_test.go
  metrics.go                  # Prometheus counters: events_total{action}, chain_writes_total, integrity_failures_total

internal/audit/export/
  service.go                  # Orchestrates sync + async exports
  service_test.go
  csv.go                      # Streaming CSV writer (io.Writer, flushes each row)
  csv_test.go
  json.go                     # Streaming NDJSON writer
  json_test.go
  filters.go                  # Parse + validate query params → SQL predicate
  filters_test.go
  encryptor.go                # Optional GPG encryption for compliance exports
  encryptor_test.go

internal/audit/integrity/
  verifier.go                 # Per-partition chain verification
  verifier_test.go
  scheduler.go                # Hourly cron wrapper

internal/audit/partition/
  manager.go                  # Create next month partition, archive old
  manager_test.go

cmd/audit-worker/
  main.go                     # Consumer + integrity cron + partition cron; replaces the stub

internal/controlplane/api/
  audit.go                    # GET /api/v1/audit (paginated query)
  audit_test.go
  audit_export.go             # POST /audit/exports, GET /audit/exports/{id}
  audit_export_test.go
  risks_history.go            # GET /api/v1/risks/{id}/history
  risks_history_test.go

docs/
  audit-action-taxonomy.md    # canonical list of action codes; breaking changes require new entry
  audit-operator-runbook.md   # integrity failure response, key rotation, export workflow
```

### Modified files

```
pkg/audit/types.go                     # extend AuditEvent with TeamID / ProjectID / IdempotencyKey / Redacted count
pkg/audit/emitter.go                   # add idempotency key, run redactor before publish
internal/controlplane/server.go        # register 3 new routes, wire audit export service
internal/controlplane/api/handlers.go  # add ssoEvents → auditEvents field parallel; audit export service
cmd/controlplane/main.go               # run partition-manager at startup (idempotent)
```

### Route additions (7)

```
GET    /api/v1/audit                            audit.read      (paginated, filterable)
GET    /api/v1/audit/{id}                       audit.read      (single event with chain proof)
POST   /api/v1/audit/exports                    audit.export    (create async export job)
GET    /api/v1/audit/exports                    audit.export    (list own jobs)
GET    /api/v1/audit/exports/{id}               audit.export    (status + download URL)
GET    /api/v1/audit/integrity                  audit.verify    (latest verification run results)
GET    /api/v1/risks/{id}/history               risks.read      (risk lifecycle timeline)
```

---

## 1. Schema Changes

### 1.1 `audit.audit_log` hardening (migration 032)

Add **append-only trigger** — required because RLS on audit_log doesn't protect against UPDATE/DELETE by role with table privileges:

```sql
CREATE OR REPLACE FUNCTION audit.prevent_mutation()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'audit.audit_log is append-only (attempted %)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

CREATE TRIGGER audit_log_no_delete
    BEFORE DELETE ON audit.audit_log
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();
```

Add **integrity check log** (separate table so the check itself is auditable and replayable):

```sql
CREATE TABLE audit.integrity_checks (
    id              BIGSERIAL PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ,
    partition_name  TEXT NOT NULL,
    row_count       BIGINT,
    first_row_id    BIGINT,
    last_row_id     BIGINT,
    outcome         TEXT NOT NULL CHECK (outcome IN ('pass','fail','partial','error')),
    failed_row_id   BIGINT,                -- first row whose hash didn't match
    failed_key_version INTEGER,            -- key version that couldn't be found
    error_message   TEXT,
    checked_by      TEXT NOT NULL DEFAULT 'cron',
    UNIQUE (started_at, partition_name)
);

CREATE INDEX integrity_checks_outcome_idx
    ON audit.integrity_checks(outcome, started_at DESC)
    WHERE outcome != 'pass';
```

Add **HMAC key registry** (key material stays in Vault; this table is a catalog):

```sql
CREATE TABLE audit.hmac_keys (
    version         INTEGER PRIMARY KEY,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ,            -- set when replaced; kept forever for verification
    vault_path      TEXT NOT NULL,          -- e.g. "sc/audit/hmac/v3"
    fingerprint     TEXT NOT NULL           -- SHA-256 of key material for integrity checking the fetch
);
```

### 1.2 Monthly partitions (migration 033)

Create the next 12 months of partitions **upfront** so the first month of audit traffic never hits the default partition (operators are notified if the partition manager cron falls behind):

```sql
-- Function called from migration + cron
CREATE OR REPLACE FUNCTION audit.ensure_partition(month_start DATE)
RETURNS VOID AS $$
DECLARE
    part_name TEXT := format('audit_log_%s', to_char(month_start, 'YYYYMM'));
    start_ts TEXT := quote_literal(month_start);
    end_ts   TEXT := quote_literal(month_start + INTERVAL '1 month');
BEGIN
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS audit.%I PARTITION OF audit.audit_log
            FOR VALUES FROM (%s) TO (%s);
         CREATE INDEX IF NOT EXISTS %I ON audit.%I (timestamp);
         CREATE INDEX IF NOT EXISTS %I ON audit.%I (action, timestamp);
         CREATE INDEX IF NOT EXISTS %I ON audit.%I (actor_id, timestamp);
         CREATE INDEX IF NOT EXISTS %I ON audit.%I (resource_type, resource_id, timestamp);
         CREATE INDEX IF NOT EXISTS %I ON audit.%I (org_id, timestamp)',
        part_name, start_ts, end_ts,
        part_name || '_ts_idx',       part_name,
        part_name || '_action_idx',   part_name,
        part_name || '_actor_idx',    part_name,
        part_name || '_resource_idx', part_name,
        part_name || '_org_idx',      part_name
    );
END;
$$ LANGUAGE plpgsql;

-- Seed current month + 12 future months
DO $$
DECLARE m DATE;
BEGIN
    FOR i IN 0..12 LOOP
        m := date_trunc('month', now())::date + (i || ' months')::interval;
        PERFORM audit.ensure_partition(m);
    END LOOP;
END $$;
```

### 1.3 `audit.risk_events` (migration 034)

Denormalised timeline populated by the audit-worker; rebuildable from `audit.audit_log`:

```sql
CREATE TABLE audit.risk_events (
    id              BIGSERIAL PRIMARY KEY,
    risk_id         UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,         -- see taxonomy
    occurred_at     TIMESTAMPTZ NOT NULL,
    actor_type      TEXT NOT NULL,         -- user | service | system
    actor_id        TEXT NOT NULL,
    audit_log_id    BIGINT NOT NULL,       -- pointer back into audit_log for chain proof
    audit_log_ts    TIMESTAMPTZ NOT NULL,  -- partition key for the pointer
    before_value    JSONB,                 -- e.g. {"score": 7.8}
    after_value     JSONB,                 -- e.g. {"score": 8.4}
    note            TEXT,                  -- user-supplied reason when available
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

-- Append-only guarantee same as audit_log
CREATE TRIGGER risk_events_no_update BEFORE UPDATE ON audit.risk_events
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();
CREATE TRIGGER risk_events_no_delete BEFORE DELETE ON audit.risk_events
    FOR EACH ROW EXECUTE FUNCTION audit.prevent_mutation();

ALTER TABLE audit.risk_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY risk_events_tenant ON audit.risk_events
    USING (org_id = current_setting('app.current_org_id', true)::uuid);
```

### 1.4 `audit.export_jobs` (migration 035)

```sql
CREATE TABLE audit.export_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    requested_by    TEXT NOT NULL,                 -- user_id
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    filters         JSONB NOT NULL,                -- {from, to, action, actor, resource_type, ...}
    format          TEXT NOT NULL CHECK (format IN ('csv','ndjson','jsonl')),
    encrypt_gpg     BOOLEAN NOT NULL DEFAULT false,
    gpg_recipient   TEXT,                          -- required if encrypt_gpg=true
    status          TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','running','succeeded','failed','expired')),
    progress_rows   BIGINT NOT NULL DEFAULT 0,
    total_rows      BIGINT,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    object_key      TEXT,                          -- MinIO key for the artifact
    sha256          TEXT,                          -- integrity digest of the artifact
    size_bytes      BIGINT,
    error_message   TEXT,
    expires_at      TIMESTAMPTZ                    -- artifact auto-removed past this
);

CREATE INDEX export_jobs_org_status_idx
    ON audit.export_jobs(org_id, status, requested_at DESC);

-- RLS: users see only their org's jobs
ALTER TABLE audit.export_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY export_jobs_tenant ON audit.export_jobs
    USING (org_id = current_setting('app.current_org_id', true)::uuid);
```

### 1.5 Tenant isolation + INSERT-only role (migration 036)

```sql
-- RLS on the existing audit_log
ALTER TABLE audit.audit_log ENABLE ROW LEVEL SECURITY;

-- Reader policy: tenant-scoped
CREATE POLICY audit_log_read_tenant ON audit.audit_log
    FOR SELECT
    USING (
        org_id = current_setting('app.current_org_id', true)::uuid
        OR current_setting('app.audit_global_read', true) = 'true'  -- for platform_admin + auditor
    );

-- Writer policy: audit-worker only
CREATE POLICY audit_log_insert_worker ON audit.audit_log
    FOR INSERT
    WITH CHECK (current_setting('app.writer_role', true) = 'audit_worker');

-- Dedicated DB role for the audit-worker (created outside migration by operator)
-- Role grants:
--   GRANT INSERT ON audit.audit_log TO sentinelcore_audit_writer;
--   GRANT SELECT ON audit.hmac_keys TO sentinelcore_audit_writer;
--   GRANT INSERT ON audit.risk_events TO sentinelcore_audit_writer;
--   GRANT INSERT ON audit.integrity_checks TO sentinelcore_audit_verifier;
-- Neither role gets UPDATE or DELETE.
```

---

## 2. Action Taxonomy

Canonical action codes. Every new action must be added here AND to `docs/audit-action-taxonomy.md`. `pkg/audit/actions.go` exports typed constants, and `actions_test.go` has a go:generate hook that fails CI if the two sources drift.

**Convention:** `<domain>.<resource>.<verb>`. Past tense for completed actions. Verbs: `created`, `updated`, `deleted`, `rotated`, `triggered`, `attempted`, `failed`, `succeeded`, `resolved`, `reopened`, `granted`, `revoked`, `used`.

### 2.1 Authentication & identity
```
auth.login.succeeded
auth.login.failed                 — wrong password, disabled user, rate-limited
auth.logout
auth.refresh.succeeded
auth.refresh.failed
auth.sso.login.succeeded          — distinct from password (already in sso_login_events but mirrored)
auth.sso.login.failed
auth.sso.logout
auth.password.changed
auth.password.reset_requested
auth.break_glass.activated        — physical-access fallback
```

### 2.2 RBAC & membership
```
rbac.role.created
rbac.role.updated
rbac.role.deleted
rbac.permission.granted
rbac.permission.revoked
user.created
user.updated
user.disabled
user.enabled
user.team_membership.added
user.team_membership.removed
```

### 2.3 API keys
```
apikey.created
apikey.rotated
apikey.revoked
apikey.used                       — sampled, not every request (see §4)
apikey.scope.changed
```

### 2.4 Scans & findings
```
scan.triggered
scan.cancelled
scan.completed
scan.failed
finding.created
finding.status.changed
finding.assigned
finding.annotation.added
finding.legal_hold.set
finding.legal_hold.cleared
```

### 2.5 Risks (full set — projected into audit.risk_events)
```
risk.created
risk.seen_again
risk.score.changed
risk.status.changed
risk.relation.added
risk.relation.removed
risk.evidence.changed
risk.resolved
risk.reopened
risk.muted
risk.unmuted
risk.assigned
risk.note.added
correlation.rebuild.triggered     — project-level, not per-risk
```

### 2.6 Governance (from Phase 4)
```
governance.approval.requested
governance.approval.approved
governance.approval.rejected
governance.approval.expired
governance.emergency_stop.activated
governance.emergency_stop.lifted
governance.sla.violated
governance.sla.resolved
```

### 2.7 SSO provider config (from Phase 3)
```
sso.provider.created
sso.provider.updated
sso.provider.deleted
sso.mapping.upserted
sso.mapping.deleted
```

### 2.8 Webhooks & notifications
```
webhook.config.created
webhook.config.updated
webhook.config.deleted
webhook.delivery.attempted
webhook.delivery.succeeded
webhook.delivery.failed
notification.dispatched
```

### 2.9 Configuration & system
```
config.setting.changed
config.retention_policy.updated
config.scan_quota.changed
system.worker.started
system.worker.stopped
system.migration.applied
system.backup.succeeded
system.backup.failed
```

### 2.10 Meta (audit about audit)
```
audit.export.requested
audit.export.downloaded
audit.integrity.check.passed
audit.integrity.check.failed
audit.hmac_key.rotated
audit.hmac_key.missing            — verifier couldn't find key version
```

---

## 3. Write-path Integration Points

**Contract:** every handler that mutates state emits exactly one audit event representing the user-visible action. The middleware logs `auth.login.failed` etc. so handlers don't have to.

### 3.1 Emitter extensions

```go
// pkg/audit/types.go
type AuditEvent struct {
    EventID        string            `json:"event_id"`        // UUID; idempotency key
    Timestamp      time.Time         `json:"timestamp"`
    ActorType      string            `json:"actor_type"`      // user | service | system | cicd
    ActorID        string            `json:"actor_id"`
    ActorIP        string            `json:"actor_ip,omitempty"`
    ActorUserAgent string            `json:"actor_user_agent,omitempty"`
    Action         Action            `json:"action"`          // typed constant from actions.go
    ResourceType   string            `json:"resource_type"`
    ResourceID     string            `json:"resource_id"`
    OrgID          string            `json:"org_id,omitempty"`
    TeamID         string            `json:"team_id,omitempty"`
    ProjectID      string            `json:"project_id,omitempty"`
    Result         Result            `json:"result"`          // success | failure | denied
    Details        map[string]any    `json:"details,omitempty"`
    RedactedFields []string          `json:"redacted_fields,omitempty"` // list of keys dropped by redactor
    TraceID        string            `json:"trace_id,omitempty"`
    SpanID         string            `json:"span_id,omitempty"`
}
```

`EventID` is the idempotency key. If the audit-worker processes the same event twice (NATS at-least-once), the second `INSERT` fails on the uniqueness constraint `UNIQUE (event_id)` and the worker `ack`s normally.

### 3.2 Redactor rules

- Key match `(?i)(secret|password|token|key|hash|cookie|authorization|bearer|credential)` → drop entirely, record in `redacted_fields`.
- String values > 512 chars → truncate to 509 + `"…"`, record `key_truncated`.
- Nested objects recursively scanned.
- Never serialise `[]byte` — force caller to base64 first (reject at compile time where possible).

### 3.3 Integration checklist (handlers)

For each handler, specify the pre-emit check and the payload:

```go
// internal/controlplane/api/auth.go :: Login
h.audit.Emit(ctx, audit.AuditEvent{
    ActorType:    "user",
    ActorID:      userID,           // empty on failed login
    ActorIP:      clientIP(r),
    Action:       audit.AuthLoginSucceeded,    // or AuthLoginFailed
    ResourceType: "user",
    ResourceID:   userID,
    OrgID:        orgID,
    Result:       audit.ResultSuccess,
    Details: map[string]any{
        "email":       req.Email,      // OK — email is not a secret
        "mfa":         false,
    },
})
```

Full inventory (apply this pattern at each site):

| Package / handler | Actions emitted |
|---|---|
| `internal/controlplane/api/auth.go` | `auth.login.succeeded`, `auth.login.failed`, `auth.logout`, `auth.refresh.*` |
| `internal/controlplane/api/sso.go` | `auth.sso.login.succeeded`, `auth.sso.login.failed`, `auth.sso.logout` |
| `internal/controlplane/api/apikeys.go` | `apikey.created`, `apikey.rotated`, `apikey.revoked` |
| `pkg/auth/middleware.go` | `apikey.used` (sampled 1 in N, configurable) |
| `internal/controlplane/api/sso_providers.go` | `sso.provider.*` |
| `internal/controlplane/api/scans.go` | `scan.triggered`, `scan.cancelled` |
| `internal/sast/worker.go` / `internal/correlation/worker.go` | `scan.completed`, `scan.failed` |
| `internal/controlplane/api/findings.go` | `finding.status.changed`, `finding.assigned`, `finding.annotation.added` |
| `internal/controlplane/api/risks.go` | `risk.resolved`, `risk.reopened`, `risk.muted`, `risk.note.added` |
| `internal/risk/worker.go` | `risk.created`, `risk.seen_again`, `risk.score.changed`, `risk.relation.added/removed`, `risk.evidence.changed` |
| `internal/governance/workflow.go` | `governance.approval.*`, `governance.sla.*` |
| `internal/governance/estop.go` | `governance.emergency_stop.*` |
| `internal/notification/webhook.go` | `webhook.delivery.attempted/succeeded/failed` |
| `internal/controlplane/api/organizations.go` / `teams.go` / `users.go` | `rbac.*`, `user.*` |

**Rate-limiting `apikey.used`:** emitting on every request is a DoS vector (~1 event per API call). Sample at 1 in 100 by default (configurable via env `AUDIT_APIKEY_SAMPLE_RATE`). Failed API key authentications are always logged (`apikey.used` with `result=denied`) — they're the security-relevant event.

### 3.4 Consumer (audit-worker)

Pseudocode for the hot path:

```go
func (c *Consumer) handle(ctx context.Context, msg jetstream.Msg) {
    var e audit.AuditEvent
    if err := json.Unmarshal(msg.Data(), &e); err != nil {
        // Malformed: nack with no redelivery; log + metric
        msg.TermWithReason("bad_payload")
        return
    }

    // Idempotency: short-circuit if we've seen this event_id already.
    if seen, _ := c.seen.Contains(ctx, e.EventID); seen {
        msg.Ack()
        return
    }

    // Acquire the write lock for this partition so HMAC chain stays serial.
    // Using pg_advisory_xact_lock(hashtext(partition_name)).
    tx, _ := c.pool.Begin(ctx)
    defer tx.Rollback(ctx)

    _, _ = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`,
        partitionNameForTimestamp(e.Timestamp))

    // Find the last row's entry_hash from the same partition.
    var prevHash string
    _ = tx.QueryRow(ctx, `
        SELECT entry_hash FROM audit.audit_log
        WHERE timestamp >= $1 AND timestamp < $2
        ORDER BY id DESC LIMIT 1
    `, monthStart(e.Timestamp), monthEnd(e.Timestamp)).Scan(&prevHash)
    // NULL ⇒ first row in partition. For continuity, we'll also fetch the
    // previous partition's last hash as bootstrap on first event of a month
    // (handled by partition-manager when it creates the partition and writes
    // a "boundary" system event referencing the previous chain tip).

    canonical := audit.Canonical(e, prevHash)
    entryHash := audit.HMAC(c.currentKey, canonical)

    _, err := tx.Exec(ctx, `
        INSERT INTO audit.audit_log (
            event_id, timestamp, actor_type, actor_id, actor_ip,
            action, resource_type, resource_id, org_id, team_id, project_id,
            details, result, previous_hash, entry_hash, hmac_key_version
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
    `, e.EventID, e.Timestamp, e.ActorType, e.ActorID, nullIfEmpty(e.ActorIP),
       string(e.Action), e.ResourceType, e.ResourceID, nullUUID(e.OrgID),
       nullUUID(e.TeamID), nullUUID(e.ProjectID),
       mustJSON(e.Details), string(e.Result),
       prevHash, entryHash, c.currentKeyVersion)

    if isUniqueViolation(err, "audit_log_event_id_key") {
        // Duplicate delivery — accept.
        msg.Ack()
        return
    }
    if err != nil {
        msg.Nak()
        return
    }

    // Project risk lifecycle events (see §5).
    if e.Action.Domain() == "risk" {
        if err := c.projector.Project(ctx, tx, e); err != nil {
            msg.Nak()
            return
        }
    }

    if err := tx.Commit(ctx); err != nil {
        msg.Nak()
        return
    }
    msg.Ack()
    c.metrics.EventsTotal.WithLabelValues(string(e.Action)).Inc()

    // SIEM fan-out (best-effort, never blocks ack).
    c.siem.Enqueue(&e)
}
```

Key properties:
- `pg_advisory_xact_lock` serialises inserts per partition, preventing race on `previous_hash`.
- Idempotency via `event_id` unique constraint (add `UNIQUE (event_id)` in migration 032).
- If HMAC key fetch fails, worker blocks (doesn't drop events) and raises `AuditKeyUnavailable` metric.

---

## 4. Risk Lifecycle Model

### 4.1 Dedicated table vs derived

**Decision: both.** The generic `audit.audit_log` is the source of truth and contains every action. `audit.risk_events` is a denormalised projection built by the consumer so:

- Per-risk timeline query (`GET /risks/{id}/history`) is a single indexed lookup on `(risk_id, occurred_at)`, not a scan across the generic audit table.
- UI can render rich before/after diffs from structured columns without re-parsing `details` JSON.
- Rebuild is safe: `TRUNCATE audit.risk_events; SELECT audit.rebuild_risk_events(...)` replays from audit_log. This is the only supported way to recover from a corrupted projection.

`audit.risk_events.audit_log_id` + `audit_log_ts` pair lets the UI deep-link from the timeline to the generic audit row for chain proof.

### 4.2 What counts as material

A risk event is emitted if **any** of:

- `event_type = 'created'` (always)
- `event_type = 'status_changed'` (always)
- `event_type = 'resolved'|'reopened'|'muted'|'unmuted'|'assigned'` (user actions, always)
- `event_type = 'score_changed'` AND `|after - before| >= 0.5`
- `event_type = 'relation_added'|'relation_removed'` (structural change, always)
- `event_type = 'evidence_changed'` AND evidence fingerprint (SHA-256 of the evidence blob set) actually differs
- `event_type = 'seen_again'` AND the previous `seen_again`/`created` for this risk was >= 7 days ago (deduplicate noise from consecutive scans)
- `event_type = 'note_added'` (always)

Non-material recomputations (e.g. 0.1-point score drift from a rule catalog update) still go into `audit.audit_log` with `result=success` and `details.materiality=noise`, but **skip** the `risk_events` projection. This keeps the UI timeline readable without losing forensic detail.

### 4.3 UI consumption

Frontend: new tab on the risk detail page.

```ts
// web/features/risks/hooks.ts
export function useRiskHistory(riskId: string) {
  return useQuery<RiskEvent[]>({
    queryKey: ["risk", "history", riskId],
    queryFn: () => api.get(`/api/v1/risks/${riskId}/history`),
  });
}
```

Each event renders as a timeline card with:
- Icon + event_type label
- Actor (user display name or "System" for automated)
- Relative time ("2 hours ago") with absolute tooltip
- Structured diff for score/status/relation changes (before → after)
- Note if present
- Link to generic audit row for chain proof (opens audit detail modal)

---

## 5. Export API Design

### 5.1 Sync path — `GET /api/v1/audit`

Lightweight, paginated. Used by the in-app audit explorer and by small exports.

```
GET /api/v1/audit?
    from=2026-01-01T00:00:00Z&
    to=2026-04-17T23:59:59Z&
    action=risk.resolved&
    actor=user-123&
    resource_type=risk&
    resource_id=abc&
    org_id=...&           # platform_admin only; default = caller's org
    page_size=100&
    page_token=eyJ...
```

- Permissions: `audit.read`. Platform admins can pass `org_id` to read cross-tenant; otherwise caller's `org_id` is implicit.
- Pagination: opaque cursor (`page_token`) encoding `(last_timestamp, last_id)` — keyset pagination, no OFFSET.
- Response includes `next_page_token` if more results.
- **Hard cap: 10,000 rows per request, 100 rows per page.** Caller must use exports for larger windows. Return `413 Payload Too Large` with `code=USE_EXPORT_JOB` and a hint URL.
- Streaming: `audit_log` rows stream out as they're read (no full materialisation in memory).

### 5.2 Async path — `POST /api/v1/audit/exports`

```json
POST /api/v1/audit/exports
Authorization: Bearer <token>

{
  "filters": {
    "from": "2025-01-01T00:00:00Z",
    "to":   "2026-04-17T23:59:59Z",
    "actions": ["risk.*", "governance.*"],   // glob; resolved server-side
    "resource_type": "risk"
  },
  "format": "ndjson",
  "encrypt_gpg": true,
  "gpg_recipient": "compliance-team-pubkey-fingerprint"
}

→ 202 Accepted
{
  "job_id": "0c134592-9e65-4aa2-98a2-d6f05c6112c0",
  "status": "queued"
}
```

`GET /api/v1/audit/exports/{id}`:

```json
{
  "job_id": "...",
  "status": "succeeded",
  "progress_rows": 1234567,
  "total_rows": 1234567,
  "format": "ndjson",
  "encrypted": true,
  "download_url": "https://sc.example.com/api/v1/audit/exports/.../artifact",
  "expires_at": "2026-04-24T15:00:00Z",
  "sha256": "a1b2…"
}
```

Artifact download endpoint streams the MinIO object (signed URL acceptable in air-gapped deployments; for proxied deployments the controlplane streams directly so no MinIO exposure is needed).

### 5.3 Export job execution

Runs on `cmd/audit-worker/` (same binary, separate goroutine pool). Flow:

1. Claim a `queued` job with `UPDATE ... SET status='running', started_at=now() WHERE id = $1 AND status='queued' RETURNING *` (atomic claim).
2. Compute `total_rows` with a cheap `SELECT COUNT(*)` under the filter (bounded by an enforced filter window of 2 years).
3. Open a server-side cursor on the filtered query, iterate in 1000-row batches.
4. For each batch, write rows to a local temp file in the configured `format`.
5. Update `progress_rows` every 10,000 rows (reservable for UI progress bar).
6. On complete:
   - Compute SHA-256 of the file.
   - If `encrypt_gpg=true`, GPG-encrypt to the recipient key (key material from Vault path `sc/audit/export-keys/<recipient>`).
   - Upload to MinIO at `audit-exports/<org_id>/<job_id>/<filename>.<ext>`.
   - Update job row: status=succeeded, object_key, sha256, size_bytes, expires_at=now()+7d.

Backpressure: max 4 concurrent export jobs per worker; excess stays in `queued`.

Failure handling: job moves to `failed` with `error_message`. UI shows retry button.

### 5.4 Access control

- `audit.read` (team_admin, security_lead, auditor, platform_admin, security_director) → can call `/audit` paginated, filtered to own org (platform_admin can cross-tenant with explicit `org_id`).
- `audit.export` (security_lead, auditor, platform_admin, security_director) → can create export jobs.
- `audit.verify` (platform_admin, auditor) → can read `/audit/integrity` (verification run results) and trigger ad-hoc verification.

Artifact URLs are signed and short-lived (15 min). Every download is itself an audit event (`audit.export.downloaded`).

---

## 6. Implementation Plan (step-by-step)

Eight chunks. Each is independently shippable and can be rolled back by the previous chunk's down migration + binary.

### Chunk 1 — HMAC chain verifier (before anything else)

Goal: prove the *existing* `audit.audit_log` rows are all `previous_hash=''`/`entry_hash=''` (which they are — no chain computed yet). Ship the verifier so when we flip the switch we know row 1 of the real chain starts clean.

- [ ] `pkg/audit/canonical.go` + tests — RFC 8785-lite: sort keys, UTF-8, no whitespace.
- [ ] `pkg/audit/hmac.go` + tests — `Compute(prev, canonical, key) string`, `Verify(row, prev, key) bool`.
- [ ] `pkg/audit/redactor.go` + tests — deny-list + truncation.
- [ ] `pkg/audit/actions.go` + `actions_test.go` — typed constants + drift-check against taxonomy doc.
- [ ] `internal/audit/integrity/verifier.go` — per-partition verify.
- [ ] Migration 032 (append-only trigger, hmac_keys table, UNIQUE (event_id), integrity_checks).
- [ ] Run verifier once in staging against the empty-chain rows: expect `outcome=partial` with message "chain not started". Log baseline.

### Chunk 2 — Partition management

- [ ] Migration 033 — `ensure_partition(DATE)` function + 13-month seed.
- [ ] `internal/audit/partition/manager.go` — daily cron; creates next-month partition, detaches partitions older than retention limit.
- [ ] Wire cron into `cmd/audit-worker/main.go` (initially sits alongside the existing no-op worker).

### Chunk 3 — Audit-worker consumer (the write path)

- [ ] Add `UNIQUE (event_id)` constraint to each existing partition (default + new monthlies).
- [ ] `internal/audit/consumer/consumer.go` with advisory lock + idempotency + projection hooks.
- [ ] Extend `pkg/audit/emitter.go` to run redactor + publish to NATS with proper idempotency key.
- [ ] `cmd/audit-worker/main.go` wiring: consumer + partition cron + verifier cron.
- [ ] Deploy the worker to prod **with the consumer disabled by env flag** (`AUDIT_CONSUMER_ENABLED=false`). Only the partition cron runs.

### Chunk 4 — Enable write path in shadow mode

- [ ] Create dedicated DB role `sentinelcore_audit_writer` with INSERT-only grants; update audit-worker's connection string in `/opt/sentinelcore/env/sentinelcore.env` to use it.
- [ ] Flip `AUDIT_CONSUMER_ENABLED=true` for audit-worker only.
- [ ] Existing handlers still call the old emitter path (which historically just best-effort inserts). That continues to write to `audit_log` too — **this is intentional**. We now have two writers hitting `audit_log`: the old path (deprecated) + the new NATS-driven worker. The old path produces rows with `previous_hash=''` and gets `outcome=partial` from the verifier. The new rows form a proper chain.
- [ ] Run integrity verifier every hour for 48 hours. Expect new-path rows to pass; old-path rows to show as a gap.

### Chunk 5 — Migrate handlers off the legacy emitter path

- [ ] Rewrite `pkg/audit/emitter.go` so `Emit()` ONLY publishes to NATS. Remove the direct DB write path.
- [ ] This is the breaking change: any missed handler stops auditing until the consumer picks up the NATS message. Verify every call site via `go vet` + a new static analysis rule that rejects direct `audit_log` SQL outside the consumer.
- [ ] Deploy controlplane + all workers with the new emitter.
- [ ] Verifier's "gap" rows stop accumulating. All new rows are chained.

### Chunk 6 — Risk lifecycle projection

- [ ] Migration 034 (`audit.risk_events`).
- [ ] `internal/audit/consumer/projector.go` — action → risk_event mapping with materiality filter.
- [ ] `internal/controlplane/api/risks_history.go` handler + route.
- [ ] Frontend: new `Timeline` tab on risk detail page; `useRiskHistory` hook.
- [ ] One-off backfill job: replay existing `audit_log` rows where `action LIKE 'risk.%'` into `risk_events`. Run under `platform_admin` break-glass session.

### Chunk 7 — Export pipeline

- [ ] Migration 035 (`audit.export_jobs`).
- [ ] `internal/audit/export/` service + CSV + NDJSON writers + GPG encryptor.
- [ ] `internal/controlplane/api/audit_export.go` + routes.
- [ ] Audit-worker grows a "export" goroutine pool; claims `queued` jobs.
- [ ] MinIO bucket `audit-exports` + lifecycle rule to auto-delete after 7 days.
- [ ] Frontend: `/settings/audit/exports` page with job list + create form.

### Chunk 8 — Taxonomy coverage + handler integration

This is the biggest chunk by line count but lowest risk per line: visit every handler in §3.3 and wire up the emit. Stopping criterion: every route in `routes.go` produces an audit event for every state-changing call, verified by integration test `TestAuditCoverageMatrix` which POSTs/PATCHes/DELETEs every route as an `owner` and asserts a matching audit row appears within 2 seconds.

- [ ] Auth + SSO handlers.
- [ ] API-key handlers + sampled middleware emitter for `apikey.used`.
- [ ] Scan / finding / risk handlers (the risk ones feed §6's projection).
- [ ] Governance handlers.
- [ ] SSO provider config handlers.
- [ ] Organisation / team / user handlers + `rbac.*` from the policy cache reloader.
- [ ] Notification + webhook handlers.
- [ ] `TestAuditCoverageMatrix` in `test/integration/`.

### Chunk 9 — Hourly integrity verification + alerting

- [ ] `internal/audit/integrity/scheduler.go` hourly cron in audit-worker.
- [ ] For each "warm" partition (current + last 3 months) verify the whole chain; for older partitions, verify a random sample of rows + the boundary row.
- [ ] On any failure: write `audit.integrity.check.failed` event, raise Prometheus `sentinelcore_audit_integrity_check_total{result="fail"}` counter, page on-call via webhook.
- [ ] `GET /api/v1/audit/integrity` handler + UI surface on the settings page.

---

## 7. Security & Compliance Pitfalls

**Must avoid:**

1. **"Insert and forget."** Without the HMAC chain, audit logs are trivially tamperable by anyone with DB access. The chain + INSERT-only role + append-only trigger are all non-negotiable.
2. **HMAC key loss = unverifiable history.** Old keys must be kept in Vault *forever* (`kv/delete` disabled on `sc/audit/hmac/*`). The `hmac_keys` table in the DB is a catalog but doesn't hold the secret. Vault unseal runbook (from Phase 3) gates access.
3. **Secrets in `details`.** The redactor is mandatory. Violations are caught in `TestRedactorFailsClosedOnSecretFields`. Add a CI job that greps for `details.*password` / `details.*secret` etc. in emitter call sites.
4. **Cross-tenant leak via raw log access.** RLS on `audit_log` prevents tenant crossover. Platform admins bypass via the session variable, but *every* bypass is itself an audit event (`audit.global_access.granted`) with the specific query logged.
5. **Replay / duplicate rows corrupting the chain.** Idempotency key on `event_id` + advisory lock in the consumer. The consumer MUST NOT write two rows for the same event even under NATS redelivery.
6. **Large `details` bloating the table.** Truncator caps strings at 512 chars and the total payload at 64 KB. Anything larger is rejected with a warning metric.
7. **PII in exports to cold storage.** Exports can be GPG-encrypted. Add a big red warning to the UI when the unencrypted option is selected.
8. **Export artifact leak via predictable URLs.** Download URLs are short-lived and signed; the object key includes the UUID job id which is unguessable.
9. **Retention vs legal hold conflict.** The partition manager NEVER drops partitions; it detaches and archives to cold storage (MinIO lifecycle tier). Legal hold API (Phase 4 feature) prevents archive. Final purge is manual, logged as `audit.partition.purged`, and requires dual approval.
10. **Time skew on actor_ip.** Behind a proxy, `r.RemoteAddr` is the proxy. Always read `X-Forwarded-For` (first value) first, as already done in `pkg/audit/clientIP`. Audit this helper's test matrix.
11. **Deleted user's events.** When a user is disabled/deleted, their `actor_id` string remains in history. Don't FK `actor_id` → `core.users.id`; treat it as opaque. We already do this, but enforce via a comment + review.

---

## 8. Safe Rollout Plan

**Staging first, then prod.** At each prod step, the verifier runs hourly and the previous step is revertible by a down migration.

| Day | Step | Revert path |
|---|---|---|
| 1  | Deploy chunks 1 + 2 (verifier + partitions). No behaviour change; just infrastructure. | down migration 033 (drop seeded partitions), down 032 (drop trigger/table). |
| 2  | Deploy chunk 3 (audit-worker with consumer disabled). Partition cron runs. | revert audit-worker binary to previous. |
| 3  | Turn consumer on in staging for 48h. Verify new rows form a valid chain. | env flag off. |
| 5  | Turn consumer on in prod. Old emitter path still writes. Rows arrive via both paths. Verifier logs "gap" rows from the old path but doesn't alert (tuned threshold). | env flag off; no data loss. |
| 8  | Deploy chunk 5 (emitter rewrite). Now ALL audit rows go via NATS → consumer. Old-path gaps stop accumulating. | revert controlplane binary + worker bin; old path resumes. |
| 12 | Deploy chunk 6 (risk lifecycle) in staging. Backfill runs in staging. Verify timeline UI against a known risk. | drop `audit.risk_events` table, revert UI feature flag. |
| 14 | Deploy chunk 6 to prod. Run backfill. | drop table; audit_log is the source; any re-run rebuilds. |
| 16 | Deploy chunk 7 (export pipeline) in staging. Generate test exports; verify GPG roundtrip. | revert; no new routes until re-deployed. |
| 18 | Deploy chunk 7 to prod. | same. |
| 20 | Start chunk 8 handler integration in batches of 5 handlers per day. Each batch has its own integration test. Coverage matrix fills in. | per-batch revert. |
| 30 | Deploy chunk 9 (hourly integrity verifier + alerting). Let it run 7 days with alerting in shadow mode (log only). | env flag off alerting. |
| 37 | Promote alerts to PagerDuty. | revert routing. |

**Exit criteria (compliance sign-off):**

- Integrity verifier passes daily for 30 consecutive days.
- `TestAuditCoverageMatrix` is green; every state-changing route produces an event.
- `actions.go` ↔ `docs/audit-action-taxonomy.md` drift test green in CI.
- HMAC key rotation drill completed: v1 → v2 rotation, v1-keyed rows still verify, new rows use v2. Documented in operator runbook.
- One successful GPG-encrypted export delivered to the compliance team mailbox and decrypted end-to-end.
- Penetration-test attempt to UPDATE/DELETE an `audit_log` row from the controlplane DB user is rejected with `insufficient_privilege`.

---

## Appendix A — Naming conventions

- Action codes: lowercase, dot-separated, past tense. Never rename; deprecate with `.deprecated` alias.
- Table names: singular schema (`audit`), plural table (`audit_log`, `risk_events`, `export_jobs`, `integrity_checks`, `hmac_keys`).
- Metric names: `sentinelcore_audit_<noun>_<verb>_total` / `_seconds`. Label cardinality capped at action_count × result_count.

## Appendix B — Cardinality budget

| Source | Rate (events/sec) | Monthly volume | Partition size |
|---|---|---|---|
| auth + sso | ~10 (peak 100) | ~26M | ~6 GB with JSON |
| scans + findings | ~50 (avg) | ~130M | ~30 GB |
| risks (projected subset) | ~5 | ~13M rows in risk_events | ~2 GB |
| apikey.used sampled | ~2 | ~5M | ~1 GB |
| webhook delivery | ~2 | ~5M | ~1 GB |
| **Total audit_log monthly** | ~70 avg | **~180M rows** | **~40 GB** |

Monthly partition model absorbs this; indexes are per-partition so writes stay O(log n) in current partition only. Two years of history = 24 partitions = ~1 TB. MinIO cold tier archival after 12 months brings hot storage to ~500 GB.

## Appendix C — Operator runbooks

Separate docs:

- `docs/audit-operator-runbook.md`:
  - "Integrity check failed for partition X" → isolation + key version check + forensic path.
  - "HMAC key rotation" → ceremony + verification.
  - "Export job stuck in running" → diagnostic queries + safe retry.
  - "Partition manager lag" → manual `SELECT audit.ensure_partition(...)` invocation.
  - "Break-glass admin read" → activation, logging, post-incident report.
