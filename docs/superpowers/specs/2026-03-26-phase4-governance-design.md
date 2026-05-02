# Phase 4: Enterprise Governance, Reporting, and Operational Hardening

**Status:** Design Approved
**Date:** 2026-03-26
**Branch:** phase4/governance (to be created)

## 1. Objectives

Turn SentinelCore from a scanning engine into an enterprise-ready AppSec platform by adding:

- Configurable finding triage workflow with optional multi-party approval
- Finding assignment, ownership, and SLA tracking
- Risk acceptance and false-positive workflows with audit trails
- Emergency scan stop (kill switch)
- In-app notification system with webhook delivery
- Data retention lifecycle (active → archived → purge_pending → purged) with legal hold
- Dashboard-ready reporting APIs
- Compliance-oriented evidence and audit retrieval

All governance features are additive — existing SAST, DAST, and Correlation Engine behavior is preserved unchanged.

## 2. Architecture Approach

**Option B: Layered Governance Modules in Control Plane**

Governance logic lives as internal packages consumed by the existing control plane. Two new background worker binaries handle async tasks:

```
internal/
  governance/
    workflow.go        # Generic approval workflow engine
    triage.go          # Finding triage orchestration
    assignment.go      # Ownership tracking, team/user assignment
    retention.go       # Retention policy evaluation, lifecycle transitions
    settings.go        # Org-level governance configuration
    types.go           # Shared types
  notification/
    service.go         # Notification creation, fan-out
    webhook.go         # Webhook delivery with retry
    types.go           # Types
  controlplane/api/
    governance.go      # REST: /api/v1/governance/*
    notifications.go   # REST: /api/v1/notifications/*
    reports.go         # REST: /api/v1/reports/*
    retention.go       # REST: /api/v1/retention/*

cmd/
  retention-worker/main.go    # CronJob: evaluate policies, archive, purge
  notification-worker/main.go # Worker: deliver webhooks, retry failures
```

**Why this approach:**
- Follows existing pattern: control plane owns REST API, workers handle background tasks
- Governance is a policy layer, not a data processing pipeline
- Future extraction path: packages have no direct dependency on controlplane internals — accept interfaces (DB pool, NATS publisher, audit emitter)

## 3. Schema Changes

### 3.1 New Schema: governance

```sql
CREATE SCHEMA IF NOT EXISTS governance;
```

### 3.2 Org-Level Governance Settings

```sql
CREATE TABLE governance.org_settings (
    org_id       UUID PRIMARY KEY REFERENCES core.organizations(id),
    require_approval_for_risk_acceptance  BOOLEAN DEFAULT false,
    require_approval_for_false_positive   BOOLEAN DEFAULT false,
    require_approval_for_scope_expansion  BOOLEAN DEFAULT false,
    default_finding_sla_days             JSONB DEFAULT '{"critical":3,"high":7,"medium":30,"low":90}',
    retention_policies                    JSONB,
    updated_at   TIMESTAMPTZ DEFAULT now(),
    updated_by   UUID
);
```

### 3.3 Approval Requests

```sql
CREATE TABLE governance.approval_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES core.organizations(id),
    team_id       UUID REFERENCES core.teams(id),
    request_type  TEXT NOT NULL,     -- 'risk_acceptance', 'false_positive', 'scope_expansion'
    resource_type TEXT NOT NULL,     -- 'finding', 'scan_target'
    resource_id   UUID NOT NULL,
    requested_by  UUID NOT NULL REFERENCES core.users(id),
    reason        TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    decided_by    UUID REFERENCES core.users(id),
    decision_reason TEXT,
    decided_at    TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ,
    created_at    TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT approval_status_check CHECK (status IN ('pending','approved','rejected','expired'))
);
CREATE INDEX idx_approval_org_status ON governance.approval_requests(org_id, status);
CREATE INDEX idx_approval_resource ON governance.approval_requests(resource_type, resource_id);
CREATE INDEX idx_approval_expiring ON governance.approval_requests(expires_at) WHERE status = 'pending';
```

### 3.4 Finding Assignments

```sql
CREATE TABLE governance.finding_assignments (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   UUID NOT NULL REFERENCES findings.findings(id),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    team_id      UUID REFERENCES core.teams(id),
    assigned_to  UUID NOT NULL REFERENCES core.users(id),
    assigned_by  UUID NOT NULL REFERENCES core.users(id),
    due_at       TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'active',
    note         TEXT,
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT assignment_status_check CHECK (status IN ('active','completed','reassigned'))
);
CREATE INDEX idx_assignment_assignee ON governance.finding_assignments(assigned_to, status);
CREATE INDEX idx_assignment_finding ON governance.finding_assignments(finding_id);
```

### 3.5 SLA Violations

```sql
CREATE TABLE governance.sla_violations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id   UUID NOT NULL REFERENCES findings.findings(id),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    severity     TEXT NOT NULL,
    sla_days     INTEGER NOT NULL,
    deadline_at  TIMESTAMPTZ NOT NULL,
    violated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at  TIMESTAMPTZ,
    escalated    BOOLEAN DEFAULT false,
    updated_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_sla_org_unresolved ON governance.sla_violations(org_id) WHERE resolved_at IS NULL;
```

### 3.6 Notifications

```sql
CREATE TABLE governance.notifications (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    user_id      UUID NOT NULL,
    category     TEXT NOT NULL,
    title        TEXT NOT NULL,
    body         TEXT,
    resource_type TEXT,
    resource_id  UUID,
    read         BOOLEAN DEFAULT false,
    created_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_notif_user_unread ON governance.notifications(user_id) WHERE read = false;
CREATE INDEX idx_notif_user_created ON governance.notifications(user_id, created_at DESC);
```

### 3.7 Webhook Configuration and Delivery

```sql
CREATE TABLE governance.webhook_configs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    name         TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret_encrypted BYTEA,       -- AES-256-GCM encrypted HMAC signing secret
    secret_key_id    TEXT,        -- KMS key ID used for encryption (for key rotation)
    events       TEXT[] NOT NULL,
    enabled      BOOLEAN DEFAULT true,
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_webhook_org ON governance.webhook_configs(org_id);

CREATE TABLE governance.webhook_deliveries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id   UUID NOT NULL REFERENCES governance.webhook_configs(id),
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER DEFAULT 0,
    last_attempt TIMESTAMPTZ,
    next_retry   TIMESTAMPTZ,
    response_code INTEGER,
    response_body TEXT,           -- truncated to 4KB at write time
    created_at   TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT delivery_status_check CHECK (status IN ('pending','delivered','failed','exhausted'))
);
CREATE INDEX idx_delivery_pending ON governance.webhook_deliveries(status, next_retry)
    WHERE status IN ('pending', 'failed');
```

### 3.8 Retention Records

```sql
CREATE TABLE governance.retention_records (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id  UUID NOT NULL,
    lifecycle    TEXT NOT NULL DEFAULT 'active',
    retention_days INTEGER NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    archived_at  TIMESTAMPTZ,
    purge_after  TIMESTAMPTZ,
    purged_at    TIMESTAMPTZ,
    legal_hold   BOOLEAN DEFAULT false,
    legal_hold_by UUID,
    legal_hold_reason TEXT,
    created_at   TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT lifecycle_check CHECK (lifecycle IN ('active','archived','purge_pending','purged'))
);
CREATE INDEX idx_retention_lifecycle ON governance.retention_records(lifecycle, expires_at);
CREATE INDEX idx_retention_legal_hold ON governance.retention_records(org_id) WHERE legal_hold = true;
CREATE UNIQUE INDEX idx_retention_resource ON governance.retention_records(resource_type, resource_id);
```

### 3.9 Emergency Stop

```sql
CREATE TABLE governance.emergency_stops (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES core.organizations(id),
    scope       TEXT NOT NULL,
    scope_id    UUID,
    reason      TEXT NOT NULL,
    activated_by UUID NOT NULL REFERENCES core.users(id),
    activated_at TIMESTAMPTZ DEFAULT now(),
    deactivated_by UUID,
    deactivated_at TIMESTAMPTZ,
    active      BOOLEAN DEFAULT true,
    CONSTRAINT scope_check CHECK (scope IN ('all','team','project','scan_job'))
);
CREATE INDEX idx_emergency_active ON governance.emergency_stops(org_id) WHERE active = true;
```

### 3.10 RLS Policies

All governance tables get RLS enabled. Tables linked to findings use **team-membership-based isolation** (matching the existing `findings.findings` RLS pattern). Org-wide tables use org-level isolation.

```sql
ALTER TABLE governance.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.finding_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhook_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.retention_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.emergency_stops ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.sla_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.org_settings ENABLE ROW LEVEL SECURITY;

-- Team-scoped tables (finding-related): use team_memberships join
-- This matches the existing RLS model in findings.findings
CREATE POLICY team_isolation ON governance.approval_requests
    USING (team_id IN (
        SELECT tm.team_id FROM core.team_memberships tm
        WHERE tm.user_id = current_setting('app.current_user_id')::uuid
    ) OR team_id IS NULL AND org_id = current_setting('app.current_org_id')::uuid);

CREATE POLICY team_isolation ON governance.finding_assignments
    USING (team_id IN (
        SELECT tm.team_id FROM core.team_memberships tm
        WHERE tm.user_id = current_setting('app.current_user_id')::uuid
    ));

CREATE POLICY team_isolation ON governance.sla_violations
    USING (org_id IN (
        SELECT DISTINCT t.org_id FROM core.team_memberships tm
        JOIN core.teams t ON t.id = tm.team_id
        WHERE tm.user_id = current_setting('app.current_user_id')::uuid
    ));

-- User-scoped: notifications visible only to recipient
-- Admin bypass: platform_admin can query all org notifications via separate admin endpoint
CREATE POLICY user_notifications ON governance.notifications
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Org-scoped tables (admin-managed): org-level isolation
CREATE POLICY org_isolation ON governance.webhook_configs
    USING (org_id = current_setting('app.current_org_id')::uuid);
CREATE POLICY org_isolation ON governance.retention_records
    USING (org_id = current_setting('app.current_org_id')::uuid);
CREATE POLICY org_isolation ON governance.emergency_stops
    USING (org_id = current_setting('app.current_org_id')::uuid);
CREATE POLICY org_isolation ON governance.org_settings
    USING (org_id = current_setting('app.current_org_id')::uuid);
```

**Note:** The existing `UpdateFindingStatus` handler must be fixed to use `db.WithRLS` before the governance approval workflow can safely build on it. This is a prerequisite task for Week 1.

### 3.11 Modifications to Existing Tables

```sql
-- findings.findings additions
ALTER TABLE findings.findings ADD COLUMN org_id UUID REFERENCES core.organizations(id);
ALTER TABLE findings.findings ADD COLUMN assigned_to UUID REFERENCES core.users(id);
ALTER TABLE findings.findings ADD COLUMN sla_deadline TIMESTAMPTZ;
ALTER TABLE findings.findings ADD COLUMN legal_hold BOOLEAN DEFAULT false;
-- Backfill org_id from project → team → org chain:
-- UPDATE findings.findings f SET org_id = (
--   SELECT t.org_id FROM core.projects p JOIN core.teams t ON t.id = p.team_id WHERE p.id = f.project_id
-- ) WHERE f.org_id IS NULL;

-- scans.scan_jobs additions
ALTER TABLE scans.scan_jobs ADD COLUMN emergency_stopped BOOLEAN DEFAULT false;
ALTER TABLE scans.scan_jobs ADD COLUMN stopped_by UUID;
ALTER TABLE scans.scan_jobs ADD COLUMN stopped_reason TEXT;
```

## 4. Workflow & State Machine Design

### 4.1 Finding Triage with Configurable Approval

**Valid status transitions (invalid transitions return 422):**

| From | Allowed To |
|------|-----------|
| new | confirmed, false_positive, accepted_risk |
| confirmed | in_progress, false_positive, accepted_risk |
| in_progress | mitigated, false_positive, accepted_risk |
| mitigated | resolved, reopened |
| resolved | reopened |
| reopened | confirmed, in_progress, false_positive, accepted_risk |
| accepted_risk | reopened |
| false_positive | reopened |

**Approval flow:**

1. User calls `PATCH /api/v1/findings/:id/status` with target status (existing route)
2. Handler validates the transition against the matrix above; rejects invalid transitions with 422
3. If target is `accepted_risk` or `false_positive`:
   - Check `governance.org_settings` for approval requirement
   - If approval required: create `governance.approval_requests` with `pending` status, emit `approval_requested` notification, return 202 Accepted with approval_id
   - If not required: execute transition directly
4. Approver calls `POST /api/v1/governance/approvals/:id/decide` (requires `governance.approvals.decide` permission)
   - If approved: execute the original status transition, emit audit event
   - If rejected: mark request as rejected, notify requester, finding stays at current status
5. Expired approvals (checked by retention worker): mark as expired, notify requester

**Prerequisite:** Fix existing `UpdateFindingStatus` handler to use `db.WithRLS` (currently queries without RLS session variables).

### 4.2 Emergency Stop (Kill Switch)

1. Admin calls `POST /api/v1/governance/emergency-stop`
2. Insert `governance.emergency_stops` record with `active=true`
3. Publish to NATS `governance.estop.activated` with scope payload
4. Orchestrator subscribes → cancels matching in-flight scan jobs (set `emergency_stopped=true`)
5. Workers subscribe → abort current work, return partial results
6. New scan submissions check for active emergency stops before dispatch
7. Admin calls `POST /api/v1/governance/emergency-stop/lift` to deactivate
8. Publish `governance.estop.lifted` → normal operations resume

### 4.3 Retention Lifecycle

```
active ──(expires_at passed)──→ archived ──(purge_after passed)──→ purge_pending ──(no legal hold)──→ purged
                                                                        │
                                                                   [legal_hold=true]
                                                                        │
                                                                   stays at purge_pending
```

**Retention worker cycle (CronJob, hourly):**
1. `active` → `archived`: resources past `expires_at`
2. `archived` → `purge_pending`: resources past `purge_after` (expires_at + grace_period)
3. `purge_pending` → `purged`: resources without legal hold — execute hard delete of underlying data
4. Audit event for every transition
5. Skip resources with `legal_hold=true` at purge step

**Resource-specific retention defaults (configurable per org):**

| Resource Type | Default Retention | Grace Period |
|--------------|-------------------|--------------|
| findings | 365 days | 30 days |
| evidence | 365 days | 30 days |
| audit_log | 730 days | 90 days (see note) |
| scan_job | 180 days | 14 days |
| notification | 90 days | 7 days |
| webhook_delivery | 30 days | 7 days |

### 4.4 SLA Tracking

- Finding creation → calculate `sla_deadline` from org settings + severity
- Assignment → can override deadline
- SLA checker (part of retention worker cron cycle):
  - 80% of deadline elapsed → emit `sla_warning` notification
  - Deadline passed → create `sla_violations` record, emit `sla_violated` notification
  - 48h after violation with no action → escalate (notify team lead)

### 4.5 Notification Events

| Event | NATS Subject | Recipients |
|-------|-------------|-----------|
| approval_requested | governance.notifications | Team users with `governance.approvals.decide` |
| approval_decided | governance.notifications | Original requester |
| finding_assigned | governance.notifications | Assignee |
| sla_warning | governance.notifications | Assignee + team lead |
| sla_violated | governance.notifications | Assignee + team lead + security admin |
| emergency_stop_activated | governance.notifications | All org admins |
| scan_completed | governance.notifications | Scan creator |
| retention_purge_scheduled | governance.notifications | Org admin |

## 5. API Design

### 5.1 Governance Settings

```
GET    /api/v1/governance/settings              → governance.settings.read
PUT    /api/v1/governance/settings              → governance.settings.write
```

### 5.2 Approvals

```
GET    /api/v1/governance/approvals             → governance.approvals.read
GET    /api/v1/governance/approvals/:id         → governance.approvals.read
POST   /api/v1/governance/approvals/:id/decide  → governance.approvals.decide
```

### 5.3 Finding Triage Extensions

```
POST   /api/v1/findings/:id/assign             → findings.triage
POST   /api/v1/findings/:id/legal-hold         → findings.legal_hold
```

### 5.4 Emergency Stop

```
POST   /api/v1/governance/emergency-stop        → governance.emergency_stop.activate
POST   /api/v1/governance/emergency-stop/lift   → governance.emergency_stop.lift
GET    /api/v1/governance/emergency-stop/active → governance.emergency_stop.activate
```

**Four-eyes principle:** The user who activated an emergency stop cannot be the same user who lifts it. The API enforces this check.

### 5.5 Notifications

```
GET    /api/v1/notifications                    → authenticated (own via RLS)
POST   /api/v1/notifications/:id/read          → authenticated
POST   /api/v1/notifications/read-all          → authenticated
GET    /api/v1/notifications/unread-count       → authenticated
```

### 5.6 Webhooks

```
GET    /api/v1/webhooks                         → webhooks.read
POST   /api/v1/webhooks                         → webhooks.manage
PUT    /api/v1/webhooks/:id                     → webhooks.manage
DELETE /api/v1/webhooks/:id                     → webhooks.manage
POST   /api/v1/webhooks/:id/test               → webhooks.manage
```

### 5.7 Retention

```
GET    /api/v1/retention/policies               → retention.read
PUT    /api/v1/retention/policies               → retention.manage
GET    /api/v1/retention/records                → retention.read
GET    /api/v1/retention/stats                  → retention.read
```

### 5.8 Reports

```
GET    /api/v1/reports/findings-summary         → reports.read
GET    /api/v1/reports/triage-metrics           → reports.read
GET    /api/v1/reports/compliance-status        → reports.read
GET    /api/v1/reports/scan-activity            → reports.read
  Query params: org_id, team_id, project_id, date_from, date_to
```

## 6. New RBAC Permissions

Added to the existing permission matrix:

| Permission | platform_admin | security_admin | appsec_analyst | auditor |
|-----------|:-:|:-:|:-:|:-:|
| governance.settings.read | Y | Y | N | Y |
| governance.settings.write | Y | Y | N | N |
| governance.approvals.read | Y | Y | Y | Y |
| governance.approvals.decide | Y | Y | N | N |
| governance.emergency_stop.activate | Y | Y | N | N |
| governance.emergency_stop.lift | Y | N | N | N |
| findings.triage | Y | Y | Y | N |
| findings.legal_hold | Y | Y | N | N |
| webhooks.read | Y | Y | Y | Y |
| webhooks.manage | Y | Y | N | N |
| retention.read | Y | Y | N | Y |
| retention.manage | Y | N | N | N |
| reports.read | Y | Y | Y | Y |

## 7. NATS Subjects (New)

```
governance.estop.activated         # Emergency stop activation
governance.estop.lifted            # Emergency stop deactivation
governance.notifications           # Notification events for fan-out
governance.webhook.delivery        # Webhook delivery tasks
```

Added to existing NATS stream configuration:

```go
{Name: "GOVERNANCE", Subjects: []string{"governance.>"}, MaxAge: 7 * 24 * time.Hour}
```

## 8. Audit Events (New)

All governance actions emit to `audit.events`:

| Action | Details |
|--------|---------|
| governance.settings.update | Changed fields |
| governance.approval.created | Request type, resource, requester |
| governance.approval.decided | Decision, decider, reason |
| governance.approval.expired | Request type, resource |
| finding.assigned | Finding ID, assignee, assigner, due date |
| finding.legal_hold.set | Finding ID, hold status, reason |
| governance.emergency_stop.activated | Scope, reason, activator |
| governance.emergency_stop.lifted | Stop ID, deactivator |
| webhook.created | Webhook name, URL, events |
| webhook.deleted | Webhook ID |
| retention.lifecycle.transition | Resource, from_state, to_state |
| retention.purge.executed | Resource type, resource ID |
| retention.legal_hold.set | Resource, hold status, reason |

## 9. Test Strategy

### 9.1 Unit Tests

- `internal/governance/workflow_test.go`: approval creation, decision, expiry, permission checks
- `internal/governance/triage_test.go`: triage with/without approval, SLA calculation
- `internal/governance/retention_test.go`: lifecycle transitions, legal hold blocking, policy evaluation
- `internal/governance/settings_test.go`: settings CRUD, defaults
- `internal/notification/service_test.go`: notification creation, fan-out, dedup
- `internal/notification/webhook_test.go`: delivery, retry logic, HMAC signing

### 9.2 Integration Tests

- Approval workflow end-to-end: create finding → triage → approval required → approve → state applied
- Emergency stop: activate → verify scans blocked → lift → verify scans resume
- Retention lifecycle: create resource → advance clock → verify transitions → verify purge
- Webhook delivery: configure webhook → trigger event → verify delivery with signature
- SLA tracking: create finding → advance clock → verify warning → verify violation
- RLS isolation: two orgs, verify no cross-tenant data access

### 9.3 Adversarial Tests

- Attempt approval without permission → denied
- Attempt to purge legal-hold resource → blocked
- Emergency stop scope boundaries: team stop doesn't affect other teams
- Webhook URL validation: reject private IPs (SSRF prevention)

## 10. Migration Plan

Single migration file: `migrations/004_governance.sql`

- Idempotent (IF NOT EXISTS / IF NOT COLUMN)
- Backward compatible: only adds new schema, tables, columns
- No data migration needed (all new tables)
- Rollback: `DROP SCHEMA governance CASCADE; ALTER TABLE findings.findings DROP COLUMN ...`

## 11. Docker Compose Additions

```yaml
retention-worker:
  build: { context: ., dockerfile: Dockerfile, target: retention-worker }
  environment:
    - DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel?sslmode=disable
    - NATS_URL=nats://nats:4222
  depends_on: [postgres, nats]

notification-worker:
  build: { context: ., dockerfile: Dockerfile, target: notification-worker }
  environment:
    - DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel?sslmode=disable
    - NATS_URL=nats://nats:4222
  depends_on: [postgres, nats]
```

## 12. Implementation Milestones

| Week | Deliverable |
|------|------------|
| 1 | Schema migration + governance types + settings CRUD |
| 2 | Approval workflow engine + triage integration |
| 3 | Finding assignment + SLA tracking |
| 4 | Emergency stop (kill switch) + NATS integration |
| 5 | Notification service + in-app notifications API |
| 6 | Webhook delivery system |
| 7 | Retention lifecycle engine + worker |
| 8 | Reporting APIs |
| 9 | Integration tests + security hardening |
| 10 | Documentation + PR preparation |

## 13. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Approval workflow adds latency to triage | Configurable per-org — orgs that don't need it skip it |
| Retention worker deletes wrong data | Legal hold as safety net, grace period, audit trail, soft-delete before hard-delete |
| Emergency stop race condition | Idempotent stop handling, NATS at-least-once delivery |
| Webhook SSRF | Dedicated `ValidateWebhookURL()` in `internal/notification/webhook.go`: (a) reject non-HTTPS (allow HTTP in dev only), (b) resolve hostname and check against `blockedCIDRs` from `pkg/scope/enforcer.go`, (c) reject embedded credentials in URL, (d) validate at both config-time and delivery-time (DNS rebinding defense) |
| Audit log hash chain integrity | Audit logs use `previous_hash`/`entry_hash` HMAC chain. Purging breaks chain verification. Solution: archive to cold storage (MinIO WORM bucket) before deleting from active table. Insert a "genesis" marker in the chain recording the truncation point. The retention worker archives audit partitions to MinIO before dropping them |
| Notification spam | Rate limiting per user, category-based dedup within time window |
| Schema migration on large tables | Only adding nullable columns to existing tables, no locks |
