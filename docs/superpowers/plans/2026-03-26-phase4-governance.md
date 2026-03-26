# Phase 4: Enterprise Governance Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add enterprise governance, triage workflows, notifications, retention, and reporting to SentinelCore without modifying existing SAST/DAST/Correlation Engine behavior.

**Architecture:** Governance as layered internal packages (`internal/governance/`, `internal/notification/`) consumed by the existing control plane, plus two new worker binaries (`cmd/retention-worker/`, `cmd/notification-worker/`). All governance tables live in a new `governance` schema with team-membership-based RLS.

**Tech Stack:** Go 1.22+, PostgreSQL 16 with RLS, NATS JetStream, AES-256-GCM for webhook secrets, existing `pkg/db`, `pkg/audit`, `pkg/auth` patterns.

**Spec:** `docs/superpowers/specs/2026-03-26-phase4-governance-design.md`

---

## File Structure

### New Files

```
internal/governance/types.go           # Shared types: ApprovalRequest, Assignment, SLAViolation, EmergencyStop, RetentionRecord, OrgSettings
internal/governance/transitions.go     # Finding status transition matrix and validation
internal/governance/settings.go        # OrgSettings CRUD (DB queries)
internal/governance/workflow.go        # Approval workflow engine: create, decide, expire
internal/governance/triage.go          # Triage orchestration: status change + approval gate
internal/governance/assignment.go      # Finding assignment: assign, reassign, complete
internal/governance/sla.go             # SLA deadline calculation and violation detection
internal/governance/retention.go       # Retention policy evaluation, lifecycle transitions
internal/governance/estop.go           # Emergency stop: activate, lift, check

internal/governance/types_test.go
internal/governance/transitions_test.go
internal/governance/settings_test.go
internal/governance/workflow_test.go
internal/governance/triage_test.go
internal/governance/assignment_test.go
internal/governance/sla_test.go
internal/governance/retention_test.go
internal/governance/estop_test.go

internal/notification/types.go         # NotificationEvent, WebhookConfig, DeliveryAttempt
internal/notification/service.go       # Create notifications, fan-out to channels
internal/notification/webhook.go       # Webhook delivery: HMAC signing, retry, SSRF validation
internal/notification/service_test.go
internal/notification/webhook_test.go

internal/controlplane/api/governance.go    # REST: settings, approvals, emergency stop
internal/controlplane/api/notifications.go # REST: notifications, webhooks
internal/controlplane/api/reports.go       # REST: dashboard-ready report endpoints
internal/controlplane/api/retention.go     # REST: retention policies and records

cmd/retention-worker/main.go           # CronJob binary
cmd/notification-worker/main.go        # NATS consumer binary

migrations/014_governance.up.sql        # All schema changes (forward)
migrations/014_governance.down.sql     # Rollback DDL
```

### Modified Files

```
internal/policy/rbac.go                # Add 13 new permissions to PermissionMatrix
internal/controlplane/server.go        # Register ~25 new routes
internal/controlplane/api/handlers.go  # No struct change needed (governance uses same Handlers)
internal/controlplane/api/findings.go  # Fix RLS bypass in UpdateFindingStatus, add transition validation
pkg/nats/client.go                     # Add GOVERNANCE stream to EnsureStreams
docker-compose.yml                     # Add retention-worker and notification-worker services
Dockerfile                             # Add build targets for new binaries
```

---

## Chunk 1: Foundation (Tasks 1-4)

### Task 1: Database Migration

**Files:**
- Create: `migrations/014_governance.up.sql`
- Create: `migrations/014_governance.down.sql`

- [ ] **Step 1: Write the up migration file**

```sql
-- migrations/014_governance.up.sql
-- Phase 4: Enterprise Governance schema

-- 1. New schema
CREATE SCHEMA IF NOT EXISTS governance;

-- 2. Org settings
CREATE TABLE IF NOT EXISTS governance.org_settings (
    org_id       UUID PRIMARY KEY REFERENCES core.organizations(id),
    require_approval_for_risk_acceptance  BOOLEAN DEFAULT false,
    require_approval_for_false_positive   BOOLEAN DEFAULT false,
    require_approval_for_scope_expansion  BOOLEAN DEFAULT false,
    default_finding_sla_days             JSONB DEFAULT '{"critical":3,"high":7,"medium":30,"low":90}',
    retention_policies                    JSONB DEFAULT '{"findings":{"retention_days":365,"grace_days":30},"evidence":{"retention_days":365,"grace_days":30},"audit_log":{"retention_days":730,"grace_days":90},"scan_job":{"retention_days":180,"grace_days":14},"notification":{"retention_days":90,"grace_days":7},"webhook_delivery":{"retention_days":30,"grace_days":7}}',
    updated_at   TIMESTAMPTZ DEFAULT now(),
    updated_by   UUID
);

-- 3. Approval requests
CREATE TABLE IF NOT EXISTS governance.approval_requests (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES core.organizations(id),
    team_id       UUID REFERENCES core.teams(id),
    request_type  TEXT NOT NULL,
    resource_type TEXT NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_approval_org_status ON governance.approval_requests(org_id, status);
CREATE INDEX IF NOT EXISTS idx_approval_resource ON governance.approval_requests(resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_approval_expiring ON governance.approval_requests(expires_at) WHERE status = 'pending';

-- 4. Finding assignments
CREATE TABLE IF NOT EXISTS governance.finding_assignments (
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
CREATE INDEX IF NOT EXISTS idx_assignment_assignee ON governance.finding_assignments(assigned_to, status);
CREATE INDEX IF NOT EXISTS idx_assignment_finding ON governance.finding_assignments(finding_id);

-- 5. SLA violations
CREATE TABLE IF NOT EXISTS governance.sla_violations (
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
CREATE INDEX IF NOT EXISTS idx_sla_org_unresolved ON governance.sla_violations(org_id) WHERE resolved_at IS NULL;

-- 6. Notifications
CREATE TABLE IF NOT EXISTS governance.notifications (
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
CREATE INDEX IF NOT EXISTS idx_notif_user_unread ON governance.notifications(user_id) WHERE read = false;
CREATE INDEX IF NOT EXISTS idx_notif_user_created ON governance.notifications(user_id, created_at DESC);

-- 7. Webhook configs
CREATE TABLE IF NOT EXISTS governance.webhook_configs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    name         TEXT NOT NULL,
    url          TEXT NOT NULL,
    secret_encrypted BYTEA,
    secret_key_id    TEXT,
    events       TEXT[] NOT NULL,
    enabled      BOOLEAN DEFAULT true,
    created_at   TIMESTAMPTZ DEFAULT now(),
    updated_at   TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_webhook_org ON governance.webhook_configs(org_id);

-- 8. Webhook deliveries
CREATE TABLE IF NOT EXISTS governance.webhook_deliveries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id   UUID NOT NULL REFERENCES governance.webhook_configs(id),
    event_type   TEXT NOT NULL,
    payload      JSONB NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',
    attempts     INTEGER DEFAULT 0,
    last_attempt TIMESTAMPTZ,
    next_retry   TIMESTAMPTZ,
    response_code INTEGER,
    response_body TEXT,
    created_at   TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT delivery_status_check CHECK (status IN ('pending','delivered','failed','exhausted'))
);
CREATE INDEX IF NOT EXISTS idx_delivery_pending ON governance.webhook_deliveries(status, next_retry)
    WHERE status IN ('pending', 'failed');

-- 9. Retention records
CREATE TABLE IF NOT EXISTS governance.retention_records (
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
CREATE INDEX IF NOT EXISTS idx_retention_lifecycle ON governance.retention_records(lifecycle, expires_at);
CREATE INDEX IF NOT EXISTS idx_retention_legal_hold ON governance.retention_records(org_id) WHERE legal_hold = true;
CREATE UNIQUE INDEX IF NOT EXISTS idx_retention_resource ON governance.retention_records(resource_type, resource_id);

-- 10. Emergency stops
CREATE TABLE IF NOT EXISTS governance.emergency_stops (
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
CREATE INDEX IF NOT EXISTS idx_emergency_active ON governance.emergency_stops(org_id) WHERE active = true;

-- 11. RLS
ALTER TABLE governance.org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.finding_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.sla_violations ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhook_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.retention_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.emergency_stops ENABLE ROW LEVEL SECURITY;

-- RLS policies
DO $$ BEGIN
CREATE POLICY org_isolation ON governance.org_settings USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY team_isolation ON governance.approval_requests
    USING (team_id IN (SELECT tm.team_id FROM core.team_memberships tm WHERE tm.user_id = current_setting('app.current_user_id')::uuid)
        OR (team_id IS NULL AND org_id = current_setting('app.current_org_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY team_isolation ON governance.finding_assignments
    USING (team_id IN (SELECT tm.team_id FROM core.team_memberships tm WHERE tm.user_id = current_setting('app.current_user_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY team_isolation ON governance.sla_violations
    USING (org_id IN (SELECT DISTINCT t.org_id FROM core.team_memberships tm JOIN core.teams t ON t.id = tm.team_id WHERE tm.user_id = current_setting('app.current_user_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY user_notifications ON governance.notifications
    USING (user_id = current_setting('app.current_user_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.webhook_configs USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.webhook_deliveries USING (
    webhook_id IN (SELECT id FROM governance.webhook_configs WHERE org_id = current_setting('app.current_org_id')::uuid));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.retention_records USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
CREATE POLICY org_isolation ON governance.emergency_stops USING (org_id = current_setting('app.current_org_id')::uuid);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 12. Modify existing tables
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES core.organizations(id);
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS assigned_to UUID REFERENCES core.users(id);
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS sla_deadline TIMESTAMPTZ;
ALTER TABLE findings.findings ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN DEFAULT false;

ALTER TABLE scans.scan_jobs ADD COLUMN IF NOT EXISTS emergency_stopped BOOLEAN DEFAULT false;
ALTER TABLE scans.scan_jobs ADD COLUMN IF NOT EXISTS stopped_by UUID;
ALTER TABLE scans.scan_jobs ADD COLUMN IF NOT EXISTS stopped_reason TEXT;
```

- [ ] **Step 2: Write the down migration file**

```sql
-- migrations/014_governance.down.sql
-- Rollback Phase 4: Enterprise Governance schema

ALTER TABLE findings.findings DROP COLUMN IF EXISTS org_id;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS assigned_to;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS sla_deadline;
ALTER TABLE findings.findings DROP COLUMN IF EXISTS legal_hold;

ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS emergency_stopped;
ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS stopped_by;
ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS stopped_reason;

DROP SCHEMA IF EXISTS governance CASCADE;
```

- [ ] **Step 3: Verify migration is syntactically valid**

Run: `psql -f migrations/014_governance.up.sql --set ON_ERROR_STOP=1 2>&1 | head -20` (or just verify the file was created)

- [ ] **Step 4: Commit**

```bash
git add migrations/014_governance.up.sql migrations/014_governance.down.sql
git commit -m "feat(phase4): add governance schema migration"
```

---

### Task 2: Governance Types and Transition Matrix

**Files:**
- Create: `internal/governance/types.go`
- Create: `internal/governance/transitions.go`
- Create: `internal/governance/transitions_test.go`

- [ ] **Step 1: Write governance types**

`internal/governance/types.go` — all shared structs:

```go
package governance

import "time"

// OrgSettings holds per-org governance configuration.
type OrgSettings struct {
    OrgID                          string          `json:"org_id"`
    RequireApprovalRiskAcceptance  bool            `json:"require_approval_for_risk_acceptance"`
    RequireApprovalFalsePositive   bool            `json:"require_approval_for_false_positive"`
    RequireApprovalScopeExpansion  bool            `json:"require_approval_for_scope_expansion"` // Stored in schema but trigger point deferred to Phase 5
    DefaultFindingSLADays          map[string]int  `json:"default_finding_sla_days"`
    RetentionPolicies              map[string]RetentionPolicy `json:"retention_policies"`
    UpdatedAt                      time.Time       `json:"updated_at"`
    UpdatedBy                      string          `json:"updated_by,omitempty"`
}

// RetentionPolicy defines retention and grace periods for a resource type.
type RetentionPolicy struct {
    RetentionDays int `json:"retention_days"`
    GraceDays     int `json:"grace_days"`
}

// DefaultRetentionPolicies returns the default retention policies.
func DefaultRetentionPolicies() map[string]RetentionPolicy {
    return map[string]RetentionPolicy{
        "findings":         {RetentionDays: 365, GraceDays: 30},
        "evidence":         {RetentionDays: 365, GraceDays: 30},
        "audit_log":        {RetentionDays: 730, GraceDays: 90},
        "scan_job":         {RetentionDays: 180, GraceDays: 14},
        "notification":     {RetentionDays: 90, GraceDays: 7},
        "webhook_delivery": {RetentionDays: 30, GraceDays: 7},
    }
}

// DefaultSLADays returns default SLA days per severity.
func DefaultSLADays() map[string]int {
    return map[string]int{"critical": 3, "high": 7, "medium": 30, "low": 90}
}

// ApprovalRequest represents a pending governance approval.
type ApprovalRequest struct {
    ID             string     `json:"id"`
    OrgID          string     `json:"org_id"`
    TeamID         string     `json:"team_id,omitempty"`
    RequestType    string     `json:"request_type"`
    ResourceType   string     `json:"resource_type"`
    ResourceID     string     `json:"resource_id"`
    RequestedBy    string     `json:"requested_by"`
    Reason         string     `json:"reason"`
    Status         string     `json:"status"`
    DecidedBy      string     `json:"decided_by,omitempty"`
    DecisionReason string     `json:"decision_reason,omitempty"`
    DecidedAt      *time.Time `json:"decided_at,omitempty"`
    ExpiresAt      *time.Time `json:"expires_at,omitempty"`
    CreatedAt      time.Time  `json:"created_at"`
}

// FindingAssignment represents an ownership assignment for a finding.
type FindingAssignment struct {
    ID          string     `json:"id"`
    FindingID   string     `json:"finding_id"`
    OrgID       string     `json:"org_id"`
    TeamID      string     `json:"team_id,omitempty"`
    AssignedTo  string     `json:"assigned_to"`
    AssignedBy  string     `json:"assigned_by"`
    DueAt       *time.Time `json:"due_at,omitempty"`
    Status      string     `json:"status"`
    Note        string     `json:"note,omitempty"`
    CreatedAt   time.Time  `json:"created_at"`
    CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// SLAViolation records when a finding breaches its SLA deadline.
type SLAViolation struct {
    ID         string     `json:"id"`
    FindingID  string     `json:"finding_id"`
    OrgID      string     `json:"org_id"`
    Severity   string     `json:"severity"`
    SLADays    int        `json:"sla_days"`
    DeadlineAt time.Time  `json:"deadline_at"`
    ViolatedAt time.Time  `json:"violated_at"`
    ResolvedAt *time.Time `json:"resolved_at,omitempty"`
    Escalated  bool       `json:"escalated"`
}

// EmergencyStop represents a kill-switch activation.
type EmergencyStop struct {
    ID            string     `json:"id"`
    OrgID         string     `json:"org_id"`
    Scope         string     `json:"scope"`
    ScopeID       string     `json:"scope_id,omitempty"`
    Reason        string     `json:"reason"`
    ActivatedBy   string     `json:"activated_by"`
    ActivatedAt   time.Time  `json:"activated_at"`
    DeactivatedBy string     `json:"deactivated_by,omitempty"`
    DeactivatedAt *time.Time `json:"deactivated_at,omitempty"`
    Active        bool       `json:"active"`
}

// RetentionRecord tracks the lifecycle of a resource for retention purposes.
type RetentionRecord struct {
    ID              string     `json:"id"`
    OrgID           string     `json:"org_id"`
    ResourceType    string     `json:"resource_type"`
    ResourceID      string     `json:"resource_id"`
    Lifecycle       string     `json:"lifecycle"`
    RetentionDays   int        `json:"retention_days"`
    ExpiresAt       time.Time  `json:"expires_at"`
    ArchivedAt      *time.Time `json:"archived_at,omitempty"`
    PurgeAfter      *time.Time `json:"purge_after,omitempty"`
    PurgedAt        *time.Time `json:"purged_at,omitempty"`
    LegalHold       bool       `json:"legal_hold"`
    LegalHoldBy     string     `json:"legal_hold_by,omitempty"`
    LegalHoldReason string     `json:"legal_hold_reason,omitempty"`
    CreatedAt       time.Time  `json:"created_at"`
}
```

- [ ] **Step 2: Write the transition matrix and validation**

`internal/governance/transitions.go`:

```go
package governance

import "fmt"

// ValidTransitions defines allowed finding status transitions.
// Key: current status, Value: set of allowed target statuses.
var ValidTransitions = map[string]map[string]bool{
    "new":           {"confirmed": true, "false_positive": true, "accepted_risk": true},
    "confirmed":     {"in_progress": true, "false_positive": true, "accepted_risk": true},
    "in_progress":   {"mitigated": true, "false_positive": true, "accepted_risk": true},
    "mitigated":     {"resolved": true, "reopened": true},
    "resolved":      {"reopened": true},
    "reopened":       {"confirmed": true, "in_progress": true, "false_positive": true, "accepted_risk": true},
    "accepted_risk": {"reopened": true},
    "false_positive": {"reopened": true},
}

// RequiresApproval returns true if transitioning to targetStatus might
// require approval depending on org settings.
var ApprovalTargets = map[string]string{
    "accepted_risk":  "require_approval_for_risk_acceptance",
    "false_positive": "require_approval_for_false_positive",
}

// ValidateTransition checks if a status transition is allowed.
func ValidateTransition(from, to string) error {
    allowed, exists := ValidTransitions[from]
    if !exists {
        return fmt.Errorf("unknown status: %s", from)
    }
    if !allowed[to] {
        return fmt.Errorf("invalid transition from %q to %q", from, to)
    }
    return nil
}

// NeedsApproval checks if a transition to the given status needs org-level approval.
func NeedsApproval(targetStatus string, settings *OrgSettings) bool {
    switch targetStatus {
    case "accepted_risk":
        return settings.RequireApprovalRiskAcceptance
    case "false_positive":
        return settings.RequireApprovalFalsePositive
    default:
        return false
    }
}
```

- [ ] **Step 3: Write the failing tests**

`internal/governance/transitions_test.go`:

```go
package governance

import "testing"

func TestValidateTransition(t *testing.T) {
    tests := []struct {
        from, to string
        wantErr  bool
    }{
        {"new", "confirmed", false},
        {"new", "false_positive", false},
        {"new", "accepted_risk", false},
        {"new", "resolved", true},          // invalid: skip states
        {"new", "in_progress", true},       // invalid: must confirm first
        {"confirmed", "in_progress", false},
        {"in_progress", "mitigated", false},
        {"mitigated", "resolved", false},
        {"mitigated", "reopened", false},
        {"resolved", "reopened", false},
        {"resolved", "confirmed", true},    // invalid: must reopen first
        {"accepted_risk", "reopened", false},
        {"false_positive", "reopened", false},
        {"false_positive", "confirmed", true}, // invalid
        {"unknown", "new", true},
    }
    for _, tt := range tests {
        t.Run(tt.from+"->"+tt.to, func(t *testing.T) {
            err := ValidateTransition(tt.from, tt.to)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateTransition(%q, %q) error = %v, wantErr %v", tt.from, tt.to, err, tt.wantErr)
            }
        })
    }
}

func TestNeedsApproval(t *testing.T) {
    noApproval := &OrgSettings{}
    withApproval := &OrgSettings{
        RequireApprovalRiskAcceptance: true,
        RequireApprovalFalsePositive:  true,
    }

    if NeedsApproval("accepted_risk", noApproval) {
        t.Error("expected no approval needed when setting is false")
    }
    if !NeedsApproval("accepted_risk", withApproval) {
        t.Error("expected approval needed when setting is true")
    }
    if NeedsApproval("confirmed", withApproval) {
        t.Error("confirmed should never need approval")
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/okyay/Documents/SentinelCore && go test ./internal/governance/... -v -run TestValidateTransition -count=1`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/governance/types.go internal/governance/transitions.go internal/governance/transitions_test.go
git commit -m "feat(phase4): add governance types and transition matrix"
```

---

### Task 3: RBAC Permission Updates

**Files:**
- Modify: `internal/policy/rbac.go`
- Create: `internal/policy/rbac_governance_test.go`

- [ ] **Step 1: Write the failing test first**

`internal/policy/rbac_governance_test.go`:

```go
package policy

import "testing"

func TestGovernancePermissions(t *testing.T) {
    newPerms := []struct {
        role       string
        permission string
        want       bool
    }{
        // governance.settings
        {"platform_admin", "governance.settings.read", true},
        {"security_admin", "governance.settings.read", true},
        {"appsec_analyst", "governance.settings.read", false},
        {"auditor", "governance.settings.read", true},
        {"platform_admin", "governance.settings.write", true},
        {"security_admin", "governance.settings.write", true},
        {"appsec_analyst", "governance.settings.write", false},

        // governance.approvals
        {"platform_admin", "governance.approvals.read", true},
        {"appsec_analyst", "governance.approvals.read", true},
        {"platform_admin", "governance.approvals.decide", true},
        {"security_admin", "governance.approvals.decide", true},
        {"appsec_analyst", "governance.approvals.decide", false},

        // emergency stop
        {"platform_admin", "governance.emergency_stop.activate", true},
        {"security_admin", "governance.emergency_stop.activate", true},
        {"appsec_analyst", "governance.emergency_stop.activate", false},
        {"platform_admin", "governance.emergency_stop.lift", true},
        {"security_admin", "governance.emergency_stop.lift", false},

        // findings extensions
        {"platform_admin", "findings.legal_hold", true},
        {"appsec_analyst", "findings.legal_hold", false},

        // webhooks
        {"platform_admin", "webhooks.manage", true},
        {"appsec_analyst", "webhooks.manage", false},
        {"appsec_analyst", "webhooks.read", true},

        // retention
        {"platform_admin", "retention.manage", true},
        {"security_admin", "retention.manage", false},
        {"auditor", "retention.read", true},

        // reports
        {"appsec_analyst", "reports.read", true},
        {"auditor", "reports.read", true},
    }
    for _, tt := range newPerms {
        t.Run(tt.role+"/"+tt.permission, func(t *testing.T) {
            got := Evaluate(tt.role, tt.permission)
            if got != tt.want {
                t.Errorf("Evaluate(%q, %q) = %v, want %v", tt.role, tt.permission, got, tt.want)
            }
        })
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -v -run TestGovernancePermissions -count=1`
Expected: FAIL — new permissions not yet in matrix

- [ ] **Step 3: Add permissions to the matrix**

In `internal/policy/rbac.go`, add the following entries to each role map in `PermissionMatrix`:

**platform_admin** — add:
```go
"governance.settings.read": true, "governance.settings.write": true,
"governance.approvals.read": true, "governance.approvals.decide": true,
"governance.emergency_stop.activate": true, "governance.emergency_stop.lift": true,
"findings.legal_hold": true,
"webhooks.read": true, "webhooks.manage": true,
"retention.read": true, "retention.manage": true,
"reports.read": true,
```

**security_admin** — add:
```go
"governance.settings.read": true, "governance.settings.write": true,
"governance.approvals.read": true, "governance.approvals.decide": true,
"governance.emergency_stop.activate": true,
"findings.legal_hold": true,
"webhooks.read": true, "webhooks.manage": true,
"retention.read": true,
"reports.read": true,
```

**appsec_analyst** — add:
```go
"governance.approvals.read": true,
"webhooks.read": true,
"reports.read": true,
```

**auditor** — add:
```go
"governance.settings.read": true,
"governance.approvals.read": true,
"webhooks.read": true,
"retention.read": true,
"reports.read": true,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/... -v -run TestGovernancePermissions -count=1`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/rbac.go internal/policy/rbac_governance_test.go
git commit -m "feat(phase4): add governance RBAC permissions"
```

---

### Task 4: NATS GOVERNANCE Stream + Fix UpdateFindingStatus RLS

**Files:**
- Modify: `pkg/nats/client.go`
- Modify: `internal/controlplane/api/findings.go`

- [ ] **Step 1: Add GOVERNANCE stream to EnsureStreams**

In `pkg/nats/client.go`, add to the `streams` slice in `EnsureStreams`:

```go
{Name: "GOVERNANCE", Subjects: []string{"governance.>"}, MaxAge: 7 * 24 * time.Hour},
```

- [ ] **Step 2: Fix UpdateFindingStatus to use WithRLS and add transition validation**

Replace the `UpdateFindingStatus` function in `internal/controlplane/api/findings.go`. The key changes:
1. Wrap DB queries in `db.WithRLS`
2. Add transition validation using `governance.ValidateTransition`
3. Return 422 for invalid transitions

The updated handler uses `db.WithRLS` for the SELECT and UPDATE queries (lines 160-177 of current file), and adds a call to `governance.ValidateTransition(oldStatus, req.Status)` before executing the update.

**Note:** This task only fixes RLS + transition validation. The approval gate integration will be added in Task 7 when `TriageFinding` exists. At that point, `UpdateFindingStatus` will be rewired to call `governance.TriageFinding` instead of doing the UPDATE directly, so that the approval gate is invoked from the HTTP layer.

- [ ] **Step 3: Run all existing tests**

Run: `go test ./internal/controlplane/... ./pkg/nats/... -count=1`
Expected: PASS (no regressions)

- [ ] **Step 4: Commit**

```bash
git add pkg/nats/client.go internal/controlplane/api/findings.go
git commit -m "fix(phase4): add GOVERNANCE stream, fix UpdateFindingStatus RLS bypass"
```

---

## Chunk 2: Governance Settings and Approval Workflow (Tasks 5-7)

### Task 5: Org Settings CRUD

**Files:**
- Create: `internal/governance/settings.go`
- Create: `internal/governance/settings_test.go`

- [ ] **Step 1: Write failing test**

`internal/governance/settings_test.go` — test `GetOrgSettings` returns defaults when no row exists, and `UpsertOrgSettings` persists changes. Use a mock/interface pattern:

```go
package governance

import "testing"

func TestDefaultOrgSettings(t *testing.T) {
    s := NewDefaultOrgSettings("org-1")
    if s.RequireApprovalRiskAcceptance {
        t.Error("default should be false")
    }
    if s.DefaultFindingSLADays["critical"] != 3 {
        t.Errorf("expected critical SLA=3, got %d", s.DefaultFindingSLADays["critical"])
    }
    if s.RetentionPolicies["findings"].RetentionDays != 365 {
        t.Error("expected findings retention 365 days")
    }
}
```

- [ ] **Step 2: Implement settings.go**

`internal/governance/settings.go` — `NewDefaultOrgSettings(orgID)`, `GetOrgSettings(ctx, pool, orgID)`, `UpsertOrgSettings(ctx, pool, settings)`. The Get function returns defaults when no row is found. The Upsert uses `INSERT ... ON CONFLICT (org_id) DO UPDATE`.

- [ ] **Step 3: Run test**

Run: `go test ./internal/governance/... -v -run TestDefault -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/governance/settings.go internal/governance/settings_test.go
git commit -m "feat(phase4): add governance org settings CRUD"
```

---

### Task 6: Approval Workflow Engine

**Files:**
- Create: `internal/governance/workflow.go`
- Create: `internal/governance/workflow_test.go`

- [ ] **Step 1: Write failing tests**

Test: `CreateApprovalRequest` returns a request with pending status and expiry. `DecideApproval` with "approved" changes status. `DecideApproval` with "rejected" changes status. Expired approvals are detected by `ExpirePendingApprovals`.

- [ ] **Step 2: Implement workflow.go**

Functions:
- `CreateApprovalRequest(ctx, pool, req ApprovalRequest) (ApprovalRequest, error)` — INSERT into `governance.approval_requests`, sets `expires_at` to now()+7 days
- `GetApprovalRequest(ctx, pool, id string) (ApprovalRequest, error)` — SELECT with RLS
- `ListApprovalRequests(ctx, pool, orgID, status string, limit, offset int) ([]ApprovalRequest, error)`
- `DecideApproval(ctx, pool, id, decidedBy, decision, reason string) error` — UPDATE status, decided_by, decided_at, decision_reason. Validates status is still 'pending'.
- `ExpirePendingApprovals(ctx, pool) (int, error)` — UPDATE status='expired' WHERE status='pending' AND expires_at < now(). Returns count of expired.

- [ ] **Step 3: Run tests**

Run: `go test ./internal/governance/... -v -run TestWorkflow -count=1`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/governance/workflow.go internal/governance/workflow_test.go
git commit -m "feat(phase4): add approval workflow engine"
```

---

### Task 7: Triage Orchestration (Approval Gate in Status Update)

**Files:**
- Create: `internal/governance/triage.go`
- Create: `internal/governance/triage_test.go`

- [ ] **Step 1: Write failing tests**

Test scenarios:
1. Transition to `confirmed` (no approval needed) → direct transition
2. Transition to `accepted_risk` with approval disabled → direct transition
3. Transition to `accepted_risk` with approval enabled → returns approval request, finding stays at current status
4. Invalid transition → error

- [ ] **Step 2: Implement triage.go**

`TriageResult` struct: `{Transitioned bool, ApprovalRequired bool, ApprovalID string}`.

`TriageFinding(ctx, pool, findingID, fromStatus, toStatus, userID, orgID, teamID, reason string, settings *OrgSettings) (TriageResult, error)`:
1. Call `ValidateTransition(fromStatus, toStatus)` → error if invalid
2. Call `NeedsApproval(toStatus, settings)` → if true, create approval request, return `{ApprovalRequired: true, ApprovalID: id}`
3. Otherwise, execute the UPDATE + INSERT transition directly, return `{Transitioned: true}`

- [ ] **Step 3: Run tests**

Run: `go test ./internal/governance/... -v -run TestTriage -count=1`
Expected: PASS

- [ ] **Step 4: Rewire UpdateFindingStatus to use TriageFinding**

Modify `internal/controlplane/api/findings.go`: replace the direct UPDATE in `UpdateFindingStatus` with a call to `governance.TriageFinding(...)`. If `TriageResult.ApprovalRequired`, return 202 with the approval ID. If `TriageResult.Transitioned`, return 200 as before. This ensures the approval gate is invoked from the HTTP layer.

- [ ] **Step 5: Run all findings tests to verify no regression**

Run: `go test ./internal/controlplane/... -v -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/governance/triage.go internal/governance/triage_test.go internal/controlplane/api/findings.go
git commit -m "feat(phase4): add triage orchestration with approval gate"
```

---

## Chunk 3: Assignment, SLA, Emergency Stop (Tasks 8-10)

### Task 8: Finding Assignment

**Files:**
- Create: `internal/governance/assignment.go`
- Create: `internal/governance/assignment_test.go`

- [ ] **Step 1: Write failing tests**

Test: `AssignFinding` creates assignment with active status. `ReassignFinding` marks old as reassigned, creates new. `CompleteFindingAssignment` marks completed.

- [ ] **Step 2: Implement assignment.go**

Functions:
- `AssignFinding(ctx, pool, findingID, orgID, teamID, assignedTo, assignedBy string, dueAt *time.Time, note string) (FindingAssignment, error)` — INSERT + UPDATE findings.findings.assigned_to
- `ReassignFinding(ctx, pool, assignmentID, newAssignee, assignedBy string) (FindingAssignment, error)` — UPDATE old to 'reassigned', INSERT new
- `CompleteFindingAssignment(ctx, pool, assignmentID string) error` — UPDATE status='completed', completed_at=now()
- `ListAssignments(ctx, pool, userID string, status string, limit, offset int) ([]FindingAssignment, error)`

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/governance/assignment.go internal/governance/assignment_test.go
git commit -m "feat(phase4): add finding assignment and ownership"
```

---

### Task 9: SLA Tracking

**Files:**
- Create: `internal/governance/sla.go`
- Create: `internal/governance/sla_test.go`

- [ ] **Step 1: Write failing tests**

Test: `CalculateSLADeadline` computes correct deadline from severity + settings. `CheckSLAViolations` identifies overdue findings. `CheckSLAWarnings` identifies findings at 80% of deadline.

- [ ] **Step 2: Implement sla.go**

Functions:
- `CalculateSLADeadline(createdAt time.Time, severity string, settings *OrgSettings) time.Time`
- `CheckSLAViolations(ctx, pool, orgID string, now time.Time) ([]SLAViolation, error)` — query findings past deadline not yet in violation table
- `CheckSLAWarnings(ctx, pool, orgID string, now time.Time) ([]string, error)` — return finding IDs at ≥80% of deadline
- `RecordSLAViolation(ctx, pool, violation SLAViolation) error`

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/governance/sla.go internal/governance/sla_test.go
git commit -m "feat(phase4): add SLA tracking and violation detection"
```

---

### Task 10: Emergency Stop (Kill Switch)

**Files:**
- Create: `internal/governance/estop.go`
- Create: `internal/governance/estop_test.go`

- [ ] **Step 1: Write failing tests**

Test: `ActivateEmergencyStop` creates active stop. `LiftEmergencyStop` deactivates. `LiftEmergencyStop` by same user who activated → error (four-eyes). `IsEmergencyStopped` returns true when active stop exists for scope.

- [ ] **Step 2: Implement estop.go**

Functions:
- `ActivateEmergencyStop(ctx, pool, orgID, scope, scopeID, reason, activatedBy string) (EmergencyStop, error)` — INSERT active=true
- `LiftEmergencyStop(ctx, pool, stopID, deactivatedBy string) error` — validates different user than activated_by, UPDATE active=false
- `IsEmergencyStopped(ctx, pool, orgID, scope, scopeID string) (bool, error)` — SELECT EXISTS active stops matching scope
- `ListActiveStops(ctx, pool, orgID string) ([]EmergencyStop, error)`

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/governance/estop.go internal/governance/estop_test.go
git commit -m "feat(phase4): add emergency stop kill switch"
```

---

## Chunk 4: Notifications and Webhooks (Tasks 11-13)

### Task 11: Notification Service

**Files:**
- Create: `internal/notification/types.go`
- Create: `internal/notification/service.go`
- Create: `internal/notification/service_test.go`

- [ ] **Step 1: Write types**

`internal/notification/types.go`:
- `NotificationEvent` struct: EventType, OrgID, ResourceType, ResourceID, Data map[string]string
- `Notification` struct: ID, OrgID, UserID, Category, Title, Body, ResourceType, ResourceID, Read, CreatedAt
- `WebhookConfig` struct: ID, OrgID, Name, URL, SecretEncrypted []byte, SecretKeyID, Events []string, Enabled
- `DeliveryAttempt` struct: ID, WebhookID, EventType, Payload, Status, Attempts, ResponseCode, ResponseBody

- [ ] **Step 2: Write failing tests for notification service**

Test: `CreateNotification` stores notification. `ListNotifications` retrieves user's notifications. `MarkRead` sets read=true. `UnreadCount` returns correct count.

- [ ] **Step 3: Implement service.go**

Functions:
- `CreateNotification(ctx, pool, n Notification) error`
- `CreateNotificationsForUsers(ctx, pool, userIDs []string, n Notification) error` — batch insert
- `ListNotifications(ctx, pool, userID string, limit, offset int) ([]Notification, error)`
- `MarkRead(ctx, pool, notificationID, userID string) error`
- `MarkAllRead(ctx, pool, userID string) error`
- `UnreadCount(ctx, pool, userID string) (int, error)`

- [ ] **Step 4: Run tests, commit**

```bash
git add internal/notification/types.go internal/notification/service.go internal/notification/service_test.go
git commit -m "feat(phase4): add notification service"
```

---

### Task 12: Webhook Delivery with SSRF Validation

**Files:**
- Create: `internal/notification/webhook.go`
- Create: `internal/notification/webhook_test.go`

- [ ] **Step 1: Write failing tests**

Test: `ValidateWebhookURL` rejects private IPs (10.0.0.1, 127.0.0.1, 169.254.x.x, fc00::). Accepts valid HTTPS URLs. `SignPayload` produces HMAC-SHA256 signature. `DeliverWebhook` with retry logic (mock HTTP server).

- [ ] **Step 2: Implement webhook.go**

Functions:
- `ValidateWebhookURL(rawURL string) error` — parse URL, reject non-HTTPS (configurable for dev), resolve hostname, check against `blockedCIDRs` (reuse the list from `pkg/scope/enforcer.go`), reject URLs with userinfo
- `SignPayload(payload []byte, secret []byte) string` — HMAC-SHA256, hex-encoded
- `DeliverWebhook(ctx context.Context, config WebhookConfig, event NotificationEvent, secret []byte) (*DeliveryAttempt, error)` — POST JSON payload, include `X-Sentinel-Signature` header, re-validate URL at delivery time (DNS rebinding defense), truncate response body to 4KB
- `CreateWebhookConfig(ctx, pool, config WebhookConfig) (WebhookConfig, error)`
- `ListWebhookConfigs(ctx, pool, orgID string) ([]WebhookConfig, error)`
- `DeleteWebhookConfig(ctx, pool, id, orgID string) error`
- `RecordDeliveryAttempt(ctx, pool, attempt DeliveryAttempt) error`
- `GetPendingDeliveries(ctx, pool, limit int) ([]DeliveryAttempt, error)`

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/notification/webhook.go internal/notification/webhook_test.go
git commit -m "feat(phase4): add webhook delivery with SSRF validation"
```

---

### Task 13: Notification Worker Binary

**Files:**
- Create: `cmd/notification-worker/main.go`

- [ ] **Step 1: Implement notification worker**

`cmd/notification-worker/main.go`:
- Connect to NATS and PostgreSQL
- Subscribe to `governance.notifications` consumer
- On message: parse NotificationEvent, create in-app notifications for target users, queue webhook deliveries
- Separate goroutine: poll `governance.webhook_deliveries` for pending/failed, deliver with exponential backoff (1m, 5m, 15m, 1h), max 5 attempts → mark 'exhausted'
- **Important:** The notification worker must connect as a service role that bypasses RLS on `governance.webhook_deliveries` (it queries pending deliveries across all orgs). Use `SET LOCAL role = 'sentinel_service'` or connect with a superuser/service account that has RLS bypass. Same applies to the retention worker.

- [ ] **Step 2: Verify it compiles**

Run: `go build ./cmd/notification-worker/`
Expected: Compiles without errors

- [ ] **Step 3: Commit**

```bash
git add cmd/notification-worker/main.go
git commit -m "feat(phase4): add notification worker binary"
```

---

## Chunk 5: Retention Engine and Worker (Tasks 14-15)

### Task 14: Retention Lifecycle Engine

**Files:**
- Create: `internal/governance/retention.go`
- Create: `internal/governance/retention_test.go`

- [ ] **Step 1: Write failing tests**

Test: `TransitionToArchived` moves expired active records. `TransitionToPurgePending` moves expired archived records. `PurgeRecords` deletes data for non-legal-hold records. `PurgeRecords` skips legal-hold records.

- [ ] **Step 2: Implement retention.go**

Functions:
- `CreateRetentionRecord(ctx, pool, rec RetentionRecord) error`
- `TransitionToArchived(ctx, pool, now time.Time) (int, error)` — UPDATE lifecycle='archived', archived_at=now WHERE lifecycle='active' AND expires_at < now
- `TransitionToPurgePending(ctx, pool, now time.Time) (int, error)` — UPDATE lifecycle='purge_pending' WHERE lifecycle='archived' AND purge_after < now
- `PurgeRecords(ctx, pool, now time.Time) (int, error)` — SELECT purge_pending WHERE legal_hold=false, delete underlying data (per resource_type), UPDATE lifecycle='purged'
- `SetLegalHold(ctx, pool, resourceType, resourceID, holdBy, reason string, hold bool) error`
- `GetRetentionStats(ctx, pool, orgID string) (map[string]map[string]int, error)` — count per resource_type per lifecycle state

- [ ] **Step 3: Run tests, commit**

```bash
git add internal/governance/retention.go internal/governance/retention_test.go
git commit -m "feat(phase4): add retention lifecycle engine"
```

---

### Task 15: Retention Worker Binary

**Files:**
- Create: `cmd/retention-worker/main.go`

- [ ] **Step 1: Implement retention worker**

`cmd/retention-worker/main.go`:
- Connect to PostgreSQL and NATS
- Run on configurable interval (default: 1 hour via env RETENTION_INTERVAL)
- Each cycle:
  1. `ExpirePendingApprovals` (from workflow.go)
  2. `TransitionToArchived`
  3. `TransitionToPurgePending`
  4. `PurgeRecords`
  5. `CheckSLAViolations` + emit notifications for new violations
  6. `CheckSLAWarnings` + emit notifications
  7. Log counts for each step
  8. Emit audit events for all lifecycle transitions

- [ ] **Step 2: Verify it compiles**

Run: `go build ./cmd/retention-worker/`
Expected: Compiles without errors

- [ ] **Step 3: Commit**

```bash
git add cmd/retention-worker/main.go
git commit -m "feat(phase4): add retention worker binary"
```

---

## Chunk 6: API Handlers and Route Registration (Tasks 16-20)

### Task 16: Governance API Handlers

**Files:**
- Create: `internal/controlplane/api/governance.go`

- [ ] **Step 1: Implement governance.go**

Handlers on `*Handlers` struct:
- `GetGovernanceSettings` — GET, requires `governance.settings.read`
- `UpdateGovernanceSettings` — PUT, requires `governance.settings.write`
- `ListApprovals` — GET, requires `governance.approvals.read`
- `GetApproval` — GET, requires `governance.approvals.read`
- `DecideApproval` — POST, requires `governance.approvals.decide`. On approve: call `governance.TriageFinding` to execute the held transition. Emit audit event.
- `ActivateEmergencyStop` — POST, requires `governance.emergency_stop.activate`
- `LiftEmergencyStop` — POST, requires `governance.emergency_stop.lift`. Publish NATS `governance.estop.lifted`.
- `ListActiveEmergencyStops` — GET, requires `governance.emergency_stop.activate`
- `AssignFinding` — POST `/api/v1/findings/:id/assign`, requires `findings.triage`
- `SetLegalHold` — POST `/api/v1/findings/:id/legal-hold`, requires `findings.legal_hold`

All handlers follow the existing pattern: `requireAuth → policy.Evaluate → db.WithRLS → execute → emitAuditEvent → writeJSON`.

- [ ] **Step 2: Commit**

```bash
git add internal/controlplane/api/governance.go
git commit -m "feat(phase4): add governance API handlers"
```

---

### Task 17: Notifications API Handlers

**Files:**
- Create: `internal/controlplane/api/notifications.go`

- [ ] **Step 1: Implement notifications.go**

Handlers:
- `ListNotifications` — GET, authenticated (own via RLS)
- `MarkNotificationRead` — POST `:id/read`, authenticated
- `MarkAllNotificationsRead` — POST `read-all`, authenticated
- `GetUnreadCount` — GET `unread-count`, authenticated
- `ListWebhooks` — GET, requires `webhooks.read`
- `CreateWebhook` — POST, requires `webhooks.manage`. Calls `ValidateWebhookURL`. Encrypts secret with AES-256-GCM before storing.
- `UpdateWebhook` — PUT, requires `webhooks.manage`
- `DeleteWebhook` — DELETE, requires `webhooks.manage`
- `TestWebhook` — POST `:id/test`, requires `webhooks.manage`

- [ ] **Step 2: Commit**

```bash
git add internal/controlplane/api/notifications.go
git commit -m "feat(phase4): add notifications and webhooks API handlers"
```

---

### Task 18: Retention API Handlers

**Files:**
- Create: `internal/controlplane/api/retention.go`

- [ ] **Step 1: Implement retention.go**

Handlers:
- `GetRetentionPolicies` — GET, requires `retention.read`. Returns org's retention policies from settings.
- `UpdateRetentionPolicies` — PUT, requires `retention.manage`. Updates the `retention_policies` JSONB in org_settings.
- `ListRetentionRecords` — GET, requires `retention.read`. Supports filtering by resource_type, lifecycle.
- `GetRetentionStats` — GET, requires `retention.read`. Returns counts per resource_type per lifecycle state.

- [ ] **Step 2: Commit**

```bash
git add internal/controlplane/api/retention.go
git commit -m "feat(phase4): add retention API handlers"
```

---

### Task 19: Reporting API Handlers

**Files:**
- Create: `internal/controlplane/api/reports.go`

- [ ] **Step 1: Implement reports.go**

Handlers:
- `FindingsSummary` — GET, requires `reports.read`. Query: count findings grouped by severity, status, finding_type. Support date_from/date_to/project_id/team_id filters.
- `TriageMetrics` — GET, requires `reports.read`. Query: open/closed/assigned/overdue counts, mean time to triage, mean time to resolution.
- `ComplianceStatus` — GET, requires `reports.read`. Query: audit log completeness, retention compliance (% of resources with retention records), SLA compliance (% within deadline).
- `ScanActivity` — GET, requires `reports.read`. Query: scan count by type, average duration, coverage (projects with at least one scan in last 30 days).

All report handlers use `db.WithRLS` and support optional query params: `org_id`, `team_id`, `project_id`, `date_from`, `date_to`.

- [ ] **Step 2: Commit**

```bash
git add internal/controlplane/api/reports.go
git commit -m "feat(phase4): add reporting API handlers"
```

---

### Task 20: Route Registration

**Files:**
- Modify: `internal/controlplane/server.go`

- [ ] **Step 1: Register all new routes in server.go Start() method**

Add after the existing Findings routes (after line 182):

```go
// Governance settings
mux.HandleFunc("GET /api/v1/governance/settings", handlers.GetGovernanceSettings)
mux.HandleFunc("PUT /api/v1/governance/settings", handlers.UpdateGovernanceSettings)

// Approvals
mux.HandleFunc("GET /api/v1/governance/approvals", handlers.ListApprovals)
mux.HandleFunc("GET /api/v1/governance/approvals/{id}", handlers.GetApproval)
mux.HandleFunc("POST /api/v1/governance/approvals/{id}/decide", handlers.DecideApproval)

// Emergency stop
mux.HandleFunc("POST /api/v1/governance/emergency-stop", handlers.ActivateEmergencyStop)
mux.HandleFunc("POST /api/v1/governance/emergency-stop/lift", handlers.LiftEmergencyStop)
mux.HandleFunc("GET /api/v1/governance/emergency-stop/active", handlers.ListActiveEmergencyStops)

// Finding triage extensions
mux.HandleFunc("POST /api/v1/findings/{id}/assign", handlers.AssignFinding)
mux.HandleFunc("POST /api/v1/findings/{id}/legal-hold", handlers.SetLegalHold)

// Notifications
mux.HandleFunc("GET /api/v1/notifications", handlers.ListNotifications)
mux.HandleFunc("POST /api/v1/notifications/{id}/read", handlers.MarkNotificationRead)
mux.HandleFunc("POST /api/v1/notifications/read-all", handlers.MarkAllNotificationsRead)
mux.HandleFunc("GET /api/v1/notifications/unread-count", handlers.GetUnreadCount)

// Webhooks
mux.HandleFunc("GET /api/v1/webhooks", handlers.ListWebhooks)
mux.HandleFunc("POST /api/v1/webhooks", handlers.CreateWebhook)
mux.HandleFunc("PUT /api/v1/webhooks/{id}", handlers.UpdateWebhook)
mux.HandleFunc("DELETE /api/v1/webhooks/{id}", handlers.DeleteWebhook)
mux.HandleFunc("POST /api/v1/webhooks/{id}/test", handlers.TestWebhook)

// Retention
mux.HandleFunc("GET /api/v1/retention/policies", handlers.GetRetentionPolicies)
mux.HandleFunc("PUT /api/v1/retention/policies", handlers.UpdateRetentionPolicies)
mux.HandleFunc("GET /api/v1/retention/records", handlers.ListRetentionRecords)
mux.HandleFunc("GET /api/v1/retention/stats", handlers.GetRetentionStats)

// Reports
mux.HandleFunc("GET /api/v1/reports/findings-summary", handlers.FindingsSummary)
mux.HandleFunc("GET /api/v1/reports/triage-metrics", handlers.TriageMetrics)
mux.HandleFunc("GET /api/v1/reports/compliance-status", handlers.ComplianceStatus)
mux.HandleFunc("GET /api/v1/reports/scan-activity", handlers.ScanActivity)
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./cmd/controlplane/`
Expected: Compiles without errors

- [ ] **Step 3: Commit**

```bash
git add internal/controlplane/server.go
git commit -m "feat(phase4): register governance API routes"
```

---

## Chunk 7: Integration, Docker, Documentation (Tasks 21-24)

### Task 21: Docker Compose and Dockerfile Updates

**Files:**
- Modify: `docker-compose.yml`
- Modify: `Dockerfile`

- [ ] **Step 1: Add build targets to Dockerfile**

Add targets for `retention-worker` and `notification-worker` following the existing multi-stage pattern.

- [ ] **Step 2: Add services to docker-compose.yml**

Add `retention-worker` and `notification-worker` services with DATABASE_URL, NATS_URL env vars, depends_on postgres and nats.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml Dockerfile
git commit -m "feat(phase4): add retention and notification workers to Docker Compose"
```

---

### Task 22: Integration Tests

**Files:**
- Create: `test/integration/phase4_governance_test.go`

- [ ] **Step 1: Write integration tests**

Test scenarios:
1. **Approval workflow E2E**: Create org → create finding → configure approval requirement → attempt risk acceptance → verify 202 + approval created → approve → verify finding status changed → **verify audit_log contains governance.approval.created and governance.approval.decided events**
2. **Emergency stop**: Activate stop → verify `IsEmergencyStopped` returns true → lift by different user → verify lifted
3. **Transition validation**: Attempt invalid transition (new→resolved) → verify 422
4. **SLA tracking**: Create finding → set SLA deadline in past → run CheckSLAViolations → verify violation recorded
5. **Legal hold**: Set legal hold on finding → attempt purge → verify blocked
6. **Four-eyes**: Activate estop → attempt lift by same user → verify error

- [ ] **Step 2: Run integration tests**

Run: `go test ./test/integration/... -v -run TestPhase4 -count=1`
Expected: All PASS

- [ ] **Step 3: Commit**

```bash
git add test/integration/phase4_governance_test.go
git commit -m "test(phase4): add governance integration tests"
```

---

### Task 23: Build Verification

- [ ] **Step 1: Build all packages**

Run: `go build ./...`
Expected: All packages compile

- [ ] **Step 2: Run all tests**

Run: `go test ./... -count=1`
Expected: All PASS, no regressions

- [ ] **Step 3: Run go vet**

Run: `go vet ./...`
Expected: No issues

---

### Task 24: Documentation and PR Summary

**Files:**
- Create: `docs/phase4-governance.md`
- Modify: `docs/ARCHITECTURE.md` (add Phase 4 entry)

- [ ] **Step 1: Write Phase 4 documentation**

`docs/phase4-governance.md` — summarize what was built, new API endpoints, new RBAC permissions, migration instructions, new binaries, configuration.

- [ ] **Step 2: Update ARCHITECTURE.md**

Add entry for Phase 4 governance documentation.

- [ ] **Step 3: Commit**

```bash
git add docs/phase4-governance.md docs/ARCHITECTURE.md
git commit -m "docs(phase4): add governance documentation and update architecture index"
```

- [ ] **Step 4: Prepare PR summary**

PR title: `feat(phase4): enterprise governance, reporting, and operational hardening`

PR body covers:
- What was added (governance settings, approval workflow, triage, assignment, SLA, emergency stop, notifications, webhooks, retention, reports)
- New binaries (retention-worker, notification-worker)
- Migration file (004_governance.sql)
- 13 new RBAC permissions
- ~25 new API endpoints
- Test coverage
- Reviewer checklist

---

## Merge Criteria

All of these must be true before the PR is merge-ready:

- [ ] All packages compile: `go build ./...`
- [ ] All tests pass: `go test ./... -count=1`
- [ ] No vet issues: `go vet ./...`
- [ ] Migration is idempotent (can run twice without error)
- [ ] RLS bypass in UpdateFindingStatus is fixed
- [ ] Transition matrix rejects invalid transitions
- [ ] Four-eyes principle enforced on emergency stop
- [ ] Webhook SSRF validation rejects private IPs
- [ ] Legal hold blocks purge
- [ ] No regressions in existing SAST/DAST/Correlation tests

## Deferred Items

These are explicitly out of scope for Phase 4 and tracked for future phases:

- **OPA policy engine integration** — currently using hardcoded RBAC matrix; OPA-based policies deferred
- **Ticket system integration** — JIRA/Azure DevOps/Linear integration for finding assignments
- **Email notifications** — SMTP delivery channel (currently in-app + webhook only)
- **Audit log retention** — The retention worker skips `audit_log` purge entirely in Phase 4 because purging breaks the HMAC hash chain. A future phase will implement MinIO WORM cold archival with genesis markers before enabling audit_log purge.
- **Admin notification bypass** — platform_admin querying other users' notifications
- **Scheduled report generation** — periodic PDF/CSV report exports
- **Custom approval chains** — multi-step approval (currently single approver)
- **Finding auto-resolution rules** — policy-based auto-close of findings
