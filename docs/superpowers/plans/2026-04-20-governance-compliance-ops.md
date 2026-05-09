# Governance & Compliance Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add enterprise-grade governance/compliance operations on top of the existing SentinelCore platform: closure/two-person approval workflows, first-class SLA tracking APIs, deterministic compliance mappings (CWE→OWASP/PCI-DSS + tenant custom), and evidence export packs.

**Architecture:** Extend the existing `governance` schema (migration 014) and `internal/governance` package rather than introducing a parallel subsystem. Reuse the established patterns: pgx RLS-scoped queries, NATS-emitted audit/notification events, per-handler `policy.Evaluate` RBAC checks, async workers for heavy work (new `export-worker` alongside `notification-worker`/`retention-worker`). Compliance mappings live in three small tables (`control_catalogs`, `control_items`, `control_mappings`) and are resolved at render time so a tenant can override built-in mappings without forking data.

**Tech Stack:** Go 1.22 (net/http, pgxpool, NATS JetStream), PostgreSQL with RLS, MinIO for artifacts, Next.js 14 + TanStack Query + Zod on the frontend, `golang-migrate` for SQL migrations.

**Out of scope:** Email/Slack/PagerDuty delivery channels (tracked under Phase 5), signed-URL CDN edge delivery of exports, offline/disconnected export signing with cosign (flagged as optional in export pack section).

**Scope note:** Four subsystems ship in this plan. They are ordered by dependency (A → B → C → D) and each epic is independently mergeable and testable. If delivery pressure requires further splitting, Epics A+B can ship as "governance-ops-v1" and Epics C+D as "governance-ops-v2".

---

## 1. Final governance/compliance feature model

```
                        ┌───────────────────────────────────────┐
                        │         Governance Layer              │
                        │  (on top of risks, findings, audit)   │
                        └──────────────────┬────────────────────┘
                                           │
          ┌────────────────┬───────────────┼────────────────┬───────────────┐
          ▼                ▼               ▼                ▼               ▼
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐
   │ Approvals   │  │ SLA         │  │ Compliance  │  │ Evidence    │  │ Existing │
   │             │  │             │  │ Mappings    │  │ Export Pack │  │ (audit,  │
   │ • closure   │  │ • per-proj  │  │ • catalogs  │  │ • async job │  │  RBAC,   │
   │ • 2-person  │  │ • warn/breach│  │ • mappings  │  │ • ZIP bundle│  │  notif,  │
   │ • decisions │  │ • dashboard │  │ • custom    │  │ • MinIO+TTL │  │  estop)  │
   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘  └──────────┘
```

**Cross-cutting invariants:**

1. **Auditable:** every state change (approval created, decided, SLA breach, export requested, compliance mapping edited) emits one `audit.audit_log` event via the existing `pkg/audit.Emitter`.
2. **Deterministic:** compliance mapping resolution is a pure function of (cwe_id, org_id) → controls; SLA deadline is a pure function of (severity, policy, first_seen_at). Same inputs always produce the same outputs, and exports embed policy/catalog versions so they can be reproduced later.
3. **RLS-enforced:** every new table ships with `ENABLE ROW LEVEL SECURITY` + an org or project scoped policy. Cross-org workers use a dedicated service role that bypasses RLS explicitly.
4. **Append-only where possible:** `approval_decisions` rows are immutable; `export_jobs` transitions one-way (`queued → running → {completed,failed,expired}`).

---

## 2. Schema changes

All changes go into a single migration pair: `migrations/024_governance_ops.up.sql` / `024_governance_ops.down.sql`. Numbering assumes no other branch lands migration 024 first; bump if it does.

### 2.1 Project sensitivity + org settings extensions

```sql
ALTER TABLE core.projects
  ADD COLUMN IF NOT EXISTS sensitivity TEXT NOT NULL DEFAULT 'standard'
    CHECK (sensitivity IN ('standard','sensitive','regulated'));

ALTER TABLE governance.org_settings
  ADD COLUMN IF NOT EXISTS require_closure_approval BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS require_two_person_closure BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS approval_expiry_days INTEGER NOT NULL DEFAULT 7
    CHECK (approval_expiry_days BETWEEN 1 AND 30),
  ADD COLUMN IF NOT EXISTS sla_warning_window_days INTEGER NOT NULL DEFAULT 7
    CHECK (sla_warning_window_days BETWEEN 1 AND 30);
```

### 2.2 Approval decisions (two-person rule)

```sql
ALTER TABLE governance.approval_requests
  ADD COLUMN IF NOT EXISTS required_approvals INTEGER NOT NULL DEFAULT 1
    CHECK (required_approvals BETWEEN 1 AND 3),
  ADD COLUMN IF NOT EXISTS current_approvals INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS target_transition TEXT,
  ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES core.projects(id);

CREATE TABLE IF NOT EXISTS governance.approval_decisions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  approval_request_id UUID NOT NULL
    REFERENCES governance.approval_requests(id) ON DELETE CASCADE,
  decided_by UUID NOT NULL REFERENCES core.users(id),
  decision TEXT NOT NULL CHECK (decision IN ('approve','reject')),
  reason TEXT NOT NULL,
  decided_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (approval_request_id, decided_by)
);

CREATE INDEX idx_approval_decisions_request
  ON governance.approval_decisions(approval_request_id);

ALTER TABLE governance.approval_decisions ENABLE ROW LEVEL SECURITY;

CREATE POLICY approval_decisions_org_isolation
  ON governance.approval_decisions
  USING (approval_request_id IN (
    SELECT id FROM governance.approval_requests
    WHERE org_id = current_setting('app.current_org_id', true)::uuid
  ));
```

### 2.3 Per-project SLA policies

```sql
CREATE TABLE IF NOT EXISTS governance.project_sla_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES core.organizations(id),
  project_id UUID NOT NULL UNIQUE REFERENCES core.projects(id) ON DELETE CASCADE,
  sla_days JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by UUID NOT NULL REFERENCES core.users(id),
  CHECK (jsonb_typeof(sla_days) = 'object'
         AND (sla_days ? 'critical') AND (sla_days ? 'high')
         AND (sla_days ? 'medium')  AND (sla_days ? 'low'))
);

CREATE INDEX idx_project_sla_policies_org ON governance.project_sla_policies(org_id);

ALTER TABLE governance.project_sla_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY project_sla_policies_org_isolation
  ON governance.project_sla_policies
  USING (org_id = current_setting('app.current_org_id', true)::uuid);
```

### 2.4 Compliance catalogs, items, mappings

```sql
CREATE TABLE IF NOT EXISTS governance.control_catalogs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES core.organizations(id),  -- NULL = built-in
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  description TEXT,
  is_builtin BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, code, version)
);

CREATE TABLE IF NOT EXISTS governance.control_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  catalog_id UUID NOT NULL
    REFERENCES governance.control_catalogs(id) ON DELETE CASCADE,
  control_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  UNIQUE (catalog_id, control_id)
);
CREATE INDEX idx_control_items_catalog ON governance.control_items(catalog_id);

CREATE TABLE IF NOT EXISTS governance.control_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES core.organizations(id),   -- NULL = built-in
  source_kind TEXT NOT NULL CHECK (source_kind IN ('cwe','owasp','internal')),
  source_code TEXT NOT NULL,
  target_control_id UUID NOT NULL
    REFERENCES governance.control_items(id) ON DELETE CASCADE,
  confidence TEXT NOT NULL DEFAULT 'normative'
    CHECK (confidence IN ('normative','derived','custom')),
  source_version TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, source_kind, source_code, target_control_id)
);
CREATE INDEX idx_control_mappings_source
  ON governance.control_mappings(source_kind, source_code);
CREATE INDEX idx_control_mappings_org
  ON governance.control_mappings(org_id);

-- RLS: NULL org_id rows are globally readable; custom rows are org-isolated.
ALTER TABLE governance.control_catalogs ENABLE ROW LEVEL SECURITY;
CREATE POLICY control_catalogs_read
  ON governance.control_catalogs FOR SELECT
  USING (org_id IS NULL
      OR org_id = current_setting('app.current_org_id', true)::uuid);
CREATE POLICY control_catalogs_write
  ON governance.control_catalogs FOR ALL
  USING (org_id = current_setting('app.current_org_id', true)::uuid);

ALTER TABLE governance.control_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY control_items_read
  ON governance.control_items FOR SELECT
  USING (catalog_id IN (
    SELECT id FROM governance.control_catalogs
    WHERE org_id IS NULL
       OR org_id = current_setting('app.current_org_id', true)::uuid));

ALTER TABLE governance.control_mappings ENABLE ROW LEVEL SECURITY;
CREATE POLICY control_mappings_read
  ON governance.control_mappings FOR SELECT
  USING (org_id IS NULL
      OR org_id = current_setting('app.current_org_id', true)::uuid);
CREATE POLICY control_mappings_write
  ON governance.control_mappings FOR ALL
  USING (org_id = current_setting('app.current_org_id', true)::uuid);
```

### 2.5 Export jobs

```sql
CREATE TABLE IF NOT EXISTS governance.export_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES core.organizations(id),
  requested_by UUID NOT NULL REFERENCES core.users(id),
  kind TEXT NOT NULL CHECK (kind IN ('risk_evidence_pack','project_evidence_pack','custom')),
  scope JSONB NOT NULL,
  format TEXT NOT NULL CHECK (format IN ('zip_json','json')),
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued','running','completed','failed','expired')),
  artifact_ref TEXT,
  artifact_hash TEXT,
  artifact_size BIGINT,
  error TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '7 days'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_export_jobs_org_status ON governance.export_jobs(org_id, status);
CREATE INDEX idx_export_jobs_expires ON governance.export_jobs(expires_at)
  WHERE status = 'completed';

ALTER TABLE governance.export_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY export_jobs_org_isolation
  ON governance.export_jobs
  USING (org_id = current_setting('app.current_org_id', true)::uuid);
```

### 2.6 Seed data migration (separate file, re-runnable)

Create `migrations/025_compliance_seed.up.sql` which inserts built-in catalogs (`OWASP_TOP10_2021`, `PCI_DSS_4_0`, `NIST_800_53_R5` + `CWE` reference) and ~40 normative CWE→OWASP mappings from the OWASP Top 10 2021 CWE list, plus derived CWE→PCI mappings for the Requirement 6.2.4 cluster (XSS/SQLi/deserialization families).

Idempotency: use `ON CONFLICT (org_id, code, version) DO NOTHING` so re-running the seed never duplicates rows.

---

## 3. Workflow / state models

### 3.1 Approval request state machine

```
            ┌──────────────────────────────────────────┐
requested → │ pending                                  │
            │  ├─ approve decision(s) < required       │ (stays pending, count increments)
            │  ├─ approve decision(s) == required  ────┼──► approved ──► target transition executes
            │  ├─ any reject decision              ────┼──► rejected
            │  └─ now() >= expires_at              ────┼──► expired
            └──────────────────────────────────────────┘
```

**Invariants:**

- `required_approvals` is set at creation based on `org_settings` + `project.sensitivity` and never changes.
- `requested_by` cannot appear in `approval_decisions.decided_by` (segregation of duties enforced at service layer + checked in test).
- When the first `reject` lands, remaining pending approvers still see the row but `DecideApproval` returns an error saying it is already rejected.
- Expiration is lazy: a pending row is treated as expired once `now() >= expires_at` and the nightly `ExpirePendingApprovals` worker moves the status.

### 3.2 Finding/Risk closure transitions

Extend the existing `governance/transitions.go`:

```go
// ApprovalTargets maps finding transitions to whether an approval is required
// AND the minimum number of approvers needed.
var ApprovalTargets = map[string]ApprovalReq{
    "accepted_risk":  {Kind: "risk_acceptance",     MinApprovers: 1},
    "false_positive": {Kind: "false_positive_mark", MinApprovers: 1},
    "resolved":       {Kind: "risk_closure",        MinApprovers: 1}, // gated by org_settings
}

type ApprovalReq struct {
    Kind         string
    MinApprovers int
}
```

`NeedsApproval(ctx, orgID, projectID, fromStatus, toStatus)` returns `(required bool, minApprovers int, kind string)` by layering:

1. Hardcoded defaults above.
2. `org_settings.require_closure_approval` (if false, strip the `resolved` entry).
3. `projects.sensitivity` + `org_settings.require_two_person_closure` → if project is `sensitive`/`regulated` AND the flag is set, bump `MinApprovers` to 2.

Triage flow (extend `governance/triage.go`):

1. Validate transition via `ValidTransitions`.
2. Call `NeedsApproval`.
3. If `required` → call `CreateApprovalRequest(..., required_approvals=min, target_transition=toStatus)`, return `{pending_approval: true, approval_request_id}` to caller.
4. Otherwise execute the transition in a transaction with an audit event.
5. When an approval is fulfilled, a separate `ExecuteApprovedTransition(ctx, approvalReqID)` path performs the transition + audit with `actor_type=system` and `details.approval_request_id=<id>`.

### 3.3 SLA status machine (derived)

SLA state is derived on read; only `sla_deadline` (on findings) and `sla_violations` rows are persisted.

```
on_track → at_risk → breached → resolved
   ▲          │          │          ▲
   │          ▼          ▼          │
   └────── deadline moved (severity change) ──┘
```

### 3.4 Export job lifecycle

```
queued ──► running ──► completed (artifact uploaded)
  │          │
  │          └─► failed  (error recorded)
  └─► expired (TTL reached after completion; artifact purged)
```

---

## 4. SLA model (detail)

**Policy resolution (first match wins):**

```go
func ResolveSLADays(ctx context.Context, pool *pgxpool.Pool, orgID, projectID uuid.UUID) (map[string]int, error) {
    // 1. project override
    // 2. org default
    // 3. platform default {critical:3,high:7,medium:30,low:90}
}
```

**Deadline calculation:** `deadline = first_seen_at + days[severity]`. Stored at insert; recomputed and overwritten on severity change through a new `RecomputeSLADeadline` helper called from the severity-update path.

**Breach detection (hourly `sla-worker`, reuses `retention-worker` shape):**

```go
for each finding where sla_deadline < now()
                    and status not in terminal_statuses
                    and no open sla_violations row:
    insert governance.sla_violations(..., severity, sla_days, deadline_at, violated_at=now())
    emit audit event "sla.breached"
    emit notification event "governance.sla.breach" (category=sla)
```

**Warning window:** same worker also selects findings whose deadline falls within the next `sla_warning_window_days` and emits `sla.at_risk` events **idempotently** (track via `governance.notifications` with a composite key so a warning fires once per finding per deadline).

**Resolution:** when a finding enters a terminal state, any open `sla_violations` row for it gets `resolved_at=now()` in the same transaction; emit `sla.resolved`.

**API surface:**

- `GET /api/v1/governance/sla/policies` — list org + per-project overrides
- `GET /api/v1/governance/sla/policies/{project_id}` — single override
- `PUT /api/v1/governance/sla/policies/{project_id}` — upsert (requires `governance.settings.write`)
- `DELETE /api/v1/governance/sla/policies/{project_id}` — reverts to org default
- `GET /api/v1/governance/sla/violations?status=open|resolved&project_id=...&severity=...` — list with pagination
- `GET /api/v1/governance/sla/dashboard` — summary: counts by status × severity, top 10 breaches, trend bucket

---

## 5. Compliance mapping model (detail)

**Resolver contract:**

```go
type ControlRef struct {
    CatalogCode string // "OWASP_TOP10_2021"
    CatalogName string
    ControlID   string // "A03"
    Title       string
    Confidence  string // "normative" | "derived" | "custom"
    SourceKind  string // "cwe" | "owasp" | "internal"
    SourceCode  string // "CWE-79"
}

// ResolveControls returns (built-in ∪ tenant custom) mappings for a CWE.
func ResolveControls(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, cweID int) ([]ControlRef, error)
```

Implementation: single SQL query joining `control_mappings` ⋈ `control_items` ⋈ `control_catalogs` with `WHERE (org_id IS NULL OR org_id = $1) AND source_kind='cwe' AND source_code = 'CWE-' || $2`. Order: `confidence` precedence (custom > normative > derived) so tenant overrides win in UI.

**API surface:**

- `GET /api/v1/compliance/catalogs` — built-in + tenant catalogs
- `GET /api/v1/compliance/catalogs/{id}/items` — items in a catalog
- `GET /api/v1/compliance/mappings?source_kind=cwe&source_code=CWE-79` — mappings for a source
- `POST /api/v1/compliance/catalogs` — create tenant custom catalog (`governance.settings.write`)
- `POST /api/v1/compliance/catalogs/{id}/items` — add control item
- `POST /api/v1/compliance/mappings` — add tenant custom mapping
- `DELETE /api/v1/compliance/mappings/{id}` — delete tenant custom mapping (NULL org rows are immutable via RLS)

**Surfacing:**

- Finding detail + risk detail pages render a "Controls" strip with links to the control item.
- SARIF export: `result.properties.tags` gains `owasp:A03`, `pci-dss:6.2.4`, etc.
- Markdown export: "Compliance" section with a table.
- Evidence pack: dedicated `compliance/controls.json`.

---

## 6. Evidence export pack design (detail)

**Scope types (first release):**

- `risk_evidence_pack`: scope `{ "risk_ids": ["<uuid>", ...] }` — bundle for one or more risks.
- `project_evidence_pack`: scope `{ "project_id": "<uuid>", "since": "2026-01-01", "status": ["resolved","accepted_risk"] }` — bundle for a project with optional filters.

**Format:** ZIP (primary). `json` is a pure `manifest.json`-equivalent stream for programmatic consumers; PDF is out of scope for MVP (leaves a future `zip_pdf` option reserved).

**ZIP layout:**

```
sentinelcore-evidence-<job_id>.zip
  manifest.json
  README.md
  risk/
    <risk_id>.json
    <risk_id>.md
  findings/
    <finding_id>.json
    <finding_id>.md
  evidence/
    <blob_hash>.bin      (content-addressed; identical blobs dedup naturally)
  compliance/
    controls.json
  timeline/
    events.json
  audit/
    log.json
  approvals/
    decisions.json
  policy/
    sla_policy.json      (the SLA policy in effect at export time)
    org_settings.json    (governance settings snapshot)
```

**manifest.json schema:**

```json
{
  "schema_version": "1.0.0",
  "generator": {"name":"sentinelcore","version":"<semver>"},
  "job_id": "<uuid>",
  "org_id": "<uuid>",
  "generated_at": "2026-04-20T12:00:00Z",
  "scope": {"kind":"risk_evidence_pack","risk_ids":["..."]},
  "files": [
    {"path":"risk/<id>.json","sha256":"<hex>","size":12345},
    ...
  ],
  "bundle_sha256": "<hex>"
}
```

**Generation strategy:**

- `POST /api/v1/governance/exports` enqueues a `governance.export_jobs` row and publishes a `governance.exports` NATS subject.
- New `cmd/export-worker` consumes the subject, streams rows from the DB, writes the ZIP to a tmp file, computes SHA-256 while writing, uploads to MinIO, stores `artifact_ref`, `artifact_hash`, `artifact_size`, sets `status=completed`.
- `GET /api/v1/governance/exports/{id}` returns job state.
- `GET /api/v1/governance/exports/{id}/download` returns a 302 to a MinIO presigned URL (valid 15 min).
- Retention worker already handles `expires_at`; extend it to purge MinIO artifacts when marking `status=expired`.

**Pitfall guards built in:**

- Streaming writer (`archive/zip` on a tmp file) — never buffers the full bundle in memory.
- Evidence blobs copied by hash; duplicates skip.
- Compliance + SLA + org_settings snapshots captured **at export time** so reruns remain reproducible.
- Bundle size cap (env `SENTINELCORE_EXPORT_MAX_MB`, default 1024) — exceed → status=failed with helpful error.

---

## File structure

### Files created

```
migrations/024_governance_ops.up.sql
migrations/024_governance_ops.down.sql
migrations/025_compliance_seed.up.sql
migrations/025_compliance_seed.down.sql

internal/governance/closure.go          # closure + two-person approval helpers
internal/governance/decisions.go        # approval_decisions CRUD
internal/governance/sla_policy.go       # project_sla_policies CRUD + resolver
internal/governance/sla_api.go          # dashboard/violations query helpers

internal/compliance/types.go
internal/compliance/catalog.go          # catalog + item CRUD
internal/compliance/mapping.go          # mapping CRUD + resolver
internal/compliance/seed.go             # re-runnable seed loader (called from migration test)

internal/controlplane/api/approvals.go  # /api/v1/governance/approvals/*
internal/controlplane/api/sla.go        # /api/v1/governance/sla/*
internal/controlplane/api/compliance.go # /api/v1/compliance/*
internal/controlplane/api/exports.go    # /api/v1/governance/exports/*

internal/export/evidence_pack.go        # bundle builder
internal/export/evidence_pack_writer.go # streaming ZIP writer

cmd/export-worker/main.go
cmd/sla-worker/main.go                  # split SLA check out of retention-worker

web/features/findings/approval-dialog.tsx
web/features/governance/approvals-inbox.tsx
web/features/governance/sla-dashboard.tsx
web/features/governance/sla-policies-form.tsx
web/features/compliance/catalogs-page.tsx
web/features/compliance/mappings-editor.tsx
web/features/governance/export-button.tsx
web/features/governance/exports-page.tsx

deploy/docker-compose/docker-compose.yml  # add sla-worker, export-worker services
```

### Files modified

```
internal/governance/types.go
internal/governance/workflow.go
internal/governance/transitions.go
internal/governance/triage.go
internal/governance/sla.go                 # extract breach check to sla-worker
internal/policy/rbac.go                    # new permissions
internal/controlplane/server.go            # route registrations
internal/export/sarif.go                   # inject compliance tags
internal/export/markdown.go                # compliance section
docs/ARCHITECTURE.md                       # governance-ops section
```

### New RBAC permissions

```go
// internal/policy/rbac.go
var governanceOpsPerms = []string{
    "governance.approvals.create",   // already de-facto via triage; now explicit
    "governance.approvals.decide",   // existing
    "governance.sla.read",
    "governance.sla.write",
    "compliance.catalogs.read",
    "compliance.catalogs.write",
    "compliance.mappings.read",
    "compliance.mappings.write",
    "governance.exports.create",
    "governance.exports.read",
}
```

Default assignments:

| Permission                       | platform_admin | security_admin | appsec_analyst | auditor |
|----------------------------------|:-:|:-:|:-:|:-:|
| governance.approvals.decide      | ✅ | ✅ | ❌ | ❌ |
| governance.sla.read              | ✅ | ✅ | ✅ | ✅ |
| governance.sla.write             | ✅ | ✅ | ❌ | ❌ |
| compliance.catalogs.read         | ✅ | ✅ | ✅ | ✅ |
| compliance.catalogs.write        | ✅ | ✅ | ❌ | ❌ |
| compliance.mappings.read         | ✅ | ✅ | ✅ | ✅ |
| compliance.mappings.write        | ✅ | ✅ | ❌ | ❌ |
| governance.exports.create        | ✅ | ✅ | ✅ | ❌ |
| governance.exports.read          | ✅ | ✅ | ✅ | ✅ |

---

## 7. Step-by-step implementation plan

### Epic A — Approval workflow extensions (closure + two-person rule + API)

#### Task A1: Migration 024 — schema extensions

**Files:**
- Create: `migrations/024_governance_ops.up.sql`
- Create: `migrations/024_governance_ops.down.sql`
- Test: `internal/governance/migration_test.go`

- [ ] **Step 1: Write the failing migration test**

```go
// internal/governance/migration_test.go
package governance_test

import (
    "context"
    "testing"
    "github.com/stretchr/testify/require"
    "sentinelcore/internal/testutil"
)

func TestMigration024Applied(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t) // applies all migrations

    var sensitivity string
    err := pool.QueryRow(ctx,
        `SELECT sensitivity FROM core.projects LIMIT 1`).Scan(&sensitivity)
    // Either no rows (ErrNoRows) or a valid enum value.
    if err != nil && err.Error() != "no rows in result set" {
        t.Fatal(err)
    }

    var colCount int
    require.NoError(t, pool.QueryRow(ctx, `
        SELECT count(*) FROM information_schema.columns
        WHERE table_schema='governance' AND table_name='approval_requests'
          AND column_name IN ('required_approvals','current_approvals','target_transition','project_id')
    `).Scan(&colCount))
    require.Equal(t, 4, colCount)

    var decTbl int
    require.NoError(t, pool.QueryRow(ctx, `
        SELECT count(*) FROM information_schema.tables
        WHERE table_schema='governance' AND table_name='approval_decisions'
    `).Scan(&decTbl))
    require.Equal(t, 1, decTbl)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/governance -run TestMigration024Applied -v`
Expected: FAIL — `column "sensitivity" does not exist` or similar.

- [ ] **Step 3: Write the up migration**

Create `migrations/024_governance_ops.up.sql` with the SQL from §2.1, §2.2, §2.3, §2.4, §2.5 in order. Every statement must use `CREATE TABLE IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS` so the migration is idempotent.

- [ ] **Step 4: Write the down migration**

```sql
-- migrations/024_governance_ops.down.sql
DROP TABLE IF EXISTS governance.export_jobs;
DROP TABLE IF EXISTS governance.control_mappings;
DROP TABLE IF EXISTS governance.control_items;
DROP TABLE IF EXISTS governance.control_catalogs;
DROP TABLE IF EXISTS governance.project_sla_policies;
DROP TABLE IF EXISTS governance.approval_decisions;

ALTER TABLE governance.approval_requests
  DROP COLUMN IF EXISTS required_approvals,
  DROP COLUMN IF EXISTS current_approvals,
  DROP COLUMN IF EXISTS target_transition,
  DROP COLUMN IF EXISTS project_id;

ALTER TABLE governance.org_settings
  DROP COLUMN IF EXISTS require_closure_approval,
  DROP COLUMN IF EXISTS require_two_person_closure,
  DROP COLUMN IF EXISTS approval_expiry_days,
  DROP COLUMN IF EXISTS sla_warning_window_days;

ALTER TABLE core.projects DROP COLUMN IF EXISTS sensitivity;
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/governance -run TestMigration024Applied -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add migrations/024_governance_ops.up.sql migrations/024_governance_ops.down.sql internal/governance/migration_test.go
git commit -m "feat(governance): add schema for closure approvals, project SLA policies, compliance catalogs, export jobs"
```

---

#### Task A2: Closure approval detection

**Files:**
- Create: `internal/governance/closure.go`
- Modify: `internal/governance/transitions.go:1-46`
- Test: `internal/governance/closure_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/governance/closure_test.go
package governance_test

import (
    "context"
    "testing"
    "github.com/google/uuid"
    "github.com/stretchr/testify/require"
    "sentinelcore/internal/governance"
    "sentinelcore/internal/testutil"
)

func TestNeedsApprovalForClosure(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    projID := testutil.SeedProject(t, pool, orgID, "standard")

    // Default org_settings: require_closure_approval=false
    required, min, kind, err := governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "resolved")
    require.NoError(t, err)
    require.False(t, required)
    require.Equal(t, 0, min)
    require.Empty(t, kind)

    // Enable org-wide closure approval
    testutil.SetOrgSetting(t, pool, orgID, "require_closure_approval", true)
    required, min, kind, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "resolved")
    require.NoError(t, err)
    require.True(t, required)
    require.Equal(t, 1, min)
    require.Equal(t, "risk_closure", kind)

    // Mark project sensitive + enable two-person closure → min=2
    testutil.SetProjectSensitivity(t, pool, projID, "sensitive")
    testutil.SetOrgSetting(t, pool, orgID, "require_two_person_closure", true)
    required, min, _, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "resolved")
    require.NoError(t, err)
    require.True(t, required)
    require.Equal(t, 2, min)

    // accepted_risk always requires approval (legacy behavior preserved)
    required, min, kind, err = governance.NeedsApproval(ctx, pool, orgID, projID, "confirmed", "accepted_risk")
    require.NoError(t, err)
    require.True(t, required)
    require.Equal(t, "risk_acceptance", kind)

    // Unused value to satisfy linter
    _ = uuid.Nil
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/governance -run TestNeedsApprovalForClosure -v`
Expected: FAIL — old `NeedsApproval` signature does not return `min` or `kind`.

- [ ] **Step 3: Update the transitions file**

Edit `internal/governance/transitions.go`:

```go
package governance

type ApprovalReq struct {
    Kind         string
    MinApprovers int
}

var ApprovalTargets = map[string]ApprovalReq{
    "accepted_risk":  {Kind: "risk_acceptance",     MinApprovers: 1},
    "false_positive": {Kind: "false_positive_mark", MinApprovers: 1},
    "resolved":       {Kind: "risk_closure",        MinApprovers: 1},
}
```

- [ ] **Step 4: Implement `NeedsApproval` in closure.go**

```go
// internal/governance/closure.go
package governance

import (
    "context"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
)

func NeedsApproval(ctx context.Context, pool *pgxpool.Pool, orgID, projectID uuid.UUID, from, to string) (bool, int, string, error) {
    base, ok := ApprovalTargets[to]
    if !ok {
        return false, 0, "", nil
    }

    var (
        requireClosure  bool
        requireTwoPerson bool
        sensitivity     string
    )
    err := pool.QueryRow(ctx, `
        SELECT os.require_closure_approval, os.require_two_person_closure, p.sensitivity
        FROM governance.org_settings os
        JOIN core.projects p ON p.id = $2
        WHERE os.org_id = $1
    `, orgID, projectID).Scan(&requireClosure, &requireTwoPerson, &sensitivity)
    if err != nil {
        return false, 0, "", err
    }

    if to == "resolved" && !requireClosure {
        return false, 0, "", nil
    }

    min := base.MinApprovers
    if requireTwoPerson && (sensitivity == "sensitive" || sensitivity == "regulated") {
        if min < 2 {
            min = 2
        }
    }
    return true, min, base.Kind, nil
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/governance -run TestNeedsApprovalForClosure -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/governance/closure.go internal/governance/transitions.go internal/governance/closure_test.go
git commit -m "feat(governance): add closure + two-person approval detection"
```

---

#### Task A3: Approval decisions service (multi-approver)

**Files:**
- Create: `internal/governance/decisions.go`
- Modify: `internal/governance/workflow.go` (extend `DecideApproval` to record decisions + gate on `current_approvals`)
- Test: `internal/governance/decisions_test.go`

- [ ] **Step 1: Write the failing test — segregation of duties**

```go
// internal/governance/decisions_test.go
package governance_test

import (
    "context"
    "testing"
    "github.com/stretchr/testify/require"
    "sentinelcore/internal/governance"
    "sentinelcore/internal/testutil"
)

func TestDecideApprovalForbidsSelfApproval(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    requester := testutil.SeedUser(t, pool, orgID, "security_admin")

    req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
        OrgID: orgID, RequestedBy: requester,
        RequestType: "risk_closure", ResourceType: "finding",
        ResourceID: "abc", Reason: "test",
        RequiredApprovals: 1, TargetTransition: "resolved",
    })
    require.NoError(t, err)

    _, err = governance.DecideApproval(ctx, pool, req.ID, requester, "approve", "self")
    require.ErrorIs(t, err, governance.ErrSelfApprovalForbidden)
}

func TestDecideApprovalTwoPersonFulfilled(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    requester := testutil.SeedUser(t, pool, orgID, "security_admin")
    approver1 := testutil.SeedUser(t, pool, orgID, "security_admin")
    approver2 := testutil.SeedUser(t, pool, orgID, "security_admin")

    req, err := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
        OrgID: orgID, RequestedBy: requester,
        RequestType: "risk_closure", ResourceType: "finding",
        ResourceID: "abc", Reason: "test",
        RequiredApprovals: 2, TargetTransition: "resolved",
    })
    require.NoError(t, err)

    // First approval — still pending.
    updated, err := governance.DecideApproval(ctx, pool, req.ID, approver1, "approve", "looks good")
    require.NoError(t, err)
    require.Equal(t, "pending", updated.Status)
    require.Equal(t, 1, updated.CurrentApprovals)

    // Second approval — promotes to approved.
    updated, err = governance.DecideApproval(ctx, pool, req.ID, approver2, "approve", "confirmed")
    require.NoError(t, err)
    require.Equal(t, "approved", updated.Status)
    require.Equal(t, 2, updated.CurrentApprovals)

    // Same approver decides again → error.
    _, err = governance.DecideApproval(ctx, pool, req.ID, approver1, "approve", "again")
    require.ErrorIs(t, err, governance.ErrDuplicateDecision)
}

func TestDecideApprovalRejectShortCircuits(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    requester := testutil.SeedUser(t, pool, orgID, "security_admin")
    a1 := testutil.SeedUser(t, pool, orgID, "security_admin")
    a2 := testutil.SeedUser(t, pool, orgID, "security_admin")

    req, _ := governance.CreateApprovalRequest(ctx, pool, governance.CreateApprovalReq{
        OrgID: orgID, RequestedBy: requester,
        RequestType: "risk_closure", ResourceType: "finding",
        ResourceID: "abc", Reason: "test",
        RequiredApprovals: 2, TargetTransition: "resolved",
    })
    _, err := governance.DecideApproval(ctx, pool, req.ID, a1, "reject", "nope")
    require.NoError(t, err)

    _, err = governance.DecideApproval(ctx, pool, req.ID, a2, "approve", "still ok")
    require.ErrorIs(t, err, governance.ErrAlreadyDecided)
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/governance -run TestDecideApproval -v`
Expected: FAIL — missing errors + decisions plumbing.

- [ ] **Step 3: Implement the decisions service**

```go
// internal/governance/decisions.go
package governance

import (
    "context"
    "errors"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

var (
    ErrSelfApprovalForbidden = errors.New("self-approval forbidden")
    ErrDuplicateDecision     = errors.New("approver already decided")
    ErrAlreadyDecided        = errors.New("approval request already decided")
    ErrExpired               = errors.New("approval request expired")
)

type Decision struct {
    ID                 uuid.UUID
    ApprovalRequestID  uuid.UUID
    DecidedBy          uuid.UUID
    Decision           string
    Reason             string
    DecidedAt          time.Time
}

// recordDecision inserts a row into governance.approval_decisions inside an existing tx
// and returns the number of approve rows currently recorded.
func recordDecision(ctx context.Context, tx pgx.Tx, reqID, decidedBy uuid.UUID, decision, reason string) (approves int, err error) {
    _, err = tx.Exec(ctx, `
        INSERT INTO governance.approval_decisions (approval_request_id, decided_by, decision, reason)
        VALUES ($1, $2, $3, $4)
    `, reqID, decidedBy, decision, reason)
    if err != nil {
        // unique_violation → duplicate decision
        if pgErr := pgxError(err); pgErr == "23505" {
            return 0, ErrDuplicateDecision
        }
        return 0, err
    }
    err = tx.QueryRow(ctx, `
        SELECT count(*) FROM governance.approval_decisions
        WHERE approval_request_id = $1 AND decision = 'approve'
    `, reqID).Scan(&approves)
    return
}

// pgxError returns the PG SQLSTATE or "" for non-pg errors.
func pgxError(err error) string {
    var pgErr interface{ SQLState() string }
    if errors.As(err, &pgErr) {
        return pgErr.SQLState()
    }
    return ""
}
```

- [ ] **Step 4: Extend `DecideApproval` in workflow.go**

Replace the body of `DecideApproval(ctx, pool, reqID, decidedBy, decision, reason)`:

```go
func DecideApproval(ctx context.Context, pool *pgxpool.Pool, reqID, decidedBy uuid.UUID, decision, reason string) (*ApprovalRequest, error) {
    tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
    if err != nil { return nil, err }
    defer tx.Rollback(ctx)

    var req ApprovalRequest
    err = tx.QueryRow(ctx, `
        SELECT id, org_id, requested_by, request_type, resource_type, resource_id,
               reason, status, required_approvals, current_approvals, target_transition,
               expires_at
        FROM governance.approval_requests
        WHERE id = $1
        FOR UPDATE
    `, reqID).Scan(&req.ID, &req.OrgID, &req.RequestedBy, &req.RequestType,
        &req.ResourceType, &req.ResourceID, &req.Reason, &req.Status,
        &req.RequiredApprovals, &req.CurrentApprovals, &req.TargetTransition, &req.ExpiresAt)
    if err != nil { return nil, err }

    if req.Status != "pending" { return nil, ErrAlreadyDecided }
    if time.Now().After(req.ExpiresAt) { return nil, ErrExpired }
    if req.RequestedBy == decidedBy { return nil, ErrSelfApprovalForbidden }

    approves, err := recordDecision(ctx, tx, reqID, decidedBy, decision, reason)
    if err != nil { return nil, err }

    newStatus := "pending"
    switch {
    case decision == "reject":
        newStatus = "rejected"
    case approves >= req.RequiredApprovals:
        newStatus = "approved"
    }

    _, err = tx.Exec(ctx, `
        UPDATE governance.approval_requests
           SET status = $1, current_approvals = $2,
               decided_by = CASE WHEN $1 <> 'pending' THEN $3 ELSE decided_by END,
               decision_reason = CASE WHEN $1 <> 'pending' THEN $4 ELSE decision_reason END,
               decided_at = CASE WHEN $1 <> 'pending' THEN now() ELSE decided_at END
         WHERE id = $5
    `, newStatus, approves, decidedBy, reason, reqID)
    if err != nil { return nil, err }

    req.Status = newStatus
    req.CurrentApprovals = approves
    return &req, tx.Commit(ctx)
}
```

Also update `ApprovalRequest` in `types.go` to add `RequiredApprovals int`, `CurrentApprovals int`, `TargetTransition string`, `ProjectID *uuid.UUID`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/governance -run TestDecideApproval -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/governance/decisions.go internal/governance/workflow.go internal/governance/types.go internal/governance/decisions_test.go
git commit -m "feat(governance): record per-approver decisions and support two-person rule"
```

---

#### Task A4: Triage executes approved transitions

**Files:**
- Modify: `internal/governance/triage.go`
- Test: `internal/governance/triage_test.go` (add new cases)

- [ ] **Step 1: Add failing test for "approval approved → transition executes"**

```go
func TestTriageExecutesAfterApproval(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    projID := testutil.SeedProject(t, pool, orgID, "sensitive")
    testutil.SetOrgSetting(t, pool, orgID, "require_closure_approval", true)
    testutil.SetOrgSetting(t, pool, orgID, "require_two_person_closure", true)

    requester := testutil.SeedUser(t, pool, orgID, "security_admin")
    a1 := testutil.SeedUser(t, pool, orgID, "security_admin")
    a2 := testutil.SeedUser(t, pool, orgID, "security_admin")

    findingID := testutil.SeedFinding(t, pool, projID, "confirmed")

    res, err := governance.TriageFinding(ctx, pool, governance.TriageInput{
        OrgID: orgID, ProjectID: projID, FindingID: findingID,
        ActorID: requester, FromStatus: "confirmed", ToStatus: "resolved",
        Reason: "patched",
    })
    require.NoError(t, err)
    require.True(t, res.PendingApproval)
    require.NotNil(t, res.ApprovalRequestID)

    // Two approvals.
    _, err = governance.DecideApproval(ctx, pool, *res.ApprovalRequestID, a1, "approve", "ok")
    require.NoError(t, err)
    _, err = governance.DecideApproval(ctx, pool, *res.ApprovalRequestID, a2, "approve", "ok")
    require.NoError(t, err)

    // After approval, triage executes transition.
    require.NoError(t, governance.ExecuteApprovedTransition(ctx, pool, *res.ApprovalRequestID))

    var status string
    require.NoError(t, pool.QueryRow(ctx,
        `SELECT status FROM findings.findings WHERE id=$1`, findingID).Scan(&status))
    require.Equal(t, "resolved", status)
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/governance -run TestTriageExecutesAfterApproval -v`
Expected: FAIL — `ExecuteApprovedTransition` not defined.

- [ ] **Step 3: Implement `ExecuteApprovedTransition`**

```go
// in internal/governance/triage.go
func ExecuteApprovedTransition(ctx context.Context, pool *pgxpool.Pool, approvalReqID uuid.UUID) error {
    tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
    if err != nil { return err }
    defer tx.Rollback(ctx)

    var req ApprovalRequest
    err = tx.QueryRow(ctx, `
        SELECT id, org_id, requested_by, request_type, resource_type, resource_id,
               status, target_transition
        FROM governance.approval_requests
        WHERE id = $1 FOR UPDATE
    `, approvalReqID).Scan(&req.ID, &req.OrgID, &req.RequestedBy, &req.RequestType,
        &req.ResourceType, &req.ResourceID, &req.Status, &req.TargetTransition)
    if err != nil { return err }
    if req.Status != "approved" { return errors.New("approval request not approved") }
    if req.ResourceType != "finding" || req.TargetTransition == "" {
        return errors.New("unsupported approval for auto-execution")
    }

    _, err = tx.Exec(ctx, `
        UPDATE findings.findings SET status = $1, updated_at = now()
        WHERE id = $2::uuid
    `, req.TargetTransition, req.ResourceID)
    if err != nil { return err }

    // Idempotency guard: mark that we executed.
    _, err = tx.Exec(ctx, `
        UPDATE governance.approval_requests
           SET status = 'executed'
         WHERE id = $1 AND status = 'approved'
    `, approvalReqID)
    if err != nil { return err }

    return tx.Commit(ctx)
}
```

Note: `TriageFinding` changes to call `NeedsApproval` (now 4-return) and to set `RequiredApprovals` on the created request.

Also extend the CHECK constraint on `approval_requests.status` to include `'executed'` via an `ALTER TABLE ... DROP CONSTRAINT ... ADD CONSTRAINT` block added to migration 024.

- [ ] **Step 4: Verify test passes.**

Run: `go test ./internal/governance -run TestTriageExecutesAfterApproval -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/governance/triage.go internal/governance/triage_test.go migrations/024_governance_ops.up.sql migrations/024_governance_ops.down.sql
git commit -m "feat(governance): execute approved transitions + extend status constraint"
```

---

#### Task A5: Approval HTTP API

**Files:**
- Create: `internal/controlplane/api/approvals.go`
- Modify: `internal/controlplane/server.go` (route registration)
- Modify: `internal/policy/rbac.go` (permissions)
- Test: `internal/controlplane/api/approvals_test.go`

- [ ] **Step 1: Write HTTP test**

```go
// internal/controlplane/api/approvals_test.go
func TestApprovalsListHandler_ReturnsPendingForOrg(t *testing.T) {
    ctx := context.Background()
    srv := apitest.NewServer(t)
    admin := srv.SeedUser("security_admin")
    other := srv.SeedUser("security_admin") // different user in same org
    findingID := srv.SeedFinding("confirmed")

    // Enable closure approval.
    srv.SetOrgSetting("require_closure_approval", true)

    // Admin triages → pending approval.
    srv.API(admin).POST("/api/v1/findings/"+findingID+"/triage",
        `{"to_status":"resolved","reason":"patched"}`).ExpectStatus(202)

    // Other user lists pending approvals.
    resp := srv.API(other).GET("/api/v1/governance/approvals?status=pending").ExpectOK()
    var got apitest.ApprovalsPage
    resp.DecodeJSON(&got)
    require.Len(t, got.Items, 1)
    require.Equal(t, "risk_closure", got.Items[0].RequestType)
}

func TestApprovalsDecideHandler_SelfApprovalForbidden(t *testing.T) {
    srv := apitest.NewServer(t)
    admin := srv.SeedUser("security_admin")
    findingID := srv.SeedFinding("confirmed")
    srv.SetOrgSetting("require_closure_approval", true)

    triage := srv.API(admin).POST("/api/v1/findings/"+findingID+"/triage",
        `{"to_status":"resolved","reason":"patched"}`).ExpectStatus(202).JSONPath("approval_request_id")

    // Self-approve → 403.
    srv.API(admin).POST("/api/v1/governance/approvals/"+triage+"/decide",
        `{"decision":"approve","reason":"me"}`).ExpectStatus(403)
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/controlplane/api -run TestApprovals -v`
Expected: FAIL — handlers missing.

- [ ] **Step 3: Implement the handlers**

```go
// internal/controlplane/api/approvals.go
package api

import (
    "encoding/json"
    "errors"
    "net/http"
    "github.com/google/uuid"
    "sentinelcore/internal/governance"
    "sentinelcore/internal/policy"
)

func (h *Handlers) ListApprovals(w http.ResponseWriter, r *http.Request) {
    user := requireAuth(w, r)
    if user == nil { return }
    if !policy.Evaluate(user.Role, "governance.approvals.read") {
        writeError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions"); return
    }
    status := r.URL.Query().Get("status")
    items, err := governance.ListApprovalRequests(r.Context(), h.pool, user.OrgID, status)
    if err != nil { writeError(w, 500, "INTERNAL", err.Error()); return }
    writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type decideReq struct {
    Decision string `json:"decision"`
    Reason   string `json:"reason"`
}

func (h *Handlers) DecideApproval(w http.ResponseWriter, r *http.Request) {
    user := requireAuth(w, r)
    if user == nil { return }
    if !policy.Evaluate(user.Role, "governance.approvals.decide") {
        writeError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions"); return
    }

    reqID, err := uuid.Parse(r.PathValue("id"))
    if err != nil { writeError(w, 400, "INVALID_ID", err.Error()); return }

    var body decideReq
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        writeError(w, 400, "INVALID_BODY", err.Error()); return
    }
    if body.Decision != "approve" && body.Decision != "reject" {
        writeError(w, 400, "INVALID_DECISION", "decision must be approve or reject"); return
    }
    if body.Reason == "" {
        writeError(w, 400, "REASON_REQUIRED", "reason is required"); return
    }

    updated, err := governance.DecideApproval(r.Context(), h.pool, reqID, user.ID, body.Decision, body.Reason)
    switch {
    case errors.Is(err, governance.ErrSelfApprovalForbidden):
        writeError(w, 403, "SELF_APPROVAL_FORBIDDEN", err.Error()); return
    case errors.Is(err, governance.ErrDuplicateDecision):
        writeError(w, 409, "DUPLICATE_DECISION", err.Error()); return
    case errors.Is(err, governance.ErrAlreadyDecided):
        writeError(w, 409, "ALREADY_DECIDED", err.Error()); return
    case errors.Is(err, governance.ErrExpired):
        writeError(w, 410, "EXPIRED", err.Error()); return
    case err != nil:
        writeError(w, 500, "INTERNAL", err.Error()); return
    }

    h.emitAuditEvent(r.Context(), auditActionFromDecision(body.Decision), "approval_request", reqID.String(), user, nil)

    // If approval just fulfilled, kick off the transition.
    if updated.Status == "approved" {
        if err := governance.ExecuteApprovedTransition(r.Context(), h.pool, reqID); err != nil {
            writeError(w, 500, "TRANSITION_FAILED", err.Error()); return
        }
    }
    writeJSON(w, 200, updated)
}

func auditActionFromDecision(d string) string {
    if d == "approve" { return "approval.approved" }
    return "approval.rejected"
}
```

- [ ] **Step 4: Register routes + permissions**

In `internal/controlplane/server.go`:

```go
mux.HandleFunc("GET /api/v1/governance/approvals",      h.ListApprovals)
mux.HandleFunc("GET /api/v1/governance/approvals/{id}", h.GetApproval)
mux.HandleFunc("POST /api/v1/governance/approvals/{id}/decide", h.DecideApproval)
```

In `internal/policy/rbac.go` add `governance.approvals.read` to all roles (read access is safe) and the other permissions per the table in §"New RBAC permissions".

- [ ] **Step 5: Verify tests pass.**

Run: `go test ./internal/controlplane/api -run TestApprovals -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/controlplane/api/approvals.go internal/controlplane/server.go internal/policy/rbac.go internal/controlplane/api/approvals_test.go
git commit -m "feat(api): expose approvals list + decide endpoints with RBAC"
```

---

#### Task A6: Frontend approval dialog + inbox

**Files:**
- Create: `web/features/findings/approval-dialog.tsx`
- Create: `web/features/governance/approvals-inbox.tsx`
- Create: `web/features/governance/approvals-api.ts`
- Test: `web/features/governance/__tests__/approvals-inbox.test.tsx`

- [ ] **Step 1: Write the failing component test**

```tsx
// web/features/governance/__tests__/approvals-inbox.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ApprovalsInbox } from '../approvals-inbox';
import { mockServer } from '@/test/mocks';

test('shows pending approvals and allows decide', async () => {
  mockServer.use(
    rest.get('/api/v1/governance/approvals', (req, res, ctx) =>
      res(ctx.json({ items: [{ id: 'r1', request_type: 'risk_closure', reason: 'patched',
                               requested_by: 'alice', required_approvals: 2, current_approvals: 1 }] }))),
    rest.post('/api/v1/governance/approvals/r1/decide', (req, res, ctx) =>
      res(ctx.json({ id: 'r1', status: 'approved' }))),
  );
  render(<ApprovalsInbox />);
  await waitFor(() => screen.getByText('risk_closure'));
  await userEvent.click(screen.getByRole('button', { name: /approve/i }));
  await userEvent.type(screen.getByLabelText(/reason/i), 'verified');
  await userEvent.click(screen.getByRole('button', { name: /confirm/i }));
  await waitFor(() => screen.getByText(/approved/));
});
```

- [ ] **Step 2: Run, verify fail.**

Run: `pnpm --filter web test -- approvals-inbox`
Expected: FAIL — components missing.

- [ ] **Step 3: Implement api client + inbox + dialog**

Follow the TanStack Query + Zod pattern from `web/features/governance/approvals-table.tsx` — the existing `approvals-table.tsx` can be generalized or superseded. Keep one shared component. Use `zod` schemas to validate the API response. The dialog must display `current_approvals / required_approvals` so the two-person state is obvious to the user.

- [ ] **Step 4: Verify test passes.**

Run: `pnpm --filter web test -- approvals-inbox`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/features/findings/approval-dialog.tsx web/features/governance/approvals-inbox.tsx web/features/governance/approvals-api.ts web/features/governance/__tests__/approvals-inbox.test.tsx
git commit -m "feat(web): approvals inbox and per-finding approval dialog"
```

---

### Epic B — SLA tracking API + per-project policies + dashboard

#### Task B1: Per-project SLA policy resolver

**Files:**
- Create: `internal/governance/sla_policy.go`
- Modify: `internal/governance/sla.go:1-151` (`CalculateSLADeadline` uses resolver)
- Test: `internal/governance/sla_policy_test.go`

- [ ] **Step 1: Write failing test**

```go
func TestResolveSLADays_ProjectOverridesOrg(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    projID := testutil.SeedProject(t, pool, orgID, "standard")

    // Org default sets high=7, project override sets high=3.
    days, err := governance.ResolveSLADays(ctx, pool, orgID, projID)
    require.NoError(t, err)
    require.Equal(t, 7, days["high"])

    testutil.UpsertProjectSLA(t, pool, orgID, projID,
        map[string]int{"critical": 1, "high": 3, "medium": 14, "low": 60})

    days, err = governance.ResolveSLADays(ctx, pool, orgID, projID)
    require.NoError(t, err)
    require.Equal(t, 3, days["high"])
    require.Equal(t, 1, days["critical"])
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/governance -run TestResolveSLADays -v`
Expected: FAIL — `ResolveSLADays` missing.

- [ ] **Step 3: Implement resolver**

```go
// internal/governance/sla_policy.go
package governance

import (
    "context"
    "encoding/json"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

var DefaultSLADays = map[string]int{"critical": 3, "high": 7, "medium": 30, "low": 90}

func ResolveSLADays(ctx context.Context, pool *pgxpool.Pool, orgID, projectID uuid.UUID) (map[string]int, error) {
    var raw []byte
    err := pool.QueryRow(ctx, `
        SELECT sla_days FROM governance.project_sla_policies WHERE project_id = $1
    `, projectID).Scan(&raw)
    if err == nil {
        out := map[string]int{}
        if jerr := json.Unmarshal(raw, &out); jerr == nil { return out, nil }
    }
    if err != nil && err != pgx.ErrNoRows { return nil, err }

    err = pool.QueryRow(ctx, `
        SELECT default_finding_sla_days FROM governance.org_settings WHERE org_id = $1
    `, orgID).Scan(&raw)
    if err == nil {
        out := map[string]int{}
        if jerr := json.Unmarshal(raw, &out); jerr == nil { return out, nil }
    }
    return DefaultSLADays, nil
}
```

`CalculateSLADeadline(severity, firstSeen, days)` becomes a pure helper with no DB access; the DB path is factored into `ResolveSLADays`.

- [ ] **Step 4: Verify pass.**

Run: `go test ./internal/governance -run TestResolveSLADays -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/governance/sla_policy.go internal/governance/sla.go internal/governance/sla_policy_test.go
git commit -m "feat(governance): per-project SLA policy resolver"
```

---

#### Task B2: SLA API + dashboard

**Files:**
- Create: `internal/controlplane/api/sla.go`
- Modify: `internal/controlplane/server.go`
- Test: `internal/controlplane/api/sla_test.go`

- [ ] **Step 1: Failing test for dashboard summary**

```go
func TestSLADashboard_ReturnsCountsBySeverityAndStatus(t *testing.T) {
    srv := apitest.NewServer(t)
    analyst := srv.SeedUser("appsec_analyst")
    proj := srv.SeedProject("standard")
    // Breached in past:
    srv.SeedFindingWithDeadline(proj, "high", "-1h")
    // At risk (deadline in 2 days, warning window default 7):
    srv.SeedFindingWithDeadline(proj, "critical", "2d")
    // On track:
    srv.SeedFindingWithDeadline(proj, "low", "60d")

    resp := srv.API(analyst).GET("/api/v1/governance/sla/dashboard").ExpectOK()
    var dash struct {
        CountsByStatus map[string]int `json:"counts_by_status"`
        CountsBySeverity map[string]int `json:"counts_by_severity"`
    }
    resp.DecodeJSON(&dash)
    require.Equal(t, 1, dash.CountsByStatus["breached"])
    require.Equal(t, 1, dash.CountsByStatus["at_risk"])
    require.Equal(t, 1, dash.CountsByStatus["on_track"])
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/controlplane/api -run TestSLADashboard -v`
Expected: FAIL.

- [ ] **Step 3: Implement API**

```go
// internal/controlplane/api/sla.go
package api

import (
    "net/http"
    "sentinelcore/internal/governance"
    "sentinelcore/internal/policy"
)

func (h *Handlers) SLADashboard(w http.ResponseWriter, r *http.Request) {
    user := requireAuth(w, r); if user == nil { return }
    if !policy.Evaluate(user.Role, "governance.sla.read") {
        writeError(w, 403, "FORBIDDEN", "insufficient permissions"); return
    }
    dash, err := governance.GetSLADashboard(r.Context(), h.pool, user.OrgID)
    if err != nil { writeError(w, 500, "INTERNAL", err.Error()); return }
    writeJSON(w, 200, dash)
}

func (h *Handlers) ListSLAViolations(w http.ResponseWriter, r *http.Request) { /* … */ }
func (h *Handlers) GetProjectSLAPolicy(w http.ResponseWriter, r *http.Request) { /* … */ }
func (h *Handlers) PutProjectSLAPolicy(w http.ResponseWriter, r *http.Request) { /* … */ }
func (h *Handlers) DeleteProjectSLAPolicy(w http.ResponseWriter, r *http.Request) { /* … */ }
```

Implement `GetSLADashboard` in `internal/governance/sla_api.go`:

```go
type SLADashboard struct {
    CountsByStatus   map[string]int   `json:"counts_by_status"`
    CountsBySeverity map[string]int   `json:"counts_by_severity"`
    TopBreaches      []BreachSummary  `json:"top_breaches"`
    Trend            []TrendBucket    `json:"trend"`
}

func GetSLADashboard(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (*SLADashboard, error) {
    // SELECT with CASE WHEN sla_deadline < now() AND status NOT IN (...) THEN 'breached' ...
}
```

Register routes:

```go
mux.HandleFunc("GET /api/v1/governance/sla/dashboard", h.SLADashboard)
mux.HandleFunc("GET /api/v1/governance/sla/violations", h.ListSLAViolations)
mux.HandleFunc("GET /api/v1/governance/sla/policies/{project_id}", h.GetProjectSLAPolicy)
mux.HandleFunc("PUT /api/v1/governance/sla/policies/{project_id}", h.PutProjectSLAPolicy)
mux.HandleFunc("DELETE /api/v1/governance/sla/policies/{project_id}", h.DeleteProjectSLAPolicy)
```

- [ ] **Step 4: Verify pass.**

Run: `go test ./internal/controlplane/api -run TestSLADashboard -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/controlplane/api/sla.go internal/governance/sla_api.go internal/controlplane/server.go internal/controlplane/api/sla_test.go
git commit -m "feat(api): SLA dashboard, violations, and project policy endpoints"
```

---

#### Task B3: Split SLA check into its own worker

**Files:**
- Create: `cmd/sla-worker/main.go`
- Modify: `deploy/docker-compose/docker-compose.yml`
- Test: `cmd/sla-worker/main_test.go`

- [ ] **Step 1: Failing integration test**

```go
func TestSLAWorker_InsertsViolationsAndEmitsEvents(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    js := testutil.NewTestJS(t)
    orgID := testutil.SeedOrg(t, pool)
    proj := testutil.SeedProject(t, pool, orgID, "standard")
    findingID := testutil.SeedFindingWithDeadline(t, pool, proj, "high", -time.Hour)

    worker := slaworker.New(pool, js)
    require.NoError(t, worker.RunOnce(ctx))

    var n int
    require.NoError(t, pool.QueryRow(ctx,
        `SELECT count(*) FROM governance.sla_violations WHERE finding_id=$1 AND resolved_at IS NULL`,
        findingID).Scan(&n))
    require.Equal(t, 1, n)
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./cmd/sla-worker -v`
Expected: FAIL.

- [ ] **Step 3: Implement worker**

Cleanest implementation: extract `CheckSLAViolations` / `CheckSLAWarnings` from `internal/governance/sla.go` into `internal/governance/slaworker/`, expose a `RunOnce(ctx)` method that:

- Uses a service-role pool (no RLS) to iterate all orgs.
- For each org: select overdue findings without open violations → insert + emit audit + emit notification.
- For each org: select near-deadline findings → emit `sla.at_risk` idempotently (dedup via `governance.notifications` composite index on `user_id, resource_id, category`).
- Hourly loop driven by `time.NewTicker(1*time.Hour)` + a context-aware shutdown.

`cmd/sla-worker/main.go` mirrors `cmd/retention-worker/main.go` — same config loading, logger, NATS wiring.

Add to `deploy/docker-compose/docker-compose.yml`:

```yaml
sla-worker:
  build: { context: ../.., dockerfile: Dockerfile, target: sla-worker }
  depends_on: [postgres, nats]
  environment:
    DATABASE_URL: ${DATABASE_URL}
    NATS_URL: ${NATS_URL}
    SLA_WORKER_INTERVAL: 1h
```

- [ ] **Step 4: Verify pass.**

Run: `go test ./cmd/sla-worker -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/sla-worker internal/governance/slaworker deploy/docker-compose/docker-compose.yml
git commit -m "feat(sla): dedicated sla-worker for breach + at-risk detection"
```

---

#### Task B4: Frontend SLA dashboard + policy editor

Follow Task A6's pattern:

- `web/features/governance/sla-dashboard.tsx` — counts cards, breaches table, trend sparkline.
- `web/features/governance/sla-policies-form.tsx` — edit per-project SLA days, save via PUT.
- Component tests for both.
- Commit: `feat(web): SLA dashboard + per-project policy editor`.

---

### Epic C — Compliance catalogs and mappings

#### Task C1: `internal/compliance` package + CRUD

**Files:**
- Create: `internal/compliance/types.go`, `catalog.go`, `mapping.go`, `mapping_test.go`
- Test: `internal/compliance/mapping_test.go`

- [ ] **Step 1: Failing test for resolver**

```go
// internal/compliance/mapping_test.go
func TestResolveControls_MergesBuiltinAndCustom(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)

    // Assume seed migration 025 inserted CWE-79 → OWASP A03 (normative).
    refs, err := compliance.ResolveControls(ctx, pool, orgID, 79)
    require.NoError(t, err)
    var owasp string
    for _, r := range refs {
        if r.CatalogCode == "OWASP_TOP10_2021" { owasp = r.ControlID }
    }
    require.Equal(t, "A03", owasp)

    // Tenant adds a custom mapping CWE-79 → internal SEC-007.
    customCatalogID := testutil.SeedCustomCatalog(t, pool, orgID, "INTERNAL_SEC", "1.0")
    itemID := testutil.SeedCustomItem(t, pool, customCatalogID, "SEC-007", "Secure output encoding")
    testutil.SeedCustomMapping(t, pool, orgID, "cwe", "CWE-79", itemID, "custom")

    refs, _ = compliance.ResolveControls(ctx, pool, orgID, 79)
    var hasCustom bool
    for _, r := range refs {
        if r.ControlID == "SEC-007" { hasCustom = true }
    }
    require.True(t, hasCustom)
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/compliance -v`
Expected: FAIL.

- [ ] **Step 3: Implement types + resolver**

```go
// internal/compliance/types.go
package compliance

import "github.com/google/uuid"

type Catalog struct { ID uuid.UUID; OrgID *uuid.UUID; Code, Name, Version, Description string; IsBuiltin bool }
type Item    struct { ID uuid.UUID; CatalogID uuid.UUID; ControlID, Title, Description string }
type ControlRef struct {
    CatalogCode, CatalogName, ControlID, Title string
    Confidence, SourceKind, SourceCode         string
}
```

```go
// internal/compliance/mapping.go
func ResolveControls(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, cweID int) ([]ControlRef, error) {
    rows, err := pool.Query(ctx, `
        SELECT c.code, c.name, i.control_id, i.title, m.confidence, m.source_kind, m.source_code
        FROM governance.control_mappings m
        JOIN governance.control_items i ON i.id = m.target_control_id
        JOIN governance.control_catalogs c ON c.id = i.catalog_id
        WHERE m.source_kind='cwe' AND m.source_code = $1
          AND (m.org_id IS NULL OR m.org_id = $2)
        ORDER BY CASE m.confidence
            WHEN 'custom' THEN 0 WHEN 'normative' THEN 1 ELSE 2 END
    `, fmt.Sprintf("CWE-%d", cweID), orgID)
    if err != nil { return nil, err }
    defer rows.Close()
    var out []ControlRef
    for rows.Next() {
        var r ControlRef
        if err := rows.Scan(&r.CatalogCode, &r.CatalogName, &r.ControlID, &r.Title,
            &r.Confidence, &r.SourceKind, &r.SourceCode); err != nil { return nil, err }
        out = append(out, r)
    }
    return out, rows.Err()
}
```

- [ ] **Step 4: Verify pass.**

Run: `go test ./internal/compliance -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/compliance/
git commit -m "feat(compliance): catalogs + mappings resolver"
```

---

#### Task C2: Seed migration 025 (built-in catalogs + mappings)

**Files:**
- Create: `migrations/025_compliance_seed.up.sql`
- Create: `migrations/025_compliance_seed.down.sql`
- Test: `internal/compliance/seed_test.go`

- [ ] **Step 1: Failing test — built-in catalogs present**

```go
func TestBuiltinCatalogsPresent(t *testing.T) {
    pool := testutil.NewTestPool(t)
    var n int
    require.NoError(t, pool.QueryRow(context.Background(),
        `SELECT count(*) FROM governance.control_catalogs
         WHERE is_builtin=true AND code IN ('OWASP_TOP10_2021','PCI_DSS_4_0','NIST_800_53_R5')`).Scan(&n))
    require.Equal(t, 3, n)

    require.NoError(t, pool.QueryRow(context.Background(),
        `SELECT count(*) FROM governance.control_mappings
         WHERE org_id IS NULL AND source_kind='cwe' AND source_code='CWE-79'`).Scan(&n))
    require.GreaterOrEqual(t, n, 1)
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/compliance -run TestBuiltinCatalogs -v`
Expected: FAIL.

- [ ] **Step 3: Write the seed migration**

Structure: 3 catalog inserts, ~15 OWASP control_items, ~12 PCI control_items, ~20 NIST control_items, then ~40 CWE→OWASP mappings and ~25 CWE→PCI mappings. All inserts use `ON CONFLICT ... DO NOTHING`. Source versions embedded (`source_version='OWASP Top 10 2021'`).

Put CWE→OWASP data in a CTE for readability:

```sql
INSERT INTO governance.control_catalogs (org_id, code, name, version, is_builtin)
VALUES (NULL, 'OWASP_TOP10_2021', 'OWASP Top 10 (2021)', '2021', true)
ON CONFLICT (org_id, code, version) DO NOTHING;
-- … items
WITH m(cwe, control) AS (VALUES
  ('CWE-79','A03'),('CWE-89','A03'),('CWE-94','A03'),('CWE-78','A03'),
  ('CWE-287','A07'),('CWE-295','A02'),('CWE-327','A02'),
  ('CWE-22','A01'),('CWE-639','A01'),('CWE-601','A04'),
  -- …
  ('CWE-502','A08'),('CWE-918','A10'))
INSERT INTO governance.control_mappings (org_id, source_kind, source_code, target_control_id, confidence, source_version)
SELECT NULL, 'cwe', m.cwe, i.id, 'normative', 'OWASP Top 10 2021'
FROM m
JOIN governance.control_catalogs c ON c.code='OWASP_TOP10_2021'
JOIN governance.control_items   i ON i.catalog_id=c.id AND i.control_id = m.control
ON CONFLICT DO NOTHING;
```

- [ ] **Step 4: Verify pass.**

Run: `go test ./internal/compliance -run TestBuiltin -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add migrations/025_compliance_seed.up.sql migrations/025_compliance_seed.down.sql internal/compliance/seed_test.go
git commit -m "feat(compliance): seed built-in OWASP/PCI/NIST catalogs + CWE mappings"
```

---

#### Task C3: Compliance HTTP API

**Files:**
- Create: `internal/controlplane/api/compliance.go`
- Modify: `internal/controlplane/server.go`
- Test: `internal/controlplane/api/compliance_test.go`

Handlers: `ListCatalogs`, `ListCatalogItems`, `ListMappings`, `CreateCatalog`, `CreateItem`, `CreateMapping`, `DeleteMapping`. RBAC via `compliance.*.read|write`. All mutation paths reject attempts to modify built-in (org_id IS NULL) rows with 403.

Write a failing test, implement, verify, commit as in Task A5.

Commit: `feat(api): compliance catalogs + mappings endpoints`.

---

#### Task C4: Surface controls in existing exports + UI

**Files:**
- Modify: `internal/export/sarif.go:1-277` — inject compliance tags into `result.properties.tags`
- Modify: `internal/export/markdown.go:1-252` — add "Compliance" section
- Modify: `web/features/findings/finding-detail.tsx` (assume exists) — Controls strip
- Create: `web/features/compliance/mappings-editor.tsx`
- Create: `web/features/compliance/catalogs-page.tsx`

Write tests for the SARIF/Markdown output first:

```go
func TestSARIFEmitsComplianceTags(t *testing.T) {
    finding := FindingData{ID:"f1", Title:"XSS", Severity:"high", CWEID: ptrInt(79)}
    out, _ := RenderSARIF(SARIFInput{Finding: finding, Org: orgID})
    require.Contains(t, string(out), `"owasp:A03"`)
    require.Contains(t, string(out), `"pci-dss:6.2.4"`)
}
```

Implement `RenderSARIF` to call `compliance.ResolveControls` and map each `ControlRef` to a tag like `strings.ToLower(r.CatalogCode.split("_")[0]) + ":" + r.ControlID`. Markdown similar with a table.

Commit: `feat(export): compliance tags in SARIF + Markdown reports`.

---

### Epic D — Evidence export packs

#### Task D1: Pack builder core

**Files:**
- Create: `internal/export/evidence_pack.go`
- Create: `internal/export/evidence_pack_writer.go`
- Test: `internal/export/evidence_pack_test.go`

- [ ] **Step 1: Failing test — bundle has expected files**

```go
func TestBuildEvidencePack_ContainsExpectedFiles(t *testing.T) {
    ctx := context.Background()
    pool := testutil.NewTestPool(t)
    orgID := testutil.SeedOrg(t, pool)
    riskID := testutil.SeedRiskWithFinding(t, pool, orgID)
    blob := minio.NewTestClient(t)

    buf := &bytes.Buffer{}
    meta, err := evidence.BuildPack(ctx, evidence.BuildInput{
        DB: pool, Blob: blob, OrgID: orgID,
        Scope: evidence.Scope{Kind: "risk_evidence_pack", RiskIDs: []uuid.UUID{riskID}},
        Format: "zip_json", Writer: buf,
    })
    require.NoError(t, err)
    require.NotZero(t, meta.Size)
    require.NotEmpty(t, meta.SHA256)

    zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
    require.NoError(t, err)
    names := map[string]bool{}
    for _, f := range zr.File { names[f.Name] = true }
    for _, want := range []string{
        "manifest.json", "README.md",
        fmt.Sprintf("risk/%s.json", riskID),
        "compliance/controls.json",
        "timeline/events.json",
        "audit/log.json",
        "approvals/decisions.json",
        "policy/sla_policy.json",
        "policy/org_settings.json",
    } {
        require.True(t, names[want], "missing %s", want)
    }
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./internal/export -run TestBuildEvidencePack -v`
Expected: FAIL.

- [ ] **Step 3: Implement**

Outline (full code ~300 LOC — follow the skeleton below exactly):

```go
// internal/export/evidence_pack.go
package evidence

type BuildInput struct {
    DB     *pgxpool.Pool
    Blob   blobstore.Client
    OrgID  uuid.UUID
    Scope  Scope
    Format string  // "zip_json" or "json"
    Writer io.Writer
}
type Scope struct {
    Kind    string
    RiskIDs []uuid.UUID
    ProjectID *uuid.UUID
    Since   *time.Time
    Statuses []string
}
type BuildMeta struct { Size int64; SHA256 string }

func BuildPack(ctx context.Context, in BuildInput) (BuildMeta, error) {
    h := sha256.New()
    mw := io.MultiWriter(in.Writer, h)
    zw := zip.NewWriter(mw)
    manifest := newManifest(in)

    // 1. Collect risks + findings + evidence per scope.
    // 2. For each risk → write risk/<id>.json + risk/<id>.md.
    // 3. For each finding → write findings/<id>.json + findings/<id>.md.
    // 4. Dedup evidence blobs by hash → evidence/<blob_hash>.bin.
    // 5. Resolve compliance controls for all unique CWEs → compliance/controls.json.
    // 6. Aggregate timeline: findings.first_seen_at, triage transitions, approvals, SLA breaches.
    // 7. Snapshot audit.audit_log rows by (resource_type, resource_id).
    // 8. Snapshot SLA policy + org settings at export time.
    // 9. Every write: manifest.Files = append(…, {path, sha256, size}).
    // 10. README.md: short human summary of contents.
    if err := zw.Close(); err != nil { return BuildMeta{}, err }
    return BuildMeta{Size: int64(h.Size()), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}
```

Use `archive/zip.Writer` with a `Create` per file; stream content through a helper that computes a per-file SHA-256 and appends to `manifest.Files`.

- [ ] **Step 4: Verify pass.**

Run: `go test ./internal/export -run TestBuildEvidencePack -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/export/evidence_pack.go internal/export/evidence_pack_writer.go internal/export/evidence_pack_test.go
git commit -m "feat(export): evidence pack ZIP bundle builder"
```

---

#### Task D2: Export worker + API

**Files:**
- Create: `cmd/export-worker/main.go`
- Create: `internal/controlplane/api/exports.go`
- Modify: `internal/controlplane/server.go`
- Modify: `deploy/docker-compose/docker-compose.yml`
- Test: `cmd/export-worker/main_test.go`, `internal/controlplane/api/exports_test.go`

- [ ] **Step 1: Failing test — request → worker → completed**

```go
func TestExportEndToEnd(t *testing.T) {
    srv := apitest.NewServer(t)
    admin := srv.SeedUser("security_admin")
    risk := srv.SeedRiskWithFinding()

    resp := srv.API(admin).POST("/api/v1/governance/exports",
      fmt.Sprintf(`{"kind":"risk_evidence_pack","scope":{"risk_ids":["%s"]},"format":"zip_json"}`, risk))
    resp.ExpectStatus(202)
    jobID := resp.JSONPath("id")

    srv.RunExportWorkerOnce()

    got := srv.API(admin).GET("/api/v1/governance/exports/"+jobID).ExpectOK()
    require.Equal(t, "completed", got.JSONPath("status"))
    require.NotEmpty(t, got.JSONPath("artifact_hash"))
}
```

- [ ] **Step 2: Run, verify fail.**

Run: `go test ./cmd/export-worker -v && go test ./internal/controlplane/api -run TestExport -v`
Expected: FAIL.

- [ ] **Step 3: Implement API + worker**

API: mirror approvals/sla handler shape. `POST /exports` inserts row + publishes subject; `GET /exports` lists org jobs; `GET /exports/{id}` returns job; `GET /exports/{id}/download` returns 302 to MinIO presigned URL (reject unless `status=completed && expires_at > now()`).

Worker: subscribes to `governance.exports`, for each message:

1. `UPDATE export_jobs SET status='running', started_at=now() WHERE id=$1 AND status='queued'`.
2. Open tmp file, call `evidence.BuildPack(..., Writer: tmpFile)`.
3. Upload to MinIO at `org/<org_id>/exports/<job_id>.zip`.
4. `UPDATE export_jobs SET status='completed', artifact_ref, artifact_hash, artifact_size, completed_at WHERE id=$1`.
5. On any error: `UPDATE … status='failed', error=$err`.

Register routes:

```go
mux.HandleFunc("POST /api/v1/governance/exports",           h.CreateExport)
mux.HandleFunc("GET /api/v1/governance/exports",            h.ListExports)
mux.HandleFunc("GET /api/v1/governance/exports/{id}",       h.GetExport)
mux.HandleFunc("GET /api/v1/governance/exports/{id}/download", h.DownloadExport)
```

- [ ] **Step 4: Verify pass.**

Run: `go test ./cmd/export-worker -v && go test ./internal/controlplane/api -run TestExport -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/export-worker internal/controlplane/api/exports.go internal/controlplane/server.go deploy/docker-compose/docker-compose.yml cmd/export-worker/main_test.go internal/controlplane/api/exports_test.go
git commit -m "feat(export): export-worker + API for evidence pack generation"
```

---

#### Task D3: Extend retention-worker for export artifact purge

**Files:**
- Modify: `cmd/retention-worker/main.go`
- Test: `cmd/retention-worker/main_test.go`

- [ ] **Step 1: Failing test — expired export is purged**

```go
func TestRetentionWorker_PurgesExpiredExports(t *testing.T) {
    srv := apitest.NewServer(t)
    jobID := srv.SeedExportJob("completed", time.Now().Add(-time.Hour))
    srv.RunRetentionWorkerOnce()
    var status string
    srv.Pool.QueryRow(ctx, `SELECT status FROM governance.export_jobs WHERE id=$1`, jobID).Scan(&status)
    require.Equal(t, "expired", status)
    require.False(t, srv.Blob.Exists(fmt.Sprintf("org/*/exports/%s.zip", jobID)))
}
```

- [ ] **Step 2-4: implement, verify, commit.**

Extend the retention loop with:

```go
rows, _ := pool.Query(ctx, `
    SELECT id, org_id, artifact_ref FROM governance.export_jobs
    WHERE status='completed' AND expires_at < now()
`)
// for each: blob.Delete(ref); UPDATE export_jobs SET status='expired'
```

Commit: `feat(retention): purge expired evidence pack artifacts`.

---

#### Task D4: Frontend export UX

**Files:**
- Create: `web/features/governance/export-button.tsx` (per-risk/project button)
- Create: `web/features/governance/exports-page.tsx` (list + status polling + download)
- Test: component tests

Match approvals-inbox pattern. Poll `GET /exports/{id}` every 3s while status is queued/running.

Commit: `feat(web): evidence pack export UI`.

---

### Cross-cutting follow-up task

#### Task X1: Docs + architecture update

**Files:**
- Modify: `docs/ARCHITECTURE.md`

Add a "Governance operations" section covering: approval states, SLA resolution order, compliance mapping precedence, evidence pack format. Update the service catalog to list `sla-worker` and `export-worker`. Update the RBAC matrix.

Commit: `docs(architecture): governance & compliance operations section`.

---

## 8. Pitfalls and rollout risks

1. **Migration 024 numbering collision.** Another feature branch may have also grabbed `024_*`. Before merging this plan's first PR, run `git log --all --oneline -- migrations/` and `ls migrations/` on `main` (`phase1/core-platform`) to confirm 024 is free. If not, bump to the first free slot and re-number 025 as well.

2. **`approval_requests.status` CHECK constraint.** The existing check in migration 014 does not include `'executed'`. The extension in Task A4 must drop and recreate the constraint — not add a new one — or PostgreSQL will error on insert with a duplicate constraint name. Include the `ALTER TABLE ... DROP CONSTRAINT approval_requests_status_check` + re-add in both the up and down migrations.

3. **Self-approval enforcement is doubly layered.** Done at service layer (Task A3). Also add a DB-level trigger (deferred to a follow-up) because an admin with direct DB access could bypass. Not MVP-blocking; document in follow-ups.

4. **SLA deadline recomputation on severity change.** If severity is mutated after creation, the deadline must be recomputed. Audit the finding-update paths in `internal/sast/`, `internal/dast/`, and `internal/risk/correlation.go` — add a call to `RecomputeSLADeadline` in each. Without this, a finding re-scored from `low`→`critical` would still carry a 90-day deadline.

5. **Warning notification storms.** Without idempotency, the hourly worker would emit a warning for every at-risk finding every hour. Dedup via a composite check in `governance.notifications` (e.g. `user_id, resource_id, category` uniqueness) or a purpose-built `sla_warnings_emitted` table. Chosen: lean on existing notifications with a dedup key check before insert.

6. **Evidence pack size blowup.** One risk with 200 findings × 10 MB evidence blobs each → 2 GB. The `SENTINELCORE_EXPORT_MAX_MB` cap must short-circuit before streaming completes so we fail fast, not at upload time. Implement the cap inside the writer by counting bytes written and returning `ErrExportTooLarge` mid-stream.

7. **MinIO presigned URL TTL must exceed the download's network time.** 15 min is safe for <5 GB; tune if exports regularly hit that.

8. **Built-in compliance catalogs are versioned.** Migration 025 seeds `version='2021'` for OWASP. If/when OWASP Top 10 2025 lands, a new migration inserts a new catalog row — don't mutate the 2021 one. The evidence pack manifest must embed the catalog version used at export time for reproducibility.

9. **RLS + cross-org workers.** `sla-worker` and `export-worker` need to iterate all orgs. Either (a) use a service-role DB user that bypasses RLS, or (b) iterate orgs and use `set_config('app.current_org_id', ...)` per org. Option (b) is slower but audit-friendly. Recommend (b) plus dedicated Grafana alerts on worker latency.

10. **Frontend optimistic updates on approvals.** Avoid optimistic update in the approvals dialog — a reject from another approver concurrently can invert state. Re-fetch on every decision.

11. **Approval expiry interacts with executed transitions.** If `status='executed'` we must not move to `expired` in the nightly worker. Scope `ExpirePendingApprovals` query to `WHERE status='pending'`.

12. **Compliance mapping resolver is hot on finding/risk detail.** Every detail page call hits `control_mappings`. Add a small in-memory LRU (`github.com/hashicorp/golang-lru/v2`) keyed by (org_id, source_kind, source_code). TTL 5 min. Invalidate on tenant custom mapping mutations.

13. **Two-person rule and scale.** On projects with <2 eligible approvers, the feature effectively locks closure. The API for enabling the flag must warn the user (frontend) and a `governance.warnings` endpoint should surface projects with the flag enabled but <2 eligible approvers.

14. **Audit log hash chain.** Still unimplemented. Evidence packs include `audit/integrity.json` — for now that file records `{"verified": false, "reason": "hash chain not yet implemented"}`. When the hash chain is wired up, this value flips without a pack format change.

15. **Existing phase4-governance plan overlap.** Some code in this plan touches files from the 2026-03-26 plan (e.g. `internal/governance/workflow.go`). The `DecideApproval` signature change is backwards-incompatible — confirm no external callers exist before merging Task A3. A grep for `governance.DecideApproval(` before merge is mandatory.

---

## 9. Rollout plan

### Phase 1 — Schema + governance extensions (Epic A, Tasks A1–A4)

- Ship migration 024 behind the existing feature flag pattern. Run in staging first.
- Deploy new `internal/governance` code; no external API change visible yet (handlers not registered).
- Verify existing approval flow regression: triage of `accepted_risk` still works with `RequiredApprovals=1`.
- Merge window: 1 PR per task, reviewed in order.

### Phase 2 — Approval API + Frontend (Epic A, Tasks A5–A6)

- Register routes in a single PR after Phase 1 is in production.
- Ship frontend approvals inbox + per-finding approval dialog.
- Enable `require_closure_approval` on a single internal test tenant first; run for ~1 week before generally available.
- Add a runbook for the "approvals stuck" scenario (e.g. approver left the company — document how to move the approval_request to `rejected` with `actor_type='system'`).

### Phase 3 — SLA (Epic B)

- Deploy `sla-worker` as a new container in docker-compose + production Helm charts.
- Keep SLA detection dual-run for 1 week (old inline path + new worker) with a `SLA_WORKER_SHADOW_MODE=true` env so the worker inserts but does not emit audit/notification. Compare detection results nightly.
- Flip shadow mode off after parity is confirmed; remove the old inline path in a follow-up PR.

### Phase 4 — Compliance (Epic C)

- Merge seed migration 025. It is re-runnable (`ON CONFLICT DO NOTHING`) so it is safe to re-apply against existing databases.
- Deploy API + UI. No feature flag needed — read-only views of built-in mappings are always safe.
- Tenant custom catalog creation guarded by `compliance.catalogs.write` permission; enable in internal tenant first.

### Phase 5 — Evidence export packs (Epic D)

- Deploy `export-worker` + API.
- Start with `kind='risk_evidence_pack'` only; gate `project_evidence_pack` behind a feature flag for 2 weeks (large scope exports more likely to trip size limits).
- Announce a "your evidence is available for 7 days" policy in the UI so tenants know to download promptly.
- Add Grafana dashboard for export-worker: jobs per day, P95 build time, failure rate, artifact size distribution.

### Monitoring + kill switches

- New metrics (Prometheus):
  - `governance_approvals_pending_total{org,kind}`
  - `governance_approval_decision_duration_seconds` (histogram)
  - `governance_sla_breaches_total{severity}`
  - `governance_sla_warnings_emitted_total{severity}`
  - `governance_export_jobs_duration_seconds` (histogram)
  - `governance_export_jobs_failed_total{reason}`
  - `compliance_mapping_cache_hit_ratio`
- Kill switches (env vars on each worker):
  - `SLA_WORKER_ENABLED=false` — stops breach detection without code revert.
  - `EXPORT_WORKER_ENABLED=false` — stops new exports; API returns 503 for `POST /exports`.
- Runbooks added to `docs/runbooks/`:
  - `governance-approval-stuck.md`
  - `sla-worker-backlog.md`
  - `export-worker-failure.md`

### Back-out

- All features are additive. Each PR is independently revertible.
- Migration 024 down file is complete; migration 025 down file truncates only NULL-org rows (so tenant customs are preserved even if we down-migrate).
- Data loss risk is limited to: in-flight approval decisions (rolled back on migration revert — rare), and in-progress export jobs (artifact orphans in MinIO — cleaned by retention-worker).

---

*End of plan.*
