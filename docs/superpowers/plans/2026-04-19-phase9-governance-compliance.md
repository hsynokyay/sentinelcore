# Phase 9 — Governance & Compliance Operations

**Date**: 2026-04-19
**Branch**: `phase9/governance-ops` (to cut from `main`)
**Prereqs**: Phase 6 (audit) + Phase 7 (tenancy) + Phase 8 (hardening) landed
**Owner**: Compliance officer + platform eng

---

## 1. Goal

Close the remaining governance gap that regulated FIs bring up on
every sales call:

- "Show me the approval trail for this closure"
- "Where's the SLA countdown?"
- "Which CWEs in this scan map to PCI DSS 6.5?"
- "Give me an evidence pack for auditor X on these 12 risks"

Out of scope: ticket-system integrations (Jira, ServiceNow),
notification channels beyond the existing webhook layer, policy-as-
code for third-party auditors.

---

## 2. Current state (survey, 2026-04-19)

**Already in place:**

- `governance.approval_requests` table — single pending→approved/
  rejected state, 7-day expiry, request_type + resource_type generic
- `governance.sla_violations` — severity + sla_days + deadline_at +
  escalated flag; records breaches only, not active countdowns
- `governance.finding_assignments` — due_at per finding; no SLA tie
- `internal/governance/workflow.go` — CreateApprovalRequest +
  ExpirePendingApprovals (cross-org sweep)
- `internal/governance/sla.go` — breach detection
- `internal/governance/transitions.go` — status transition validator
- `pkg/correlation/cwe.go` — CWE parent/category hierarchy
- `internal/audit/export/` — audit-log CSV/NDJSON export (Phase 6)
- Phase 6 audit emits every state change of risks, findings, etc.

**Gaps:**

- Approval: no **multi-approver / two-person** policy; no per-project
  sensitivity config; UI has no "my pending approvals" surface
- SLA: no **policy table** (hardcoded defaults); no **active
  countdown** API for list/detail views; no breach-projection — just
  post-hoc violation rows
- Compliance mapping: **zero** OWASP/PCI DSS mapping data in DB
- Evidence export pack: **does not exist** — auditors currently get
  JSON API dumps by hand

---

## 3. Feature model

Four features, each independently shippable. Each has a single-row
"principal" table + optional associated-rows tables; each emits
audit events via the existing Phase 6 emitter; each has a thin HTTP
surface in `internal/controlplane/api/`.

```
 ┌──────────────────────────────────────────────────────┐
 │ Approval workflow                                    │
 │   governance.approval_policies  (per project)        │
 │   governance.approval_requests  (extend existing)    │
 │   governance.approval_approvers (N-per-request)      │
 │                                                      │
 │   States:  pending → (approved|rejected|expired)     │
 │   Two-person: pending → reviewed → (approved|...)    │
 └──────────────────────────────────────────────────────┘
 ┌──────────────────────────────────────────────────────┐
 │ SLA tracking                                         │
 │   governance.sla_policies       (per org + project)  │
 │   governance.sla_deadlines      (per finding)        │
 │                                                      │
 │   Status: on_track | due_soon | overdue | resolved   │
 │   Active API: GET /findings?sla=overdue              │
 └──────────────────────────────────────────────────────┘
 ┌──────────────────────────────────────────────────────┐
 │ Compliance mapping                                   │
 │   compliance.frameworks         (owasp, pci_dss, …)  │
 │   compliance.controls           (per framework)      │
 │   compliance.cwe_control_map    (cwe_id → control)   │
 │   compliance.tenant_overrides   (per-org custom map) │
 └──────────────────────────────────────────────────────┘
 ┌──────────────────────────────────────────────────────┐
 │ Evidence export packs                                │
 │   governance.evidence_packs     (job rows)           │
 │                                                      │
 │   Output: .tar.zst containing:                       │
 │     manifest.json   (pack metadata)                  │
 │     risks/*.json    (risk + findings + remediation)  │
 │     timeline.csv    (audit events by resource)       │
 │     compliance.json (control mappings)               │
 └──────────────────────────────────────────────────────┘
```

---

## 4. Schema changes

Four new migrations pick up from Phase 8's 041.

### 4.1 Migration 042 — approval policy + multi-approver

```sql
BEGIN;

-- Per-project approval policy. One row per project; missing row =
-- "no approval needed".
CREATE TABLE governance.approval_policies (
    project_id          UUID PRIMARY KEY REFERENCES core.projects(id) ON DELETE CASCADE,
    org_id              UUID NOT NULL REFERENCES core.organizations(id),
    -- Which actions require approval. CHECK list kept narrow; extend
    -- via migration when a new approvable action lands.
    risk_closure        BOOLEAN NOT NULL DEFAULT false,
    finding_suppression BOOLEAN NOT NULL DEFAULT false,
    scan_target_change  BOOLEAN NOT NULL DEFAULT false,
    -- Approver count required before transition. 1 = single-approver
    -- (current behaviour); 2 = two-person rule. Requester cannot be
    -- an approver either way.
    required_approvers  INTEGER NOT NULL DEFAULT 1 CHECK (required_approvers BETWEEN 1 AND 5),
    -- Allowed approver roles. Subset of {owner, admin, security_engineer}.
    approver_roles      TEXT[] NOT NULL DEFAULT ARRAY['owner','admin'],
    auto_expire_hours   INTEGER NOT NULL DEFAULT 168, -- 7 days
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_approval_policies_org ON governance.approval_policies(org_id);

-- Per-request approver decisions. One row per approver who touches
-- the request. Primary key (request_id, approver_id) — same user
-- can't vote twice.
CREATE TABLE governance.approval_approvers (
    request_id   UUID NOT NULL REFERENCES governance.approval_requests(id) ON DELETE CASCADE,
    approver_id  UUID NOT NULL REFERENCES core.users(id),
    decision     TEXT NOT NULL CHECK (decision IN ('approve','reject')),
    reason       TEXT,
    decided_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (request_id, approver_id)
);
CREATE INDEX idx_approvers_request ON governance.approval_approvers(request_id);

-- RLS: inherit from approval_requests via request_id FK.
ALTER TABLE governance.approval_policies      ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.approval_approvers     ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON governance.approval_policies
    USING (org_id = current_setting('app.current_org_id')::uuid);

CREATE POLICY request_visibility ON governance.approval_approvers
    USING (request_id IN (
        SELECT id FROM governance.approval_requests
        WHERE org_id = current_setting('app.current_org_id')::uuid));

-- Extend approval_requests with an "approvals_received" counter so
-- the transition function can check quorum without a subquery.
ALTER TABLE governance.approval_requests
    ADD COLUMN IF NOT EXISTS approvals_received INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rejections_received INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS required_approvers INTEGER NOT NULL DEFAULT 1;

-- Append-only on decisions: once a row exists in approval_approvers
-- for a (request, approver), it cannot be rewritten. Prevents vote
-- flipping after the fact.
CREATE OR REPLACE FUNCTION governance.approvers_immutable()
RETURNS TRIGGER SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'approval_approvers is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER approvers_no_update BEFORE UPDATE ON governance.approval_approvers
    FOR EACH ROW EXECUTE FUNCTION governance.approvers_immutable();
CREATE TRIGGER approvers_no_delete BEFORE DELETE ON governance.approval_approvers
    FOR EACH ROW EXECUTE FUNCTION governance.approvers_immutable();

COMMIT;
```

### 4.2 Migration 043 — SLA policy + active deadlines

```sql
BEGIN;

-- Per (org, severity) SLA policy. Org-wide defaults; optional per-
-- project override via project_id NOT NULL UNIQUE.
CREATE TABLE governance.sla_policies (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES core.organizations(id),
    project_id       UUID REFERENCES core.projects(id),  -- NULL = org default
    severity         TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    remediation_days INTEGER NOT NULL CHECK (remediation_days > 0),
    warn_days_before INTEGER NOT NULL DEFAULT 7,
    escalate_after_hours INTEGER,  -- null = no auto-escalation
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, project_id, severity)
);
CREATE INDEX idx_sla_policies_org ON governance.sla_policies(org_id);

-- Per-finding active deadline. One row per finding at creation time.
-- On severity change, UPDATE the deadline; on resolve, set resolved_at.
CREATE TABLE governance.sla_deadlines (
    finding_id   UUID PRIMARY KEY REFERENCES findings.findings(id) ON DELETE CASCADE,
    org_id       UUID NOT NULL REFERENCES core.organizations(id),
    project_id   UUID NOT NULL REFERENCES core.projects(id),
    severity     TEXT NOT NULL,
    policy_id    UUID NOT NULL REFERENCES governance.sla_policies(id),
    deadline_at  TIMESTAMPTZ NOT NULL,
    warn_at      TIMESTAMPTZ NOT NULL,
    resolved_at  TIMESTAMPTZ,
    breached_at  TIMESTAMPTZ,  -- set by the sweep when deadline_at < now
    escalated_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_sla_deadlines_unresolved ON governance.sla_deadlines(deadline_at)
    WHERE resolved_at IS NULL;
CREATE INDEX idx_sla_deadlines_project ON governance.sla_deadlines(project_id);

-- Seed default org policy: critical 7d, high 30d, medium 90d, low 180d.
-- Applied by retention-worker on org create (not here — data migration
-- would need to walk every org).

-- RLS
ALTER TABLE governance.sla_policies   ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance.sla_deadlines  ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_isolation ON governance.sla_policies
    USING (org_id = current_setting('app.current_org_id')::uuid);
CREATE POLICY org_isolation ON governance.sla_deadlines
    USING (org_id = current_setting('app.current_org_id')::uuid);

COMMIT;
```

### 4.3 Migration 044 — compliance framework catalog + CWE map

```sql
BEGIN;

CREATE SCHEMA IF NOT EXISTS compliance;

-- Framework catalog: owasp_top10_2021, pci_dss_4_0, nist_csf_1_1, …
CREATE TABLE compliance.frameworks (
    id          TEXT PRIMARY KEY,          -- stable slug (e.g. 'owasp_top10_2021')
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    url         TEXT,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Control catalog: one row per individual control within a framework.
CREATE TABLE compliance.controls (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id  TEXT NOT NULL REFERENCES compliance.frameworks(id),
    control_ref   TEXT NOT NULL,           -- 'A01:2021', '6.5.1', 'PR.AC-1'
    title         TEXT NOT NULL,
    description   TEXT,
    parent_ref    TEXT,                    -- for hierarchies (PCI sub-requirements)
    UNIQUE (framework_id, control_ref)
);
CREATE INDEX idx_controls_framework ON compliance.controls(framework_id);

-- CWE → control map. M-to-N via rows.
CREATE TABLE compliance.cwe_control_map (
    cwe_id     INTEGER NOT NULL,
    control_id UUID NOT NULL REFERENCES compliance.controls(id),
    confidence TEXT NOT NULL DEFAULT 'authoritative' CHECK (confidence IN ('authoritative','inferred','tenant')),
    source     TEXT,  -- 'MITRE', 'OWASP-2021-map', 'custom', ...
    PRIMARY KEY (cwe_id, control_id)
);
CREATE INDEX idx_cwe_map_cwe ON compliance.cwe_control_map(cwe_id);

-- Per-tenant custom mappings layered on top of the global map.
-- Org can add OR remove a mapping for its own tenancy; scope column
-- says which.
CREATE TABLE compliance.tenant_overrides (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES core.organizations(id),
    cwe_id     INTEGER NOT NULL,
    control_id UUID NOT NULL REFERENCES compliance.controls(id),
    action     TEXT NOT NULL CHECK (action IN ('add','hide')),
    note       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID NOT NULL REFERENCES core.users(id),
    UNIQUE (org_id, cwe_id, control_id, action)
);
CREATE INDEX idx_tenant_overrides_org ON compliance.tenant_overrides(org_id);

-- Catalog tables are globally readable; overrides are per-tenant.
ALTER TABLE compliance.tenant_overrides ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON compliance.tenant_overrides
    USING (org_id = current_setting('app.current_org_id')::uuid);

-- Seed frameworks + the OWASP Top 10 2021 control set. PCI DSS and
-- NIST seeded separately (migrations 045+).

INSERT INTO compliance.frameworks (id, name, version, url) VALUES
    ('owasp_top10_2021', 'OWASP Top 10', '2021', 'https://owasp.org/Top10/'),
    ('pci_dss_4_0',      'PCI DSS',       '4.0',  'https://www.pcisecuritystandards.org/'),
    ('nist_csf_2_0',     'NIST CSF',      '2.0',  'https://www.nist.gov/cyberframework'),
    ('iso_27001_2022',   'ISO/IEC 27001', '2022', 'https://www.iso.org/standard/27001')
ON CONFLICT DO NOTHING;

INSERT INTO compliance.controls (framework_id, control_ref, title) VALUES
    ('owasp_top10_2021', 'A01:2021', 'Broken Access Control'),
    ('owasp_top10_2021', 'A02:2021', 'Cryptographic Failures'),
    ('owasp_top10_2021', 'A03:2021', 'Injection'),
    ('owasp_top10_2021', 'A04:2021', 'Insecure Design'),
    ('owasp_top10_2021', 'A05:2021', 'Security Misconfiguration'),
    ('owasp_top10_2021', 'A06:2021', 'Vulnerable and Outdated Components'),
    ('owasp_top10_2021', 'A07:2021', 'Identification and Authentication Failures'),
    ('owasp_top10_2021', 'A08:2021', 'Software and Data Integrity Failures'),
    ('owasp_top10_2021', 'A09:2021', 'Security Logging and Monitoring Failures'),
    ('owasp_top10_2021', 'A10:2021', 'Server-Side Request Forgery')
ON CONFLICT DO NOTHING;

COMMIT;
```

Migration 045 seeds the CWE→OWASP/PCI map (data-only, ~500 rows).
Generated offline from MITRE CWE + OWASP authoritative spreadsheet;
kept as a .sql file so the data is reviewable in PRs.

### 4.4 Migration 046 — evidence pack jobs

```sql
BEGIN;

CREATE TABLE governance.evidence_packs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES core.organizations(id),
    requested_by  UUID NOT NULL REFERENCES core.users(id),
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Scope: "risks":[...] or "project_id":... or "scan_id":...
    scope         JSONB NOT NULL,
    format        TEXT NOT NULL CHECK (format IN ('tar_zst','zip')),
    include_evidence_bytes BOOLEAN NOT NULL DEFAULT false,  -- true = raw HAR/DOM blobs
    status        TEXT NOT NULL DEFAULT 'queued'
                      CHECK (status IN ('queued','running','succeeded','failed','expired')),
    started_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ,
    error_message TEXT,
    -- Output artifact reference. Local filesystem path for the MVP;
    -- MinIO s3:// URL once the async pipeline lands (Phase 10).
    artifact_path TEXT,
    artifact_sha256 TEXT,
    bytes         BIGINT,
    expires_at    TIMESTAMPTZ NOT NULL  -- e.g. now() + 30 days
);
CREATE INDEX idx_evidence_packs_org ON governance.evidence_packs(org_id);
CREATE INDEX idx_evidence_packs_expiring ON governance.evidence_packs(expires_at)
    WHERE status = 'succeeded';

ALTER TABLE governance.evidence_packs ENABLE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON governance.evidence_packs
    USING (org_id = current_setting('app.current_org_id')::uuid);

-- Column lockdown (Phase 7 §5.4 pattern): id / org_id / requested_by
-- / requested_at / scope / format immutable once written.
CREATE OR REPLACE FUNCTION governance.evidence_packs_restrict()
RETURNS TRIGGER SECURITY DEFINER SET search_path = pg_catalog AS $$
BEGIN
    IF NEW.id           IS DISTINCT FROM OLD.id           THEN RAISE EXCEPTION 'evidence_packs.id immutable'           USING ERRCODE='insufficient_privilege'; END IF;
    IF NEW.org_id       IS DISTINCT FROM OLD.org_id       THEN RAISE EXCEPTION 'evidence_packs.org_id immutable'       USING ERRCODE='insufficient_privilege'; END IF;
    IF NEW.requested_by IS DISTINCT FROM OLD.requested_by THEN RAISE EXCEPTION 'evidence_packs.requested_by immutable' USING ERRCODE='insufficient_privilege'; END IF;
    IF NEW.requested_at IS DISTINCT FROM OLD.requested_at THEN RAISE EXCEPTION 'evidence_packs.requested_at immutable' USING ERRCODE='insufficient_privilege'; END IF;
    IF NEW.scope        IS DISTINCT FROM OLD.scope        THEN RAISE EXCEPTION 'evidence_packs.scope immutable'        USING ERRCODE='insufficient_privilege'; END IF;
    IF NEW.format       IS DISTINCT FROM OLD.format       THEN RAISE EXCEPTION 'evidence_packs.format immutable'       USING ERRCODE='insufficient_privilege'; END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER evidence_packs_immutable_cols BEFORE UPDATE ON governance.evidence_packs
    FOR EACH ROW EXECUTE FUNCTION governance.evidence_packs_restrict();

COMMIT;
```

---

## 5. Workflow / state models

### 5.1 Approval state machine

```
                   ┌──────────────────────────────────────┐
                   │                                      │
   Create ──► pending ──► reviewed ──► approved           │
                  │           │                           │
                  │           └──► rejected ──────────────┘
                  │
                  └──► expired   (auto, at expires_at)
```

- `reviewed` state only exists when `required_approvers >= 2`.
  The first approver transitions pending→reviewed; the second (and
  different) approver transitions reviewed→approved.
- Any approver's `reject` decision collapses the state to
  `rejected` immediately, regardless of how many others approved.
- `expired` is terminal; a fresh request must be created.

Invariant: `approvals_received >= required_approvers AND
rejections_received = 0` ⇔ status=approved.

Transition rules enforced in `pkg/governance/approval_fsm.go`:
- Requester cannot approve their own request.
- Approver role must be in the policy's `approver_roles` array.
- Same user cannot vote twice (PK on approval_approvers).

### 5.2 SLA state model

Derived, not stored explicitly on finding:

```
  status(finding) =
    if resolved_at != NULL         -> "resolved"
    if breached_at != NULL         -> "overdue"
    if now >= warn_at              -> "due_soon"
    else                           -> "on_track"
```

A nightly `cmd/sla-sweep` worker:
- Sets `breached_at = now()` on rows where `now >= deadline_at` and `breached_at IS NULL`.
- Triggers escalation (emit `sla.breached` audit + notification) if the policy has `escalate_after_hours` and enough time has passed since the breach.
- Sets `resolved_at` on rows where the underlying finding is now closed.

### 5.3 Evidence pack lifecycle

```
  queued ── (pack-builder picks up) ──► running
                                          │
                                          ├──► succeeded (artifact_path set, sha256 set)
                                          └──► failed    (error_message set)

  succeeded ── after expires_at ──► expired  (artifact deleted, row kept for audit)
```

`cmd/evidence-builder` worker polls `status='queued'` every 15s,
takes an advisory lock on the row, builds the pack, commits.

---

## 6. Compliance mapping — lookup model

Two tiers of resolution for "what controls does this finding touch?":

1. **Global map** (`compliance.cwe_control_map`) — authoritative
   CWE↔control rows shipped in migration 045. ~500 rows.
2. **Tenant overrides** (`compliance.tenant_overrides`) — per-org
   add/hide rows. Applied at query time:

```sql
-- Resolve controls for a CWE in one tenant's view.
WITH base AS (
    SELECT c.control_id, 'authoritative'::text AS source
      FROM compliance.cwe_control_map c
     WHERE c.cwe_id = $1
),
added AS (
    SELECT t.control_id, 'tenant'::text AS source
      FROM compliance.tenant_overrides t
     WHERE t.cwe_id = $1 AND t.action = 'add'
),
hidden AS (
    SELECT control_id FROM compliance.tenant_overrides
     WHERE cwe_id = $1 AND action = 'hide'
)
SELECT b.control_id, b.source FROM base b
    WHERE b.control_id NOT IN (SELECT control_id FROM hidden)
UNION
SELECT a.control_id, a.source FROM added a;
```

### 6.1 UI surfaces

- **Finding detail** — a "Compliance" section listing mapped controls
  grouped by framework. Click-through to the framework's public URL.
- **Risk detail** — aggregated: union of mapped controls across all
  contributing findings.
- **Compliance page** (`/compliance`) — heatmap: rows = open findings
  bucketed by control, columns = frameworks. Quick view of "where are
  we bleeding against PCI DSS?"
- **Settings → Compliance** (owner/admin only) — per-tenant add/hide
  overrides UI. Changes emit audit events.

---

## 7. Evidence export pack design

### 7.1 Pack contents

```
pack-<id>.tar.zst
├── manifest.json
│   { "id", "org_id", "requested_by", "requested_at",
│     "scope", "risks_included": [...], "findings_count",
│     "format_version": "1" }
├── risks/
│   ├── <risk_id>.json            # full risk + members + score
│   └── <risk_id>.md              # human-readable remediation guide
├── findings/
│   ├── <finding_id>.json         # finding record + taint paths
│   └── <finding_id>-evidence/    # (if include_evidence_bytes=true)
│       ├── request.har
│       └── response.dom.html.zst
├── timeline.csv                  # audit events, chronological
├── compliance.json               # control mappings per risk/finding
├── sbom.json                     # optional; CycloneDX if targets are SBOM-scanned
└── SIGNATURE                     # detached HMAC-SHA256 over tarball bytes
```

### 7.2 Generation strategy

```go
// cmd/evidence-builder/main.go
//
//   1. Acquire advisory lock on pack row (pg_try_advisory_xact_lock).
//   2. Read scope → resolve {risks, findings} under tenant.TxUser.
//   3. For each risk:
//      - emit risks/<id>.json from risk.clusters + cluster_members
//      - emit risks/<id>.md via pkg/export/risk_markdown.go
//   4. For each finding:
//      - emit findings/<id>.json from findings.findings
//      - if include_evidence_bytes: fetch HAR/DOM from artifacts vol
//   5. Query audit.audit_log filtered by resource_id IN (...); emit timeline.csv.
//   6. Resolve compliance mappings; emit compliance.json.
//   7. Stream everything through tar + zstd.NewWriter straight to file.
//   8. Compute sha256(tarball) → HMAC with pack-signing key → SIGNATURE.
//   9. UPDATE evidence_packs SET status='succeeded', artifact_path, artifact_sha256.
//
// Pack-signing key: a new entry in auth.aes_keys with purpose='evidence_pack'.
// Keeps sig key lifecycle aligned with Phase 7 rotation.
```

### 7.3 Delivery

Operator downloads via `GET /api/v1/evidence-packs/{id}/download`.
The endpoint:
- Requires `evidence_packs.read` capability (gated by RBAC).
- Streams the file from `artifact_path` with
  `Content-Disposition: attachment; filename="evidence-pack-<id>.tar.zst"`.
- Emits `evidence_pack.downloaded` audit with requester + size.

### 7.4 Format alternatives

MVP: `tar.zst` only. Phase 10 can add:
- **zip** for Windows auditors who can't open `.zst`.
- **GPG-encrypted** variant for external auditor delivery (reuses the
  existing `audit.export_jobs.encrypt_gpg` path from Phase 6).

---

## 8. Implementation plan — three waves

### Wave 1 — Approval workflow + SLA policy (week 1–2)

Files:

```
migrations/042_approval_policy.up.sql / .down.sql
migrations/043_sla_policies.up.sql / .down.sql
pkg/governance/approval_fsm.go          # state machine + transition validator
pkg/governance/approval_fsm_test.go
pkg/governance/sla_deadline.go          # per-finding deadline calculator
pkg/governance/sla_deadline_test.go
internal/controlplane/api/approvals.go  # CRUD + /approve + /reject
internal/controlplane/api/sla_policies.go
internal/controlplane/api/sla.go        # list findings with SLA status
cmd/sla-sweep/main.go                   # nightly breach + resolve sweep
deploy/systemd/sc-sla-sweep.{service,timer}
web/app/(app)/approvals/page.tsx        # "my pending approvals"
web/app/(app)/settings/sla/page.tsx     # SLA policy UI
docs/approval-workflow.md
docs/sla-policy.md
```

Changes:
1. 042 + 043 migrations land; tenant-local state invariant kept.
2. `pkg/governance/approval_fsm.go` — pure state machine; pool-free,
   unit-testable. Exports `Transition(curr, event) (next, error)`.
3. `pkg/governance/sla_deadline.go` — compute deadline + warn_at from
   policy + severity + created_at.
4. Risk close handler (internal/controlplane/api/risks.go) consults
   approval policy; if required_approvers >= 1 on this project,
   status flips to "pending_closure" and an approval request is
   created instead of directly closing.
5. `cmd/sla-sweep` runs every 15 min via systemd timer; emits audit
   events for each breach + resolution.

Revert path: migrations 042 + 043 down; workflow reverts to direct
close.

### Wave 2 — Compliance mapping (week 2–3)

Files:

```
migrations/044_compliance_catalog.up.sql / .down.sql
migrations/045_cwe_control_map.up.sql           # data-only, ~500 rows
pkg/compliance/
  resolver.go          # CWE → controls (with tenant overrides)
  resolver_test.go
  loader.go            # package seed files into migration
internal/controlplane/api/compliance.go
web/app/(app)/compliance/page.tsx               # heatmap
web/app/(app)/settings/compliance/page.tsx      # overrides UI
docs/compliance-mapping.md
scripts/generate-cwe-owasp-map.py               # regenerates migration 045
```

Changes:
1. 044 migration lands with framework catalog (OWASP, PCI, NIST, ISO
   seeded; controls only for OWASP in the initial migration).
2. 045 seeds the CWE → control map from a reviewed SQL file
   generated offline from MITRE's CWE + OWASP's authoritative map.
3. `pkg/compliance/resolver.go` — single query + tenant overrides
   layered; cached in a 5-minute in-memory map per org (like the
   RBAC cache).
4. Finding + Risk detail API adds `"compliance":[...]` array to
   their response shape. Zero schema impact on existing clients —
   new field is additive.
5. New `/api/v1/compliance/controls` listing endpoint for the UI
   heatmap + dropdowns.

Revert path: migrations 044 + 045 down; API responses lose the
`compliance` field (clients tolerate absent fields).

### Wave 3 — Evidence export packs (week 3–4)

Files:

```
migrations/046_evidence_packs.up.sql / .down.sql
pkg/evidence/
  builder.go           # walks scope → writes tar.zst
  builder_test.go
  manifest.go
  sign.go              # HMAC signature over tarball
cmd/evidence-builder/main.go
deploy/docker-compose/docker-compose.yml       # new service entry
internal/controlplane/api/evidence_packs.go    # POST /request, GET /{id}, /{id}/download
web/app/(app)/evidence-packs/page.tsx          # list + request UI
web/app/(app)/risks/[id]/export/page.tsx       # one-click "export this risk"
docs/evidence-pack-format.md
```

Changes:
1. 046 migration lands; RLS + column lockdown on evidence_packs.
2. `pkg/evidence/builder.go` — deterministic pack layout; tests
   verify every file in the manifest matches its bytes + mtime.
3. `cmd/evidence-builder` worker service added to compose; runs as
   sentinelcore_worker role post-Phase-7 role split.
4. Pack download stream gates on `evidence_packs.read` + emits
   audit event with the pack id + bytes.
5. Retention worker (Phase 6 existing) sweeps packs past
   `expires_at` — deletes artifact file, keeps DB row for audit.

Revert path: 046 down; /evidence-packs routes return 404.

---

## 9. Verification checklist

### Wave 1

- [ ] POST /approvals creates a pending request; audit event emitted.
- [ ] POST /approvals/{id}/approve by REQUESTER → 403.
- [ ] POST /approvals/{id}/approve by non-approver role → 403.
- [ ] Two-person policy: 1 approve → status=reviewed; 2nd (different user) approve → status=approved.
- [ ] Any reject → status=rejected regardless of prior approvals.
- [ ] Expired sweep: after 7 days, status=expired; cannot be approved.
- [ ] Attempt UPDATE governance.approval_approvers → rejected (append-only trigger).
- [ ] SLA policy CRUD: create critical=7d, high=30d; GET list returns both.
- [ ] New finding at severity=critical → sla_deadlines row with deadline_at = created + 7d.
- [ ] SLA sweep: past-deadline row gets breached_at set; audit event emitted.
- [ ] GET /findings?sla=overdue returns only breached rows.

### Wave 2

- [ ] GET /compliance/frameworks returns 4 frameworks seeded.
- [ ] GET /compliance/controls?framework=owasp_top10_2021 returns 10 controls.
- [ ] CWE 89 (SQLi) → A03:2021 Injection in the cwe_control_map.
- [ ] GET /findings/{id} response includes `compliance:[{framework, control_ref, title},...]`.
- [ ] Tenant override add: hides A01 → subsequent /findings/{id} does not list A01.
- [ ] /compliance heatmap page renders with findings bucketed per control.

### Wave 3

- [ ] POST /evidence-packs with scope={risks:[id1,id2]} → row status=queued.
- [ ] evidence-builder worker picks it up within 30s; transitions to running then succeeded.
- [ ] GET /evidence-packs/{id} returns status=succeeded + artifact_sha256.
- [ ] GET /evidence-packs/{id}/download streams tar.zst with Content-Disposition attachment.
- [ ] Untar → verify manifest.json, risks/, findings/, timeline.csv, compliance.json, SIGNATURE all present.
- [ ] SIGNATURE verifies against the evidence-pack HMAC key.
- [ ] UPDATE on evidence_packs.org_id → rejected (trigger).
- [ ] After expires_at, retention worker deletes artifact file; DB row intact.

---

## 10. Pitfalls + rollout risks

1. **Don't let approval close a risk before the second approver votes.**
   Quorum must be ≥ `required_approvers` AND `rejections_received =
   0`. Bug here = auditors see single-person closure on "two-person"
   projects.
2. **Don't let a requester approve their own request** — enforce at
   the FSM, not only the UI. UI gates are bypassable.
3. **Don't forget to backfill sla_deadlines for existing findings.**
   Migration 043 is structural; a one-shot SQL script in
   `scripts/backfill-sla-deadlines.sql` applies the org default to
   every unresolved finding. Run once, after deploy.
4. **Don't hardcode SLA defaults in Go.** Org can change them; the
   code MUST read from governance.sla_policies. Default seed belongs
   in a bootstrap migration, not in code.
5. **Don't ship compliance mappings without sourcing.** Every row in
   cwe_control_map MUST have `source` populated (MITRE-CWE,
   OWASP-2021-map, etc). Auditors ask where the map came from.
6. **Don't make evidence packs synchronous over HTTP.** A 10-risk
   pack takes ~30s; a 500-risk pack is 10 min. Always queue + worker.
7. **Don't let evidence packs spill PII into the signed tarball.**
   Reuse the existing audit redactor (Phase 6) on any `details`
   jsonb before writing.
8. **Don't store the pack-signing key in env.** Put it in auth.aes_keys
   like every other key; rotate it on the same cadence.
9. **Don't return evidence pack artifact_path to the API.** Internal
   filesystem path only; download via the authenticated endpoint.
10. **Don't emit approval state changes as single audit events.** Emit
    one per transition (pending→reviewed, reviewed→approved, reject,
    expired) so the auditor can see the full chain, not just the
    terminal state.

### Rollout risks

| Risk | Mitigation |
|---|---|
| Existing risk-close flow breaks when policy=required | Feature flag `SC_APPROVAL_POLICY_ENFORCED=false` by default; flip per tenant as they opt in |
| SLA sweep paints every finding as breached on day 1 | Migration 043 sets `created_at = finding.created_at`; only findings NEWER than deploy get active deadlines for 30 days, then backfill sweeps the rest |
| Compliance map rows are wrong (e.g. Turkish mapping) | Data migration 045 is reviewable; every row has `source`; tenant overrides provide per-customer escape hatch |
| Evidence pack overwhelms worker disk | `expires_at = now()+30d` + retention sweep; `bytes` recorded for quota visibility |

---

## 11. Rollout plan

### Phase 9 Wave 1 (week 1–2)

- [ ] Migrations 042 + 043 applied to staging.
- [ ] `cmd/sla-sweep` deployed as systemd timer; observe for 1 week.
- [ ] Approval policy opt-in per tenant via settings UI.
- [ ] Production rollout: flag SC_APPROVAL_POLICY_ENFORCED=true
      per customer on request.

### Phase 9 Wave 2 (week 2–3)

- [ ] Migrations 044 + 045 applied.
- [ ] Finding + Risk API responses include compliance section
      (additive; clients tolerate absent fields).
- [ ] /compliance heatmap goes live in UI.
- [ ] Tenant overrides opt-in UI.

### Phase 9 Wave 3 (week 3–4)

- [ ] Migration 046 applied.
- [ ] `cmd/evidence-builder` worker lands in compose.
- [ ] One-click "Export evidence pack for this risk" in UI.
- [ ] First real pack generated + downloaded + signature verified in
      a staging tenant.

### Exit criteria

- Approval flow: one regulated-FI customer runs a full two-person
  closure end-to-end; audit trail shows both approvers.
- SLA: a staging finding at severity=critical gets deadline_at
  correctly, gets breached_at set after 7 days, gets resolved_at set
  when closed.
- Compliance: external auditor signs off on a randomly-sampled CWE
  → control mapping (provide 20 samples, they check against MITRE).
- Evidence pack: signed tarball passes internal integrity check AND
  external customer's vetting.

---

## Appendix A — File manifest

```
migrations/
  042_approval_policy.up.sql / .down.sql
  043_sla_policies.up.sql / .down.sql
  044_compliance_catalog.up.sql / .down.sql
  045_cwe_control_map.up.sql                  # data-only
  046_evidence_packs.up.sql / .down.sql

pkg/governance/
  approval_fsm.go, approval_fsm_test.go
  sla_deadline.go, sla_deadline_test.go
pkg/compliance/
  resolver.go, resolver_test.go
  loader.go
pkg/evidence/
  builder.go, builder_test.go
  manifest.go
  sign.go

internal/controlplane/api/
  approvals.go            # CRUD + approve + reject
  sla_policies.go
  sla.go                  # list findings by SLA status
  compliance.go
  evidence_packs.go

cmd/
  sla-sweep/main.go
  evidence-builder/main.go

deploy/systemd/
  sc-sla-sweep.service / .timer
deploy/docker-compose/
  docker-compose.yml      # adds evidence-builder service

web/app/(app)/
  approvals/page.tsx
  compliance/page.tsx
  evidence-packs/page.tsx
  risks/[id]/export/page.tsx
  settings/sla/page.tsx
  settings/compliance/page.tsx

scripts/
  backfill-sla-deadlines.sql
  generate-cwe-owasp-map.py

docs/
  approval-workflow.md
  sla-policy.md
  compliance-mapping.md
  evidence-pack-format.md
  governance-operator-runbook.md
```

## Appendix B — Intentionally deferred

- **Ticket-system integrations** (Jira, ServiceNow): bidirectional
  sync goes into Phase 10; one-way export via webhook Phase 6
  already handles the simple cases.
- **Custom workflows beyond two-person**: 3+ approver chains, serial
  vs parallel approval, delegation — all expressible with current
  schema but UI gets complicated; defer to market demand.
- **Control mapping for every framework**: MVP ships OWASP Top 10
  complete and ~30 key PCI DSS sub-requirements. NIST CSF + ISO
  27001 get stub rows + the catalog entry so the UI can render;
  fully seeding either is a whole sub-project.
- **Continuous compliance posture dashboard**: "you're at 87% of PCI
  6.5" style scoring. Requires defining what "covered" means;
  Phase 10 + compliance consulting engagement.
- **Tenant-specific framework additions**: Customer X has its own
  "Internal Policy 2024". Add by tenant_overrides or a new
  `tenant_frameworks` table; the latter if the demand is wide.
