# SentinelCore Phase 3 — Correlation Engine

**Version:** 0.1.0
**Date:** 2026-03-19
**Status:** DESIGN

---

## 1. Correlation Architecture

### Purpose

The correlation engine transforms raw scanner output — SAST findings, DAST observations, and vulnerability intelligence — into unified, high-confidence security findings. A SAST finding reporting SQL injection in `userDao.go:47` and a DAST finding confirming SQL injection at `GET /api/users?id=` are separate data points; the correlation engine links them into a single confirmed finding with elevated confidence and risk score.

### Architecture Position

```
┌─────────────┐    ┌─────────────┐    ┌──────────────┐
│ SAST Worker │    │ DAST Worker │    │ Vuln Intel   │
│scan.results │    │scan.results │    │   Service    │
│   .sast     │    │   .dast     │    │              │
└──────┬──────┘    └──────┬──────┘    └──────┬───────┘
       │                  │                   │
       ▼                  ▼                   ▼
  ┌────────────────────────────────────────────────┐
  │              NATS JetStream                     │
  │  scan.results.sast  │  scan.results.dast       │
  │  findings.correlated │ findings.deduplicated    │
  └───────────────────────┬────────────────────────┘
                          │
                ┌─────────▼──────────┐
                │ Correlation Engine │
                │                    │
                │  ┌──────────────┐  │
                │  │  Ingester    │  │  ← consumes raw findings
                │  └──────┬───────┘  │
                │         ▼          │
                │  ┌──────────────┐  │
                │  │  Deduplicator│  │  ← fingerprint-based dedup
                │  └──────┬───────┘  │
                │         ▼          │
                │  ┌──────────────┐  │
                │  │  Correlator  │  │  ← 4-axis matching
                │  └──────┬───────┘  │
                │         ▼          │
                │  ┌──────────────┐  │
                │  │ Risk Scorer  │  │  ← composite risk formula
                │  └──────┬───────┘  │
                │         ▼          │
                │  ┌──────────────┐  │
                │  │  Publisher   │  │  ← emit correlated findings
                │  └──────────────┘  │
                └────────────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │  PostgreSQL  │
                   │  findings.*  │
                   └──────────────┘
```

### Processing Model

**Event-driven, scan-scoped batches.** The engine does not run continuously against the full finding corpus. Instead:

1. It subscribes to `scan.status.update` and triggers when a scan job transitions to `completed`
2. It loads all findings from that scan job
3. It cross-references against existing findings in the same project (from prior scans)
4. It cross-references SAST↔DAST findings if both types exist for the project
5. It enriches findings with vulnerability intelligence (CWE→CVE mapping, EPSS scores)
6. It publishes correlated results and updates the database

This batch-per-scan model avoids the combinatorial explosion of correlating every finding against every other finding in real time.

---

## 2. Matching Heuristics

### 2.1 Deduplication (same-type findings)

Before cross-type correlation, identical findings across scans are deduplicated.

```
fingerprint = SHA-256(
  project_id ‖ finding_type ‖ cwe_id
  ‖ file_path ‖ line_start              (SAST)
  ‖ url ‖ http_method ‖ parameter       (DAST)
  ‖ dependency_name ‖ cve_id            (SCA)
)
```

**Rules:**
- Same fingerprint, same project → UPDATE `last_seen_at`, increment `scan_count`
- Same fingerprint, different scan → mark as persistent (not regressed)
- Previously-seen fingerprint absent from new scan → mark as potentially resolved (after N consecutive misses)
- New fingerprint → INSERT with `status = 'new'`

### 2.2 Cross-Type Correlation (SAST ↔ DAST)

The core algorithm: for each DAST finding, search for matching SAST findings in the same project. Score each candidate pair across four axes.

#### Axis 1: CWE Match (weight 0.40)

| Condition | Score |
|---|---|
| Exact CWE ID match | 1.0 |
| Parent CWE match (e.g., CWE-89 child of CWE-943) | 0.5 |
| Same CWE category (e.g., both Injection) | 0.3 |
| No CWE relationship | 0.0 |

The engine loads the MITRE CWE hierarchy at startup and builds a parent lookup map. The hierarchy is static per CWE version (updated with vuln intel feeds).

#### Axis 2: Parameter Match (weight 0.25)

DAST findings have a `parameter` field (e.g., `id`). SAST findings have `file_path` and `code_snippet`. The engine extracts parameter references from SAST code snippets using heuristics:

| Condition | Score |
|---|---|
| DAST parameter appears literally in SAST code snippet | 1.0 |
| Normalized match (snake_case↔camelCase, common aliases like `id`↔`userId`) | 0.7 |
| DAST URL path segment matches SAST file path component (e.g., `/users/` ↔ `userDao.go`) | 0.4 |
| No match | 0.0 |

#### Axis 3: Endpoint Match (weight 0.20)

Maps DAST URLs to SAST file paths using route-to-handler mapping:

| Condition | Score |
|---|---|
| Explicit route annotation found in SAST code mapping to DAST URL | 1.0 |
| Path segments match file/package names (≥60% overlap) | 0.6 |
| Same top-level resource (e.g., `/api/users` ↔ `internal/users/`) | 0.4 |
| No match | 0.0 |

The route mapping is best-effort. MVP uses heuristic path-segment matching; Phase 4 adds framework-specific route parsing (Go chi/mux, Express, Spring).

#### Axis 4: Temporal Proximity (weight 0.15)

| Condition | Score |
|---|---|
| Same scan cycle (SAST and DAST triggered together) | 1.0 |
| Within 24 hours | 0.8 |
| Within 7 days | 0.5 |
| Older than 7 days | 0.2 |

### 2.3 Vulnerability Intelligence Enrichment

After correlation, findings are enriched with vulnerability intelligence:

- **CWE → CVE mapping**: if a finding's CWE has known CVEs in `vuln_intel.vulnerabilities`, link them
- **EPSS scoring**: attach exploit probability score from EPSS data
- **KEV check**: flag findings whose CWE maps to actively-exploited CVEs (CISA KEV)
- **Exploit availability**: check if public exploits exist for related CVEs

This enrichment does not affect the correlation score but feeds into the risk score.

---

## 3. Data Model

### 3.1 New Tables

```sql
-- Correlation groups link related findings across types
CREATE TABLE findings.correlation_groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES core.projects(id),
    primary_finding_id UUID NOT NULL REFERENCES findings.findings(id),
    correlation_score  NUMERIC(4,3) NOT NULL,  -- 0.000 to 1.000
    confidence      VARCHAR(10) NOT NULL,      -- high, medium, low
    risk_score      NUMERIC(4,2) NOT NULL,     -- 0.00 to 10.00
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Members of a correlation group
CREATE TABLE findings.correlation_members (
    group_id        UUID NOT NULL REFERENCES findings.correlation_groups(id) ON DELETE CASCADE,
    finding_id      UUID NOT NULL REFERENCES findings.findings(id),
    axis_scores     JSONB NOT NULL,  -- {"cwe": 1.0, "parameter": 0.7, "endpoint": 0.6, "temporal": 1.0}
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, finding_id)
);

-- CWE hierarchy for parent/child matching
CREATE TABLE findings.cwe_hierarchy (
    cwe_id          INTEGER PRIMARY KEY,
    parent_id       INTEGER,
    category        VARCHAR(100),
    name            TEXT NOT NULL,
    description     TEXT
);

-- Correlation run history for auditability
CREATE TABLE findings.correlation_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_job_id     UUID NOT NULL,
    project_id      UUID NOT NULL,
    input_findings  INTEGER NOT NULL,
    deduplicated    INTEGER NOT NULL,
    correlated      INTEGER NOT NULL,
    new_groups      INTEGER NOT NULL,
    updated_groups  INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 3.2 Schema Changes to Existing Tables

```sql
-- Add enrichment fields to findings
ALTER TABLE findings.findings
    ADD COLUMN IF NOT EXISTS related_cve_ids TEXT[],
    ADD COLUMN IF NOT EXISTS epss_score NUMERIC(5,4),
    ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS actively_exploited BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS correlation_group_id UUID;
```

### 3.3 Go Types

```go
// CorrelationGroup links related findings across scan types.
type CorrelationGroup struct {
    ID               string
    ProjectID        string
    PrimaryFindingID string
    Score            float64
    Confidence       string  // high, medium, low
    RiskScore        float64
    Members          []CorrelationMember
    Status           string
}

// CorrelationMember is a finding within a correlation group.
type CorrelationMember struct {
    FindingID  string
    AxisScores AxisScores
}

// AxisScores captures the per-axis match quality.
type AxisScores struct {
    CWE       float64 `json:"cwe"`
    Parameter float64 `json:"parameter"`
    Endpoint  float64 `json:"endpoint"`
    Temporal  float64 `json:"temporal"`
}

// CorrelationResult is the output of a single correlation run.
type CorrelationResult struct {
    ScanJobID      string
    ProjectID      string
    InputFindings  int
    Deduplicated   int
    NewGroups      []CorrelationGroup
    UpdatedGroups  []CorrelationGroup
    Duration       time.Duration
}
```

---

## 4. Scoring System

### 4.1 Correlation Score

```
correlation_score = (0.40 × cwe_score) + (0.25 × param_score) + (0.20 × endpoint_score) + (0.15 × temporal_score)
```

Range: 0.0 to 1.0.

### 4.2 Confidence Thresholds

| Score | Confidence | Action |
|---|---|---|
| ≥ 0.80 | HIGH | Auto-link, no review needed |
| ≥ 0.50 | MEDIUM | Auto-link, flag for review |
| ≥ 0.30 | LOW | Suggest as potential link |
| < 0.30 | — | No correlation |

Thresholds are configurable per project via `config_override` JSONB on scan_jobs.

### 4.3 Composite Risk Score

```
risk = min(
    base_severity
    × exploit_multiplier
    × asset_criticality
    × correlation_boost,
    10.0
)
```

Where:
- `base_severity`: CVSS score if available, else severity→numeric mapping (critical=9.5, high=7.5, medium=5.0, low=2.5, info=0.5)
- `exploit_multiplier`: no_known=1.0, exploit_exists=1.3, actively_exploited=1.6
- `asset_criticality`: from project metadata (critical=1.4, high=1.2, medium=1.0, low=0.8)
- `correlation_boost`: HIGH=1.2, MEDIUM=1.1, LOW_or_none=1.0

A SAST+DAST correlated SQL injection in a critical asset with a known exploit scores:
```
min(9.5 × 1.3 × 1.4 × 1.2, 10.0) = min(20.7, 10.0) = 10.0
```

### 4.4 Severity Mapping

The composite risk score maps back to a severity label for display:

| Risk Score | Severity |
|---|---|
| ≥ 9.0 | critical |
| ≥ 7.0 | high |
| ≥ 4.0 | medium |
| ≥ 1.0 | low |
| < 1.0 | info |

---

## 5. Incremental Update Model

### 5.1 Scan-Triggered Correlation

Correlation runs are triggered by scan completion, not on a schedule. The flow:

1. Scan job completes → status update on `scan.status.update`
2. Correlation engine receives the event
3. Loads all findings from the completed scan
4. Loads existing findings from prior scans in the same project
5. Runs deduplication (update existing vs insert new)
6. Runs cross-type correlation (SAST↔DAST pairs)
7. Enriches with vuln intel
8. Computes risk scores
9. Upserts correlation groups
10. Publishes `findings.correlated` event

### 5.2 Incremental vs Full Recorrelation

**Incremental (default):** Only correlate findings from the new scan against existing corpus. O(N × M) where N = new findings, M = existing findings for the project.

**Full recorrelation (on demand):** Recorrelate all findings in a project. Triggered by:
- Vulnerability intelligence update (new CVE data may change risk scores)
- Threshold configuration change
- Manual admin request

### 5.3 Finding Lifecycle

```
New Scan → Ingest → Dedup → Correlate → Score → Store
                      │
                      ├── fingerprint exists → UPDATE last_seen, scan_count
                      └── new fingerprint    → INSERT as 'new'

Prior finding absent from N consecutive scans → status = 'resolved'
Resolved finding reappears → status = 'reopened'
```

The `scan_count` field tracks persistence. A finding seen in 10/10 scans is more credible than one seen in 1/10.

---

## 6. Performance Considerations

### 6.1 Scalability Targets

| Metric | Target |
|---|---|
| Correlation latency per scan | < 30 seconds for 10K findings |
| Deduplication throughput | ≥ 50K fingerprint lookups/second |
| Cross-correlation pairs evaluated | ≥ 1M pairs/second |
| Database batch upsert | ≥ 5K findings/second |

### 6.2 Indexing Strategy

```sql
-- Fingerprint index for dedup (already exists)
CREATE INDEX idx_findings_fingerprint ON findings.findings(fingerprint);

-- Project + type composite for cross-correlation queries
CREATE INDEX idx_findings_project_type ON findings.findings(project_id, finding_type);

-- CWE index for axis-1 matching
CREATE INDEX idx_findings_cwe ON findings.findings(cwe_id) WHERE cwe_id IS NOT NULL;

-- Correlation group lookup
CREATE INDEX idx_correlation_groups_project ON findings.correlation_groups(project_id);
CREATE INDEX idx_correlation_members_finding ON findings.correlation_members(finding_id);
```

### 6.3 Memory Management

- CWE hierarchy loaded once at startup (~1,500 entries, < 1MB)
- Findings loaded per-project, per-scan (bounded by project size)
- Correlation computed in-memory, streamed to DB in batches of 500
- No unbounded in-memory accumulation

### 6.4 Parallelism

- Multiple scan completions processed concurrently (one goroutine per project)
- Per-project: dedup is sequential (fingerprint uniqueness), correlation is parallelizable across finding pairs
- DB writes use batch upserts with `ON CONFLICT` for atomicity

---

## 7. Failure Modes

### 7.1 Failure Scenarios

| Scenario | Detection | Recovery |
|---|---|---|
| Correlation engine crashes mid-run | Scan job stays in `correlating` status | On restart, re-process jobs stuck in `correlating` for > 10 min |
| Database unavailable during write | Batch upsert fails | Retry with exponential backoff (3 attempts), then publish failure status |
| NATS message loss | Finding missing from correlation | At-least-once delivery via JetStream ACK; idempotent dedup via fingerprint |
| CWE hierarchy missing/corrupt | Axis-1 always scores 0 | Startup health check validates CWE data; refuse to start if absent |
| Vuln intel stale | Risk scores use outdated EPSS/KEV | Staleness metric; risk scores still valid, just not enriched with latest intel |
| Correlation score drift | Thresholds too loose/tight | Correlation run audit log; admin can review and adjust thresholds |
| Duplicate correlation runs | Two engines process same scan | Idempotent: correlation groups use `ON CONFLICT (project_id, primary_finding_id) DO UPDATE` |

### 7.2 Data Integrity

- Correlation groups are append-only (groups are never deleted, only status changes)
- Axis scores are immutable once computed (audit trail)
- Risk scores can be recomputed (deterministic formula)
- All correlation runs logged in `findings.correlation_runs` for auditability

### 7.3 Graceful Degradation

If the correlation engine is unavailable:
- Scans still complete and produce raw findings
- Raw findings are stored and queryable
- Correlation happens when the engine recovers (processes backlog)
- No data loss, only delayed enrichment

---

## 8. Test Strategy

### 8.1 Unit Tests

| Component | Test Cases |
|---|---|
| Deduplicator | Same fingerprint → update; new fingerprint → insert; absent → resolve |
| CWE Matcher | Exact match, parent match, category match, no match |
| Parameter Matcher | Literal match, normalized match, snake↔camel, no match |
| Endpoint Matcher | Path segment match, resource match, no match |
| Temporal Scorer | Same cycle, 24h, 7d, old |
| Risk Scorer | All multiplier combinations; cap at 10.0; edge cases |
| Correlator | Single pair, multi-pair, group formation, threshold boundaries |

### 8.2 Integration Tests

| Test | Description |
|---|---|
| Full pipeline | Ingest SAST + DAST findings → verify correlation groups created |
| Dedup across scans | Run same findings twice → verify `scan_count` incremented, no duplicates |
| SAST-only scan | No DAST findings → standalone findings with base risk |
| DAST-only scan | No SAST findings → standalone findings with base risk |
| Vuln intel enrichment | Finding with CWE-89 → linked to CVE-2024-xxxx from vuln intel |
| Threshold customization | Project overrides threshold → verify different grouping |
| Idempotent re-run | Run correlation twice → same result |

### 8.3 Adversarial Tests

| Test | Description |
|---|---|
| 10K findings stress test | Verify < 30s latency |
| Malformed findings | Missing CWE, empty URL → graceful skip |
| CWE hierarchy corruption | Missing parent → fall back to exact match only |
| Concurrent project correlation | 10 projects simultaneously → no cross-contamination |
| Score boundary tests | Scores at exactly 0.30, 0.50, 0.80 thresholds |

### 8.4 Regression Tests

- Golden dataset: curated set of 50 SAST + 50 DAST findings with known-good correlation groups
- Any algorithm change must produce identical results on the golden dataset (or be explicitly acknowledged as a scoring change)

---

## 9. MVP vs Advanced

### 9.1 MVP (Phase 3)

| Feature | Included |
|---|---|
| Fingerprint-based deduplication | Yes |
| CWE exact + parent match (axis 1) | Yes |
| Parameter literal match (axis 2) | Yes, literal only |
| Path-segment endpoint matching (axis 3) | Yes, heuristic |
| Temporal proximity (axis 4) | Yes |
| Composite risk scoring | Yes |
| Vuln intel enrichment (EPSS, KEV) | Yes |
| NATS-triggered per-scan correlation | Yes |
| Correlation audit log | Yes |
| Prometheus metrics | Yes |
| Configurable thresholds per project | Yes |

### 9.2 Advanced (Phase 4+)

| Feature | Phase |
|---|---|
| Framework-specific route parsing (chi, mux, Express, Spring) | Phase 4 |
| Data-flow analysis (SAST taint source → DAST sink) | Phase 4 |
| Machine-learned correlation weights (trained on user triage data) | Phase 5 |
| Cross-project correlation (shared libraries) | Phase 5 |
| SCA finding correlation (vulnerable dependency → exploit in DAST) | Phase 4 |
| Automated false-positive suppression (user feedback loop) | Phase 4 |
| GraphQL API for correlation exploration | Phase 4 |
| Real-time correlation (stream processing, not batch) | Phase 5 |

### 9.3 Implementation Order

```
Week 1:  pkg/correlation — scoring functions, CWE hierarchy, axis matchers
Week 2:  internal/correlation — deduplicator, correlator, risk scorer
Week 3:  internal/correlation — NATS consumer, DB persistence, publisher
Week 4:  cmd/correlation-engine — service entrypoint, Docker Compose
Week 5:  Integration tests, golden dataset, stress test
Week 6:  Vuln intel enrichment integration, metrics, docs
```

---

## Appendix A: CWE Parent Mapping (subset)

| CWE | Name | Parent | Category |
|---|---|---|---|
| 79 | Cross-site Scripting | 74 | Injection |
| 89 | SQL Injection | 943 | Injection |
| 22 | Path Traversal | 706 | File Handling |
| 78 | OS Command Injection | 77 | Injection |
| 352 | Cross-Site Request Forgery | 345 | Auth |
| 918 | Server-Side Request Forgery | 441 | Injection |
| 502 | Deserialization of Untrusted Data | 913 | Data Integrity |
| 611 | XML External Entity | 91 | Injection |
| 287 | Improper Authentication | 284 | Auth |
| 862 | Missing Authorization | 285 | Auth |

## Appendix B: NATS Subject Map

| Subject | Producer | Consumer |
|---|---|---|
| `scan.results.sast` | SAST Worker | Correlation Engine |
| `scan.results.dast` | DAST Worker | Correlation Engine |
| `scan.status.update` | Workers | Correlation Engine (trigger) |
| `findings.correlated` | Correlation Engine | Control Plane |
| `findings.deduplicated` | Correlation Engine | Audit Service |
