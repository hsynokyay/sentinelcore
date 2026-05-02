# Risk Correlation MVP — Design Spec

**Date:** 2026-04-10
**Status:** Approved
**Scope:** MVP
**Sprint:** Risk Correlation

---

## 1. Goal

Turn SentinelCore from a finding-centric system into a **risk-centric** system by correlating SAST, DAST, and attack surface evidence into explainable risk clusters.

A user of the platform should see a smaller set of higher-value risk clusters, where each cluster:

- groups duplicate and related findings into a single actionable unit
- explains why it is ranked highly (every score point is traceable to a specific reason)
- survives re-scans without losing triage history
- links to related runtime and surface evidence

Non-goals (MVP): ML ranking, ticketing integration, graph databases, multi-cluster merge operations, evidence retention policy.

---

## 2. Principles

1. **Deterministic** — given the same inputs, the correlation worker always produces the same clusters, scores, and relations. No random tiebreaks, no fuzzy matching.
2. **Explainable** — every risk score decomposes into a list of evidence rows. A user can read "why is this ranked 85?" line by line.
3. **Low-noise** — prefer slight fragmentation over incorrect merging. Two separate clusters are easier to recover from than one wrong cluster.
4. **Stable identity** — clusters have fingerprint-based IDs that survive across re-runs so triage history persists.
5. **Isolated rebuilds** — each correlation run is atomic per project and guarded by an advisory lock to prevent races.

---

## 3. Architecture

### 3.1 Deployment

Reuse the existing `cmd/correlation-engine/` binary. Strip the legacy in-memory `CorrelationGroup` orchestration and attach the new `internal/risk/` package. No new Docker Compose service, no new health check, no new deployment artifact.

### 3.2 Package layout

```
internal/risk/
  fingerprint.go       # Canonical route/path/param normalization; fingerprint computation
  correlator.go        # Per-project rebuild (the main pipeline)
  scorer.go            # Base severity + boost scoring; emits evidence rows
  relations.go         # Cluster relation classification (runtime_confirmation, same_cwe, related_surface)
  store.go             # PostgreSQL persistence for clusters, findings, evidence, relations, runs
  worker.go            # NATS subscriber, per-project debouncer, run dispatcher
  types.go             # Cluster, ClusterFinding, ClusterEvidence, Relation, Run structs
  correlator_test.go
  fingerprint_test.go
  scorer_test.go
  relations_test.go
  testdata/            # Fixture findings for deterministic end-to-end tests

internal/controlplane/api/
  risks.go             # GET /risks, GET /risks/:id, POST /risks/:id/{resolve|reopen|mute}

web/features/risks/
  api.ts, hooks.ts, risks-table.tsx, risk-detail.tsx, risk-evidence-panel.tsx

web/app/(dashboard)/risks/
  page.tsx, [id]/page.tsx
```

Reuse from `pkg/correlation/`: `CWEHierarchy` only. All route/param normalization is new in `internal/risk/fingerprint.go`.

Deletions: `internal/correlation/engine.go`, `memstore.go`, `natshandler.go` (unused legacy in-memory experiment). `pkg/correlation/` stays since it has stable helpers and tests.

### 3.3 Worker trigger model

The risk worker subscribes to `scan.completed` NATS events. For each incoming event, it debounces per project with a 30-second window:

```
on scan.completed(project_id):
  if last_successful_run(project_id) < 10 seconds ago:
    drop event
  else:
    schedule run for project_id in 30s
    if run already scheduled for project_id:
      extend the deadline
```

When the deadline fires, the worker runs the rebuild in a single database transaction with a project-scoped advisory lock. Manual recompute endpoint (`POST /api/v1/projects/{id}/risks/rebuild`) is available for debugging and recovery; it bypasses the debouncer but still acquires the lock.

---

## 4. Schema

New schema `risk`. Three tables + runs + relations.

### 4.1 Migration `023_risk_clusters.up.sql`

```sql
CREATE SCHEMA IF NOT EXISTS risk;

-- ---------------------------------------------------------------------------
-- Correlation runs: observability + debouncing + lifecycle gating
-- ---------------------------------------------------------------------------
CREATE TABLE risk.correlation_runs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    trigger              TEXT NOT NULL,
        -- 'scan_completed' | 'manual' | 'retry'
    triggered_by_scan    UUID,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at          TIMESTAMPTZ,
    status               TEXT NOT NULL DEFAULT 'running',
        -- 'running' | 'ok' | 'error'
    error_message        TEXT,
    clusters_touched     INTEGER NOT NULL DEFAULT 0,
    clusters_created     INTEGER NOT NULL DEFAULT 0,
    clusters_resolved    INTEGER NOT NULL DEFAULT 0,
    findings_processed   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_risk_runs_project
    ON risk.correlation_runs(project_id, started_at DESC);

ALTER TABLE risk.correlation_runs ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Clusters: the primary risk entity
-- ---------------------------------------------------------------------------
CREATE TABLE risk.clusters (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,

    -- Stable identity
    fingerprint          TEXT NOT NULL,
    fingerprint_version  SMALLINT NOT NULL DEFAULT 1,
    fingerprint_kind     TEXT NOT NULL,
        -- 'dast_route' | 'sast_file'

    -- Human-readable summary
    title                TEXT NOT NULL,
    vuln_class           TEXT NOT NULL,
    cwe_id               INTEGER,
    owasp_category       TEXT,
    language             TEXT,               -- SAST only
    canonical_route      TEXT,               -- DAST only
    canonical_param      TEXT,               -- DAST only
    http_method          TEXT,               -- DAST only
    file_path            TEXT,               -- SAST only
    enclosing_method     TEXT,               -- SAST only
    location_group       TEXT,               -- SAST only (see §5.2)

    -- Scoring + state
    severity             TEXT NOT NULL,
    risk_score           INTEGER NOT NULL DEFAULT 0
        CHECK (risk_score BETWEEN 0 AND 100),
    exposure             TEXT NOT NULL DEFAULT 'unknown',
        -- worst across linked surface entries: public|authenticated|both|unknown
    status               TEXT NOT NULL DEFAULT 'active',
        -- 'active' | 'auto_resolved' | 'user_resolved' | 'muted'
    missing_run_count    INTEGER NOT NULL DEFAULT 0,

    -- Denormalized counts
    finding_count        INTEGER NOT NULL DEFAULT 0,
    surface_count        INTEGER NOT NULL DEFAULT 0,

    -- Timeline
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_id          UUID REFERENCES risk.correlation_runs(id) ON DELETE SET NULL,

    -- Triage
    resolved_at          TIMESTAMPTZ,
    resolved_by          UUID REFERENCES core.users(id) ON DELETE SET NULL,
    resolution_reason    TEXT,
    muted_until          TIMESTAMPTZ,

    CONSTRAINT clusters_project_fp_unique
        UNIQUE (project_id, fingerprint_version, fingerprint)
);
CREATE INDEX idx_risk_clusters_project_score
    ON risk.clusters(project_id, risk_score DESC, status);
CREATE INDEX idx_risk_clusters_vuln_class
    ON risk.clusters(project_id, vuln_class);
CREATE INDEX idx_risk_clusters_status
    ON risk.clusters(project_id, status);

ALTER TABLE risk.clusters ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Cluster findings: which findings belong to which cluster this run
-- ---------------------------------------------------------------------------
CREATE TABLE risk.cluster_findings (
    cluster_id           UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    finding_id           UUID NOT NULL REFERENCES findings.findings(id) ON DELETE CASCADE,
    role                 TEXT NOT NULL,     -- 'sast' | 'dast' | 'sca'
    first_seen_run_id    UUID REFERENCES risk.correlation_runs(id) ON DELETE SET NULL,
    last_seen_run_id     UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    added_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (cluster_id, finding_id)
);
CREATE INDEX idx_cluster_findings_finding
    ON risk.cluster_findings(finding_id);
CREATE INDEX idx_cluster_findings_last_seen_run
    ON risk.cluster_findings(last_seen_run_id);

ALTER TABLE risk.cluster_findings ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Cluster evidence: explainability rows. Every score contribution, link, or
-- context note for a cluster is one row here.
-- ---------------------------------------------------------------------------
CREATE TABLE risk.cluster_evidence (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id           UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    category             TEXT NOT NULL
        CHECK (category IN ('score_base', 'score_boost', 'score_penalty', 'link', 'context')),
    code                 TEXT NOT NULL,
        -- 'SEVERITY_BASE' | 'RUNTIME_CONFIRMED' | 'PUBLIC_EXPOSURE' |
        -- 'SAME_ROUTE' | 'SAME_PARAM' | 'SURFACE_LINK' | 'RELATED_CLUSTER'
    label                TEXT NOT NULL,
    weight               INTEGER,           -- score contribution; NULL for link/context
    ref_type             TEXT,              -- 'surface_entry' | 'finding' | 'cluster' | NULL
    ref_id               TEXT,
    sort_order           INTEGER NOT NULL DEFAULT 0,
    source_run_id        UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_cluster_evidence_cluster
    ON risk.cluster_evidence(cluster_id, sort_order);
CREATE INDEX idx_cluster_evidence_run
    ON risk.cluster_evidence(source_run_id);

ALTER TABLE risk.cluster_evidence ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- Cluster relations: explicit links between clusters (e.g. SAST <-> DAST)
-- ---------------------------------------------------------------------------
CREATE TABLE risk.cluster_relations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    source_cluster_id    UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    target_cluster_id    UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    relation_type        TEXT NOT NULL
        CHECK (relation_type IN ('runtime_confirmation', 'same_cwe', 'related_surface')),
    confidence           NUMERIC(3,2) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    rationale            TEXT NOT NULL,
    first_linked_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_linked_run_id   UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,

    CONSTRAINT no_self_relation CHECK (source_cluster_id <> target_cluster_id),
    UNIQUE (source_cluster_id, target_cluster_id, relation_type)
);
CREATE INDEX idx_cluster_relations_source
    ON risk.cluster_relations(source_cluster_id);
CREATE INDEX idx_cluster_relations_target
    ON risk.cluster_relations(target_cluster_id);
CREATE INDEX idx_cluster_relations_project
    ON risk.cluster_relations(project_id, relation_type);

ALTER TABLE risk.cluster_relations ENABLE ROW LEVEL SECURITY;

-- RLS policies — isolate every table by project_id -> org_id via core.projects.
-- Follows the existing pattern from scans.scan_jobs / findings.findings.
-- (Concrete CREATE POLICY statements omitted here; implementation must
-- mirror the existing convention using current_setting('app.org_id').)
```

### 4.2 New column on `findings.findings`

```sql
-- migrations/023_risk_clusters.up.sql (continued)
ALTER TABLE findings.findings
    ADD COLUMN function_name TEXT;
```

Populated going forward by the SAST worker from `ir.Function.Name` on emit. Existing rows are NULL. Used by `locationGroup()` for SAST fingerprinting.

---

## 5. Fingerprinting

### 5.1 Route, path, and param normalization

**Route normalization** (DAST URL → canonical form), applied in order:

1. Strip scheme + host: `https://api.example.com/users?x=1` → `/users?x=1`
2. Strip query string: `/users?x=1` → `/users`
3. URL-decode path segments
4. Lowercase the path
5. Split on `/` and parameterize each non-empty segment positionally:
   - pure numeric → `:num`
   - UUID-shaped (regex `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`) → `:uuid`
   - long alphanumeric (length > 16, contains both letters and digits) → `:token`
   - short literal → keep as-is
6. Rejoin with `/`, strip trailing `/` except for the root `/`

Examples:

| Input | Canonical |
|---|---|
| `https://api.example.com/Users/42/Orders/` | `/users/:num/orders` |
| `/users/admin` | `/users/admin` |
| `/api/v1/users/550e8400-e29b-41d4-a716-446655440000` | `/api/v1/users/:uuid` |
| `/download/abc123def456ghi789jkl` | `/download/:token` |

**Param normalization:** lowercase, trim whitespace. `UserID` → `userid`. Empty string becomes the literal empty string.

**File path normalization:** use `findings.file_path` as the source. Apply:
1. Replace backslashes with forward slashes (Windows)
2. Strip any leading `./`
3. Reject absolute paths — error out (should never happen; SAST emits artifact-relative paths)

### 5.2 `location_group` — SAST discriminator

```
if enclosing_method (findings.function_name) is set and non-empty:
    location_group = "m:" + enclosing_method
else:
    location_group = "b:" + floor(line_start / 25) + ":cwe_" + cwe_id
```

Bucket size of 25 lines is chosen to survive small refactors (comment blocks, formatter runs) while keeping distinct findings in the same file in separate clusters. The `cwe_id` suffix is defensively redundant (CWE is already in the outer hash) but is explicit in the location_group so it survives any future refactor of the outer hash structure. `rule_id` is intentionally NOT used because rule IDs drift between rule engine versions.

### 5.3 Fingerprint formulas

**DAST cluster fingerprint:**

```
fp_input = [
    project_id,
    "dast",
    cwe_id,
    http_method_upper,
    canonical_route,
    canonical_param,
]
fingerprint = sha256(join(fp_input, "|"))
fingerprint_kind = "dast_route"
fingerprint_version = 1
```

**SAST cluster fingerprint:**

```
fp_input = [
    project_id,
    "sast",
    cwe_id,
    language_lower,
    normalized_file_path,
    location_group,
]
fingerprint = sha256(join(fp_input, "|"))
fingerprint_kind = "sast_file"
fingerprint_version = 1
```

`fingerprint_version` is stored on the cluster row and participates in the `UNIQUE (project_id, fingerprint_version, fingerprint)` constraint, but is **not** included in the hash input. This lets a future v2 bump change hash inputs without invalidating v1 clusters, and lets v1+v2 coexist during gradual migration.

---

## 6. Scoring

### 6.1 Formula

```
base = severityBase(cluster.severity)
  // critical = 60
  // high     = 45
  // medium   = 30
  // low      = 15
  // info     = 5

total = base

if exists cluster_relations row with
     relation_type = 'runtime_confirmation'
     AND confidence >= 0.80
     AND source_cluster_id = cluster.id OR target_cluster_id = cluster.id:
    total += 20    // RUNTIME_CONFIRMED

if any linked surface_entry has exposure = 'public':
    total += 15    // PUBLIC_EXPOSURE

if cluster.fingerprint_kind = 'dast_route'
     AND multiple findings in the cluster share cluster.canonical_route:
    total += 5     // SAME_ROUTE

if cluster.fingerprint_kind = 'dast_route'
     AND multiple findings in the cluster share cluster.canonical_param:
    total += 5     // SAME_PARAM

risk_score = min(100, total)
```

Each boost is applied **at most once** per cluster per run, regardless of how many members would individually qualify. The cap is applied once at the end.

Maximum reachable: 60 + 20 + 15 + 5 + 5 = 105 → capped to 100.
Minimum: 5 (info severity, no boosts).

### 6.2 Evidence emission

Every run rebuilds evidence for touched clusters. The scorer emits one row per scoring decision **plus** a mandatory `SEVERITY_BASE` row so the UI can always show where the base score comes from.

Example evidence rows for a cluster that scored 85 (high + runtime + public + same_route):

```
sort_order | category     | code              | label                                           | weight
-----------+--------------+-------------------+-------------------------------------------------+-------
         0 | score_base   | SEVERITY_BASE     | Base score from high severity                  |     45
        10 | score_boost  | RUNTIME_CONFIRMED | Confirmed at runtime by DAST                    |     20
        20 | score_boost  | PUBLIC_EXPOSURE   | Exposed on public surface /api/users            |     15
        30 | score_boost  | SAME_ROUTE        | Multiple findings on route /api/users           |      5
```

Sum: 45 + 20 + 15 + 5 = 85. The UI renders this table directly.

Additional non-score evidence may appear with `category = 'link'` or `'context'`:

```
sort_order | category  | code              | label                                                    | weight
-----------+-----------+-------------------+----------------------------------------------------------+-------
       100 | link      | SURFACE_LINK      | Linked to surface entry /api/users (public)              | NULL
       110 | link      | RELATED_CLUSTER   | Related to SAST cluster UserController.java (CWE-89)     | NULL
```

---

## 7. Cluster relations

Relations are computed **per touched cluster** after cluster_findings are settled and before scoring. Each relation has a `confidence` and a human-readable `rationale`.

### 7.1 Types and confidence

| Relation type | Base | Bonus | Max | Drives boost? |
|---|---|---|---|---|
| `runtime_confirmation` | 0.80 | +0.10 if both clusters share a non-empty `owasp_category` | 0.90 | **Yes** (+20 if conf ≥ 0.80) |
| `same_cwe` | 0.30 | — | 0.30 | No |
| `related_surface` | 0.60 | — | 0.60 | No |

`runtime_confirmation` is emitted when one cluster is `sast_file` and the other is `dast_route` and both share the same `cwe_id`. This is the strongest cross-type link and directly drives the `RUNTIME_CONFIRMED` score boost.

`same_cwe` is emitted for two clusters of the **same** kind (both SAST or both DAST) that share a CWE. Informational only; surfaces in the UI as a "related risk" but does not affect scoring.

`related_surface` is emitted for two DAST clusters that share at least one linked surface entry. Informational only.

### 7.2 Pair canonicalization

To satisfy the `UNIQUE (source, target, type)` constraint, pairs are canonicalized so the smaller UUID is always the `source_cluster_id`. API queries use `WHERE source_cluster_id = $1 OR target_cluster_id = $1` to read both directions.

### 7.3 Classification pseudocode

```go
func classifyRelation(a, b *Cluster) (relType string, confidence float64, rationale string) {
    // runtime_confirmation: SAST cluster + DAST cluster with same CWE
    sastDast := (a.FingerprintKind == "sast_file" && b.FingerprintKind == "dast_route") ||
                (a.FingerprintKind == "dast_route" && b.FingerprintKind == "sast_file")
    if sastDast && a.CWEID == b.CWEID {
        conf := 0.80
        if a.OWASPCategory != "" && a.OWASPCategory == b.OWASPCategory {
            conf += 0.10
        }
        if conf > 1.00 {
            conf = 1.00
        }
        return "runtime_confirmation", conf,
            fmt.Sprintf("SAST and DAST both detected CWE-%d (%s)", a.CWEID, a.VulnClass)
    }

    // same_cwe: both same kind, same CWE
    if a.FingerprintKind == b.FingerprintKind && a.CWEID == b.CWEID {
        return "same_cwe", 0.30,
            fmt.Sprintf("Same vulnerability class (CWE-%d)", a.CWEID)
    }

    // related_surface: two DAST clusters touching the same surface entry
    if a.FingerprintKind == "dast_route" && b.FingerprintKind == "dast_route" &&
        sharesSurface(a.ID, b.ID) {
        return "related_surface", 0.60,
            "Both clusters touch the same surface entry"
    }

    return "", 0, ""
}
```

---

## 8. Rebuild pipeline

The correlation worker's core operation is a **per-project rebuild**. It runs inside a single database transaction with an advisory lock, guaranteeing no two runs for the same project execute concurrently.

### 8.1 Pseudocode

```go
func RebuildProject(ctx context.Context, projectID string, trigger string, triggeredByScan *string) error {
    tx := db.BeginTx(ctx, ReadCommitted)
    defer tx.Rollback()

    // Project-scoped lock: released when transaction ends.
    tx.Exec(`SELECT pg_advisory_xact_lock($1)`, hashProjectLock(projectID))

    // Open a new run row
    runID := tx.QueryRow(`
        INSERT INTO risk.correlation_runs
            (project_id, trigger, triggered_by_scan, status)
        VALUES ($1, $2, $3, 'running')
        RETURNING id
    `, projectID, trigger, triggeredByScan)

    // Load all currently-active findings for the project
    findings := loadActiveFindings(tx, projectID)

    touched := set{}
    created := 0

    for _, f := range findings {
        fp, kind, version := ComputeFingerprint(f)

        // Upsert the cluster; reactivate if auto_resolved
        clusterID, wasInserted := upsertCluster(tx, runID, f, fp, kind, version)
        if wasInserted {
            created++
        }
        touched.add(clusterID)

        // Attach finding to cluster (PK (cluster_id, finding_id))
        tx.Exec(`
            INSERT INTO risk.cluster_findings
                (cluster_id, finding_id, role, first_seen_run_id, last_seen_run_id)
            VALUES ($1, $2, $3, $4, $4)
            ON CONFLICT (cluster_id, finding_id) DO UPDATE SET
                last_seen_run_id = EXCLUDED.last_seen_run_id
        `, clusterID, f.ID, f.Type, runID)
    }

    // Project-scoped cleanup of stale cluster_findings rows.
    // Catches findings that migrated between clusters AND findings that vanished.
    tx.Exec(`
        DELETE FROM risk.cluster_findings cf
        USING risk.clusters c
        WHERE cf.cluster_id = c.id
          AND c.project_id = $1
          AND cf.last_seen_run_id <> $2
    `, projectID, runID)

    // Recompute denormalized counts, exposure, severity for touched clusters
    recomputeClusterAggregates(tx, touched)

    // Delete stale evidence for touched clusters (rebuilt below)
    tx.Exec(`
        DELETE FROM risk.cluster_evidence
        WHERE cluster_id = ANY($1) AND source_run_id <> $2
    `, touched, runID)

    // For each touched cluster: rebuild relations, then rescore and emit evidence
    for clusterID := range touched {
        rebuildRelations(tx, projectID, clusterID, runID)
        rescoreAndEmitEvidence(tx, clusterID, runID)
    }

    // Missing-cluster bookkeeping: auto-resolve after 3 misses
    resolved := markMissingClustersAndResolve(tx, projectID, runID)

    // Close run
    tx.Exec(`
        UPDATE risk.correlation_runs SET
            finished_at = now(),
            status = 'ok',
            clusters_touched = $2,
            clusters_created = $3,
            clusters_resolved = $4,
            findings_processed = $5
        WHERE id = $1
    `, runID, len(touched), created, resolved, len(findings))

    return tx.Commit()
}
```

### 8.2 Cluster upsert with auto-reactivation

```go
func upsertCluster(tx, runID, f, fp, kind, version) (id string, inserted bool) {
    return tx.QueryRow(`
        INSERT INTO risk.clusters (
            project_id, fingerprint, fingerprint_version, fingerprint_kind,
            title, vuln_class, cwe_id, owasp_category, language,
            canonical_route, canonical_param, http_method,
            file_path, enclosing_method, location_group,
            severity, status, last_run_id, last_seen_at, first_seen_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                'active', $17, now(), now())
        ON CONFLICT (project_id, fingerprint_version, fingerprint) DO UPDATE SET
            last_seen_at      = now(),
            last_run_id       = EXCLUDED.last_run_id,
            missing_run_count = 0,
            status = CASE
                WHEN risk.clusters.status = 'auto_resolved' THEN 'active'
                WHEN risk.clusters.status = 'muted'
                     AND risk.clusters.muted_until < now() THEN 'active'
                ELSE risk.clusters.status
            END,
            resolved_at = CASE
                WHEN risk.clusters.status = 'auto_resolved' THEN NULL
                ELSE risk.clusters.resolved_at
            END
        RETURNING id, (xmax = 0) AS inserted
    `, ...).Scan(&id, &inserted)
}
```

### 8.3 Missing cluster detection + grace period

```go
func markMissingClustersAndResolve(tx, projectID, runID) int {
    // Step 1: increment missing_run_count for active clusters not touched in this run
    tx.Exec(`
        UPDATE risk.clusters
        SET missing_run_count = missing_run_count + 1
        WHERE project_id = $1
          AND status = 'active'
          AND (last_run_id IS NULL OR last_run_id <> $2)
    `, projectID, runID)

    // Step 2: auto-resolve after 3 consecutive misses
    return tx.QueryRow(`
        WITH updated AS (
            UPDATE risk.clusters
            SET status = 'auto_resolved',
                resolved_at = now(),
                resolution_reason = 'no findings in ' || missing_run_count || ' consecutive runs'
            WHERE project_id = $1
              AND status = 'active'
              AND missing_run_count >= 3
            RETURNING id
        )
        SELECT count(*) FROM updated
    `, projectID)
}
```

### 8.4 Lifecycle states

| State | How entered | How exited |
|---|---|---|
| `active` | Default on creation; reactivation from `auto_resolved` or expired `muted` | Auto after 3 missed runs; user resolve; user mute |
| `auto_resolved` | Cluster missing for 3+ consecutive runs | Findings return → reactivated to `active` |
| `user_resolved` | User action via `POST /risks/:id/resolve` | Only via `POST /risks/:id/reopen`; does NOT auto-reactivate on finding return |
| `muted` | User action with `muted_until` | Expiration → `active` on next run; user unmute |

The worker NEVER auto-resolves a `user_resolved` cluster. If a `user_resolved` cluster has new findings, they silently re-link to it via cluster_findings, but the status remains `user_resolved`. The UI surfaces these as "resolved clusters with new findings" on the risks page.

---

## 9. API

### 9.1 Routes

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/risks` | List risk clusters |
| GET | `/api/v1/risks/{id}` | Cluster detail with evidence, findings, relations |
| POST | `/api/v1/risks/{id}/resolve` | Mark as user_resolved |
| POST | `/api/v1/risks/{id}/reopen` | Reopen a user_resolved cluster |
| POST | `/api/v1/risks/{id}/mute` | Mute until a given timestamp |
| POST | `/api/v1/projects/{id}/risks/rebuild` | Manual recompute (debug/recovery) |

All routes require the standard JWT or API key auth and enforce RLS via `app.org_id`. Scoping follows existing controlplane patterns.

### 9.2 GET /api/v1/risks

**Default query:**
```sql
SELECT id, title, vuln_class, severity, risk_score, exposure, status,
       finding_count, surface_count, first_seen_at, last_seen_at
FROM risk.clusters
WHERE project_id = $1 AND status = 'active'
ORDER BY risk_score DESC, last_seen_at DESC
LIMIT 50
```

**Query params:**
- `project_id=<uuid>` — required
- `status=active|auto_resolved|user_resolved|muted|all` — default `active`
- `severity=critical|high|medium|low|info` — optional
- `vuln_class=<string>` — optional
- `limit=<int>` — default 50, max 200
- `offset=<int>` — default 0

**Response shape:**
```json
{
  "risks": [
    {
      "id": "uuid",
      "title": "SQL Injection on POST /api/users",
      "vuln_class": "sql_injection",
      "cwe_id": 89,
      "severity": "critical",
      "risk_score": 85,
      "exposure": "public",
      "status": "active",
      "finding_count": 3,
      "surface_count": 1,
      "first_seen_at": "2026-04-10T12:00:00Z",
      "last_seen_at": "2026-04-10T14:30:00Z",
      "top_reasons": [
        {"code": "SEVERITY_BASE", "label": "Base score from critical severity", "weight": 60},
        {"code": "RUNTIME_CONFIRMED", "label": "Confirmed at runtime by DAST", "weight": 20}
      ]
    }
  ],
  "total": 42,
  "limit": 50,
  "offset": 0
}
```

`top_reasons` is the first 2 evidence rows by `sort_order` — enough for the list row UI to show a one-liner "why".

### 9.3 GET /api/v1/risks/{id}

Returns the full cluster with all evidence rows, finding summaries, and related clusters:

```json
{
  "id": "uuid",
  "project_id": "uuid",
  "title": "SQL Injection on POST /api/users",
  "vuln_class": "sql_injection",
  "cwe_id": 89,
  "owasp_category": "A03:2021",
  "fingerprint_kind": "dast_route",
  "canonical_route": "/api/users",
  "http_method": "POST",
  "canonical_param": "id",
  "severity": "critical",
  "risk_score": 85,
  "exposure": "public",
  "status": "active",
  "first_seen_at": "...",
  "last_seen_at": "...",
  "last_run_id": "uuid",
  "evidence": [
    {
      "category": "score_base",
      "code": "SEVERITY_BASE",
      "label": "Base score from critical severity",
      "weight": 60,
      "sort_order": 0
    },
    {
      "category": "score_boost",
      "code": "RUNTIME_CONFIRMED",
      "label": "Confirmed at runtime by DAST",
      "weight": 20,
      "sort_order": 10
    },
    {
      "category": "link",
      "code": "SURFACE_LINK",
      "label": "Linked to surface entry /api/users (public)",
      "weight": null,
      "ref_type": "surface_entry",
      "ref_id": "surface_uuid",
      "sort_order": 100
    }
  ],
  "findings": [
    {
      "id": "uuid",
      "role": "dast",
      "title": "SQL Injection via id parameter",
      "severity": "critical",
      "file_path": null,
      "url": "https://stg.example.com/api/users",
      "line_start": null
    },
    {
      "id": "uuid",
      "role": "sast",
      "title": "SQL Injection in UserController.getUser",
      "severity": "critical",
      "file_path": "src/controllers/UserController.java",
      "line_start": 42
    }
  ],
  "relations": [
    {
      "id": "uuid",
      "related_cluster_id": "uuid",
      "relation_type": "runtime_confirmation",
      "confidence": 0.80,
      "rationale": "SAST and DAST both detected CWE-89 (sql_injection)",
      "related_cluster_title": "SQL Injection in UserController.java"
    }
  ]
}
```

### 9.4 Dashboard "Top Risks" card

The dashboard card reuses the same list query with `limit=5`:

```
GET /api/v1/risks?project_id=<id>&status=active&limit=5
```

Single source of truth. No separate endpoint.

---

## 10. Frontend

### 10.1 Routes

- `/risks` — list page
- `/risks/[id]` — detail page
- Dashboard card on `/` (if dashboard exists) or on the project home

### 10.2 Risks list page (`web/app/(dashboard)/risks/page.tsx`)

Table columns:
- **Risk score** (colored bar, 0-100)
- **Severity** (badge)
- **Title**
- **Vuln class**
- **Exposure** (badge: public/authenticated/unknown)
- **Findings** (count)
- **Surfaces** (count)
- **Last seen**

Filter bar: status tabs (Active / Auto-resolved / User-resolved / Muted), severity filter, vuln class filter, search by title.

Clicking a row navigates to `/risks/[id]`.

### 10.3 Risk detail page (`web/app/(dashboard)/risks/[id]/page.tsx`)

Layout:
- **Header:** title, severity badge, risk score (big number, colored), status badge, action buttons (Resolve / Mute / Reopen)
- **Evidence panel:** "Why ranked highly?" — renders the evidence table ordered by `sort_order`, with the base score at the top
- **Findings panel:** list of member findings with role badges (SAST / DAST / SCA) and links to the existing finding detail pages
- **Related risks panel:** list of clusters from `relations`, each with relation type, confidence, and rationale
- **Context panel:** cluster metadata (fingerprint kind, canonical route/file, first/last seen, last run)

### 10.4 Dashboard "Top Risks" card

Reusable card component showing top 5 active risks ordered by score. Each row: severity badge, title, score. Clicking a row navigates to `/risks/[id]`. "View all" link to `/risks`.

---

## 11. Testing

### 11.1 Unit tests

| File | Coverage |
|---|---|
| `fingerprint_test.go` | Route normalization (all edge cases in §5.1), param normalization, file path normalization, location_group with and without enclosing_method, deterministic fingerprint output across N runs |
| `scorer_test.go` | Base score per severity, each boost in isolation, cap at 100, evidence row emission (count, sort_order, codes) |
| `relations_test.go` | runtime_confirmation base 0.80, +0.10 OWASP bonus, same_cwe, related_surface, canonical pair ordering |
| `correlator_test.go` | End-to-end rebuild: create SAST + DAST findings, run rebuild, assert cluster count, scores, evidence, relations. Re-run with no changes — assert stable. Migration case: change fingerprint_version, assert old cluster persists and new cluster coexists. |

### 11.2 Integration tests

| Test | Scenario |
|---|---|
| `TestRebuildProject_SAST_and_DAST_same_CWE` | Create SAST and DAST findings with CWE-89. Run rebuild. Expect 2 clusters (separate fingerprint kinds), 1 runtime_confirmation relation, both clusters have RUNTIME_CONFIRMED boost (+20), score ≥ 80. |
| `TestRebuildProject_AutoResolve_GracePeriod` | Create a finding, run. Delete finding, run 2 more times — cluster still active (missing_run_count=2). Run 3rd time — cluster auto_resolved. Create finding again, run — cluster reactivated to active. |
| `TestRebuildProject_UserResolved_StaysResolved` | Create finding, run, mark cluster user_resolved. Delete finding, run — cluster stays user_resolved. Create finding again, run — cluster STILL user_resolved (not auto-reactivated). |
| `TestRebuildProject_FindingMigration` | Create finding, run. Change finding's fingerprint input (e.g. file rename). Run. Assert finding moved to new cluster, old cluster's finding_count = 0. |
| `TestRebuildProject_ConcurrentRuns` | Dispatch two rebuilds for same project simultaneously. Assert only one proceeds at a time (advisory lock), both complete without error. |
| `TestRebuildProject_PublicExposure` | Create DAST finding + surface_entry with exposure=public linked by URL. Run. Assert PUBLIC_EXPOSURE boost emitted. |

### 11.3 Frontend tests

- RisksTable renders correctly with empty state
- Risk detail page renders evidence in sort_order
- Dashboard card shows top 5 with correct score coloring
- Filters update URL query params

---

## 12. Cleanup / code deletions

As part of this sprint:

- Delete `internal/correlation/engine.go`
- Delete `internal/correlation/memstore.go`
- Delete `internal/correlation/natshandler.go`
- Delete `internal/correlation/engine_test.go` (if exists)
- Keep `pkg/correlation/cwe.go`, `scorer.go`, `types.go` (stable helpers)
- Keep `cmd/correlation-engine/main.go` but rewire it to `internal/risk/worker.go`

---

## 13. Edge cases and known limitations

1. **Advisory lock contention.** If two `scan.completed` events for the same project fire within 30s, the debouncer collapses them. If they fire more than 30s apart but the first run is still executing, the second run blocks on `pg_advisory_xact_lock` until the first commits. Worker logs the block duration; alerts if > 60s.

2. **`fingerprint_version` bumping is a migration event.** Bumping `FingerprintVersionV1` to `V2` creates a new set of clusters on the next run. Old (v1) clusters coexist but stop being updated because new findings go to v2 clusters. A follow-up backfill job is required to migrate user triage state (`user_resolved`, `muted`) from v1 to v2 clusters.

3. **Orphaned evidence from mid-transaction failures.** `ON DELETE CASCADE` handles cluster deletion. A mid-transaction failure rolls back the entire rebuild — no manual cleanup needed.

4. **`location_group` when `function_name` is NULL.** For findings emitted before the `function_name` column was added, the fallback is `"b:" + line_bucket + ":cwe_" + cwe_id`. Slightly less granular than the `m:` form but stable.

5. **`user_resolved` cluster with new findings.** Silently re-linked to the cluster; status stays `user_resolved`. The Risks page MUST surface these as "resolved clusters with new findings" in a filter tab so operators can review them.

6. **Relation symmetry.** Canonicalized via `min(UUID)` as source. API reads both directions with `WHERE source_cluster_id = $1 OR target_cluster_id = $1`.

7. **Evidence retention (MVP limitation).** Each rebuild deletes prior evidence rows to keep the UI clean. Debugging why a cluster's score changed is limited to the current run. See §14.

8. **Surface linking is best-effort.** A DAST cluster is linked to a surface entry when its `canonical_route` exactly matches the surface entry's normalized URL. Fuzzy matching is out of scope.

9. **Cross-type membership deferred.** SAST and DAST clusters remain separate in v1. Cluster merging (true unification) is deferred to a future sprint. Linking via `cluster_relations` is the v1 answer.

---

## 14. Future work / technical debt

- **Evidence retention policy.** Keep last N evidence snapshots per cluster (default N=5), with a vacuum job pruning older. UI gains a "score history" panel showing deltas across recent runs. Add `?run_id=<uuid>` filter to the detail API.

- **Cluster merging.** Introduce a merge pass that unifies SAST and DAST clusters when a runtime_confirmation relation reaches high confidence. Requires cluster lifecycle state transitions (merged-from, merged-into) and preserves triage history.

- **Exploit availability boost.** When threat intel data is available, add a `+10 EXPLOIT_AVAILABLE` boost for clusters with actively exploited CVEs.

- **Heuristic SAST → DAST route inference.** Use controller file path conventions (e.g. `UserController.java` → `/users`) to enrich SAST clusters with probable routes. Enables stronger cross-type linking.

- **Scheduled periodic rebuild.** Cron-based fallback to catch projects whose scan.completed events were missed.

- **Scoring tuning.** Once we have operational data, revisit boost weights (currently 20/15/5/5) based on false-positive rates.

---

## 15. Acceptance criteria

The sprint is done when:

- All four new tables exist with RLS and migrations are applied.
- The correlation worker subscribes to `scan.completed`, debounces per project, and rebuilds in a single transaction under an advisory lock.
- A user can create SAST + DAST findings for the same CWE, trigger a scan, and see **one** runtime-confirmed risk cluster in the Risks UI with score ≥ 80 and a line-by-line explanation of why.
- Deleting all findings in a project causes clusters to auto-resolve after 3 consecutive runs, not on the first empty run.
- A user-resolved cluster stays resolved even when findings reappear.
- `GET /api/v1/risks?project_id=X` returns the active cluster list ordered by score.
- `GET /api/v1/risks/{id}` returns the cluster with evidence, findings, and relations.
- The dashboard "Top Risks" card shows the top 5 active risks using the same query.
- The full test suite passes with zero regressions.
- Live verification: upload a real SAST + DAST artifact pair that should share a CWE, and observe the correlation in the Risks UI within 30-60 seconds of scan completion.
