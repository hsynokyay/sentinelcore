# Risk Correlation MVP Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn SentinelCore into a risk-centric platform by correlating SAST + DAST + surface evidence into explainable, persistent risk clusters with a new API and UI.

**Architecture:** New `internal/risk/` package, new `risk.*` schema, reused `cmd/correlation-engine/` binary. Worker subscribes to `scan.status.update`, debounces per project, rebuilds clusters in one transaction under a project-scoped advisory lock. Deterministic base+boost scoring emits one evidence row per contribution. Legacy `internal/correlation/*.go` deleted.

**Tech Stack:** Go 1.22, PostgreSQL 16 (pgx/v5), NATS JetStream, Next.js 16 (App Router, TanStack Query, Tailwind, shadcn/ui).

**Design spec:** `docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md` — read this before implementing.

---

## Overview

The plan is organized into 12 chunks. Each chunk is self-contained and ends with a commit. Chunks 1-8 are backend (Go), chunks 9-11 are frontend (TypeScript/React), chunk 12 is live verification.

| Chunk | Title | Outcome |
|---|---|---|
| 1 | SQL migration | `risk.*` schema exists, `findings.function_name` added |
| 2 | Go package scaffolding | `internal/risk/` builds with empty types + store skeleton |
| 3 | Fingerprinting | Pure-logic normalization + fingerprint functions with tests |
| 4 | Scorer | Pure-logic base+boost scoring with tests |
| 5 | Relations classifier | Pure-logic cluster relation classification with tests |
| 6 | Store queries | Concrete PostgreSQL persistence layer |
| 7 | Correlator pipeline | Full rebuild wired end-to-end with integration test |
| 8 | Worker + legacy cleanup | NATS subscriber, debouncer, binary rewired, legacy deleted |
| 9 | API handlers | `GET /risks`, `GET /risks/{id}`, `POST /risks/{id}/...` |
| 10 | Frontend: types, API client, hooks | TypeScript types + TanStack Query hooks |
| 11 | Frontend: pages + dashboard card | Risks list, detail page, Top Risks card |
| 12 | Live verification | End-to-end scan → cluster flow validated |

---

## Pre-implementation checklist

- [ ] Read the spec: `docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md`
- [ ] Confirm local infrastructure is running (`./scripts/local-bringup.sh`)
- [ ] Confirm you are on a feature branch (not main)
- [ ] Confirm `go test ./...` passes before starting

---

## Chunk 1: SQL migration

**Files:**
- Create: `migrations/023_risk_clusters.up.sql`
- Create: `migrations/023_risk_clusters.down.sql`

### Task 1.1: Write the up migration

- [ ] **Step 1: Create migration file**

Create `migrations/023_risk_clusters.up.sql` with the full schema from design spec §4.1 and §4.2. Paste this exact content:

```sql
-- Risk Correlation MVP: risk.* schema, findings.function_name column
-- See docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md §4

CREATE SCHEMA IF NOT EXISTS risk;

-- ---------------------------------------------------------------------------
-- risk.correlation_runs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.correlation_runs (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    trigger              TEXT NOT NULL,
    triggered_by_scan    UUID,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at          TIMESTAMPTZ,
    status               TEXT NOT NULL DEFAULT 'running',
    error_message        TEXT,
    clusters_touched     INTEGER NOT NULL DEFAULT 0,
    clusters_created     INTEGER NOT NULL DEFAULT 0,
    clusters_resolved    INTEGER NOT NULL DEFAULT 0,
    findings_processed   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_risk_runs_project
    ON risk.correlation_runs(project_id, started_at DESC);
ALTER TABLE risk.correlation_runs ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS correlation_runs_isolation ON risk.correlation_runs;
CREATE POLICY correlation_runs_isolation ON risk.correlation_runs
    USING (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.clusters
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.clusters (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES core.projects(id) ON DELETE CASCADE,
    fingerprint          TEXT NOT NULL,
    fingerprint_version  SMALLINT NOT NULL DEFAULT 1,
    fingerprint_kind     TEXT NOT NULL,
    title                TEXT NOT NULL,
    vuln_class           TEXT NOT NULL,
    cwe_id               INTEGER,
    owasp_category       TEXT,
    language             TEXT,
    canonical_route      TEXT,
    canonical_param      TEXT,
    http_method          TEXT,
    file_path            TEXT,
    enclosing_method     TEXT,
    location_group       TEXT,
    severity             TEXT NOT NULL,
    risk_score           INTEGER NOT NULL DEFAULT 0
        CHECK (risk_score BETWEEN 0 AND 100),
    exposure             TEXT NOT NULL DEFAULT 'unknown',
    status               TEXT NOT NULL DEFAULT 'active',
    missing_run_count    INTEGER NOT NULL DEFAULT 0,
    finding_count        INTEGER NOT NULL DEFAULT 0,
    surface_count        INTEGER NOT NULL DEFAULT 0,
    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_run_id          UUID REFERENCES risk.correlation_runs(id) ON DELETE SET NULL,
    resolved_at          TIMESTAMPTZ,
    resolved_by          UUID REFERENCES core.users(id) ON DELETE SET NULL,
    resolution_reason    TEXT,
    muted_until          TIMESTAMPTZ,
    CONSTRAINT clusters_project_fp_unique
        UNIQUE (project_id, fingerprint_version, fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_risk_clusters_project_score
    ON risk.clusters(project_id, risk_score DESC, status);
CREATE INDEX IF NOT EXISTS idx_risk_clusters_vuln_class
    ON risk.clusters(project_id, vuln_class);
CREATE INDEX IF NOT EXISTS idx_risk_clusters_status
    ON risk.clusters(project_id, status);

ALTER TABLE risk.clusters ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS clusters_isolation ON risk.clusters;
CREATE POLICY clusters_isolation ON risk.clusters
    USING (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.cluster_findings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.cluster_findings (
    cluster_id           UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    finding_id           UUID NOT NULL REFERENCES findings.findings(id) ON DELETE CASCADE,
    role                 TEXT NOT NULL,
    first_seen_run_id    UUID REFERENCES risk.correlation_runs(id) ON DELETE SET NULL,
    last_seen_run_id     UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    added_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cluster_id, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_cluster_findings_finding
    ON risk.cluster_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_cluster_findings_last_seen_run
    ON risk.cluster_findings(last_seen_run_id);

ALTER TABLE risk.cluster_findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cluster_findings_isolation ON risk.cluster_findings;
CREATE POLICY cluster_findings_isolation ON risk.cluster_findings
    USING (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.cluster_evidence
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.cluster_evidence (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id           UUID NOT NULL REFERENCES risk.clusters(id) ON DELETE CASCADE,
    category             TEXT NOT NULL
        CHECK (category IN ('score_base', 'score_boost', 'score_penalty', 'link', 'context')),
    code                 TEXT NOT NULL,
    label                TEXT NOT NULL,
    weight               INTEGER,
    ref_type             TEXT,
    ref_id               TEXT,
    sort_order           INTEGER NOT NULL DEFAULT 0,
    source_run_id        UUID NOT NULL REFERENCES risk.correlation_runs(id) ON DELETE CASCADE,
    metadata             JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cluster_evidence_cluster
    ON risk.cluster_evidence(cluster_id, sort_order);
CREATE INDEX IF NOT EXISTS idx_cluster_evidence_run
    ON risk.cluster_evidence(source_run_id);

ALTER TABLE risk.cluster_evidence ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cluster_evidence_isolation ON risk.cluster_evidence;
CREATE POLICY cluster_evidence_isolation ON risk.cluster_evidence
    USING (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (cluster_id IN (
        SELECT c.id FROM risk.clusters c
         JOIN core.projects p ON p.id = c.project_id
         WHERE p.org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- risk.cluster_relations
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk.cluster_relations (
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
CREATE INDEX IF NOT EXISTS idx_cluster_relations_source
    ON risk.cluster_relations(source_cluster_id);
CREATE INDEX IF NOT EXISTS idx_cluster_relations_target
    ON risk.cluster_relations(target_cluster_id);
CREATE INDEX IF NOT EXISTS idx_cluster_relations_project
    ON risk.cluster_relations(project_id, relation_type);

ALTER TABLE risk.cluster_relations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS cluster_relations_isolation ON risk.cluster_relations;
CREATE POLICY cluster_relations_isolation ON risk.cluster_relations
    USING (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ))
    WITH CHECK (project_id IN (
        SELECT id FROM core.projects
         WHERE org_id = current_setting('app.org_id', true)::uuid
    ));

-- ---------------------------------------------------------------------------
-- findings.function_name: enables SAST location_group "m:" branch
-- ---------------------------------------------------------------------------
ALTER TABLE findings.findings
    ADD COLUMN IF NOT EXISTS function_name TEXT;
```

- [ ] **Step 2: Create the down migration**

Create `migrations/023_risk_clusters.down.sql`:

```sql
ALTER TABLE findings.findings DROP COLUMN IF EXISTS function_name;
DROP TABLE IF EXISTS risk.cluster_relations;
DROP TABLE IF EXISTS risk.cluster_evidence;
DROP TABLE IF EXISTS risk.cluster_findings;
DROP TABLE IF EXISTS risk.clusters;
DROP TABLE IF EXISTS risk.correlation_runs;
DROP SCHEMA IF EXISTS risk;
```

- [ ] **Step 3: Apply the up migration locally**

Run:
```bash
psql -U sentinelcore -d sentinelcore -f migrations/023_risk_clusters.up.sql
```

Expected output: `CREATE SCHEMA`, `CREATE TABLE` (×5), `CREATE INDEX` (×9), `ALTER TABLE` (×5 enable RLS + 1 add column), `CREATE POLICY` (×5). No errors.

- [ ] **Step 4: Verify schema exists**

Run:
```bash
psql -U sentinelcore -d sentinelcore -c "\dt risk.*"
```

Expected: 5 tables (correlation_runs, clusters, cluster_findings, cluster_evidence, cluster_relations).

Run:
```bash
psql -U sentinelcore -d sentinelcore -c "\d findings.findings" | grep function_name
```

Expected: `function_name | text`.

- [ ] **Step 5: Test the down migration (safety check)**

Run:
```bash
psql -U sentinelcore -d sentinelcore -f migrations/023_risk_clusters.down.sql
psql -U sentinelcore -d sentinelcore -c "\dt risk.*"
```

Expected: "Did not find any relation" (schema is gone).

Re-apply the up migration to restore state:
```bash
psql -U sentinelcore -d sentinelcore -f migrations/023_risk_clusters.up.sql
```

- [ ] **Step 6: Commit**

```bash
git add migrations/023_risk_clusters.up.sql migrations/023_risk_clusters.down.sql
git commit -m "feat(risk): schema for risk clusters, findings, evidence, relations

Adds risk.* schema with:
- risk.correlation_runs (observability + debouncing)
- risk.clusters (stable-identity clusters via fingerprint_version + fingerprint)
- risk.cluster_findings (PK only, no UNIQUE(finding_id))
- risk.cluster_evidence (score_base/boost/penalty/link/context)
- risk.cluster_relations (runtime_confirmation | same_cwe | related_surface)

Also adds findings.function_name column for SAST location_group 'm:' branch.

All tables have RLS policies isolating by project_id -> org_id via core.projects.

Spec: docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md"
```

---

## Chunk 2: Go package scaffolding

**Files:**
- Create: `internal/risk/types.go`
- Create: `internal/risk/store.go` (skeleton only)
- Create: `internal/risk/doc.go`

### Task 2.1: Package doc and types

- [ ] **Step 1: Create `internal/risk/doc.go`**

```go
// Package risk implements the SentinelCore risk correlation engine.
//
// The risk package groups related findings into persistent, explainable
// "risk clusters" that survive across scan re-runs. It subscribes to
// scan completion events, debounces per project, and rebuilds the cluster
// view in a single database transaction guarded by an advisory lock.
//
// See docs/superpowers/specs/2026-04-10-risk-correlation-mvp-design.md
// for the full design rationale.
package risk
```

- [ ] **Step 2: Create `internal/risk/types.go`**

```go
package risk

import (
	"time"
)

// FingerprintVersion is the current fingerprint schema version. Bump this
// constant when fingerprint inputs or normalization rules change. Old
// clusters with the previous version continue to coexist via the
// UNIQUE (project_id, fingerprint_version, fingerprint) constraint.
const FingerprintVersion int16 = 1

// Finding is the minimal shape of a SentinelCore finding that the risk
// correlator needs. It is populated from findings.findings via the store.
type Finding struct {
	ID              string
	ProjectID       string
	ScanJobID       string
	Type            string // 'sast' | 'dast' | 'sca'
	RuleID          string
	Title           string
	CWEID           int
	OWASPCategory   string
	Severity        string
	Confidence      string
	Language        string // SAST only
	FilePath        string // SAST only
	LineStart       int    // SAST only
	FunctionName    string // SAST only; may be empty
	URL             string // DAST only
	HTTPMethod      string // DAST only
	Parameter       string // DAST only
}

// Cluster is an in-memory representation of risk.clusters.
type Cluster struct {
	ID                 string
	ProjectID          string
	Fingerprint        string
	FingerprintVersion int16
	FingerprintKind    string // 'dast_route' | 'sast_file'
	Title              string
	VulnClass          string
	CWEID              int
	OWASPCategory      string
	Language           string
	CanonicalRoute     string
	CanonicalParam     string
	HTTPMethod         string
	FilePath           string
	EnclosingMethod    string
	LocationGroup      string
	Severity           string
	RiskScore          int
	Exposure           string
	Status             string
	MissingRunCount    int
	FindingCount       int
	SurfaceCount       int
	FirstSeenAt        time.Time
	LastSeenAt         time.Time
	LastRunID          string
}

// ClusterFinding is a row in risk.cluster_findings.
type ClusterFinding struct {
	ClusterID       string
	FindingID       string
	Role            string
	FirstSeenRunID  string
	LastSeenRunID   string
}

// Evidence is a row in risk.cluster_evidence.
type Evidence struct {
	ID          string
	ClusterID   string
	Category    string // 'score_base' | 'score_boost' | 'score_penalty' | 'link' | 'context'
	Code        string // 'SEVERITY_BASE' | 'RUNTIME_CONFIRMED' | ...
	Label       string
	Weight      *int // nullable for link/context rows
	RefType     string
	RefID       string
	SortOrder   int
	SourceRunID string
	Metadata    map[string]any
}

// Relation is a row in risk.cluster_relations.
type Relation struct {
	ID              string
	ProjectID       string
	SourceClusterID string
	TargetClusterID string
	RelationType    string // 'runtime_confirmation' | 'same_cwe' | 'related_surface'
	Confidence      float64
	Rationale       string
	LastLinkedRunID string
}

// Run is a row in risk.correlation_runs.
type Run struct {
	ID                 string
	ProjectID          string
	Trigger            string // 'scan_completed' | 'manual' | 'retry'
	TriggeredByScan    *string
	StartedAt          time.Time
	FinishedAt         *time.Time
	Status             string // 'running' | 'ok' | 'error'
	ErrorMessage       string
	ClustersTouched    int
	ClustersCreated    int
	ClustersResolved   int
	FindingsProcessed  int
}

// SurfaceEntry is the minimal surface-entry shape needed for scoring.
// Populated from scans.surface_entries via the store.
type SurfaceEntry struct {
	ID       string
	URL      string
	Method   string
	Exposure string // 'public' | 'authenticated' | 'both' | 'unknown'
}
```

- [ ] **Step 3: Create `internal/risk/store.go` skeleton**

```go
package risk

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the persistence layer for the risk package. All PostgreSQL
// interactions go through this interface so the correlator can be tested
// against a stub in unit tests and the real pool in integration tests.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a Store backed by the given pgx connection pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ErrNotFound is returned by Store lookups when no row matches.
var ErrNotFound = errors.New("risk: not found")

// The concrete store methods are implemented in Chunk 6. This skeleton
// exists so that earlier chunks can reference the Store type without
// introducing compile errors.
func (s *Store) ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}
```

- [ ] **Step 4: Verify the package builds**

Run:
```bash
go build ./internal/risk/
```

Expected: no output, exit code 0.

- [ ] **Step 5: Commit**

```bash
git add internal/risk/doc.go internal/risk/types.go internal/risk/store.go
git commit -m "feat(risk): scaffold internal/risk package

Adds package doc, core types (Finding, Cluster, ClusterFinding, Evidence,
Relation, Run, SurfaceEntry), and Store skeleton.

FingerprintVersion constant pinned at 1. Bumping this triggers coexist-
based migration via UNIQUE(project_id, fingerprint_version, fingerprint)."
```

---

## Chunk 3: Fingerprinting

**Files:**
- Create: `internal/risk/fingerprint.go`
- Create: `internal/risk/fingerprint_test.go`

### Task 3.1: Failing tests for route normalization

- [ ] **Step 1: Write `fingerprint_test.go` with route normalization tests**

```go
package risk

import "testing"

func TestNormalizeRoute(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain path", "/users", "/users"},
		{"lowercase", "/Users/Foo", "/users/foo"},
		{"strip scheme host", "https://api.example.com/users", "/users"},
		{"strip query", "/users?id=1&filter=x", "/users"},
		{"strip trailing slash", "/users/", "/users"},
		{"preserve root", "/", "/"},
		{"numeric segment", "/users/42", "/users/:num"},
		{"uuid segment", "/users/550e8400-e29b-41d4-a716-446655440000", "/users/:uuid"},
		{"long alnum token", "/download/abc123DEF456ghi789jkl", "/download/:token"},
		{"short literal preserved", "/users/admin", "/users/admin"},
		{"positional params", "/users/1/orders/2", "/users/:num/orders/:num"},
		{"url-decoded", "/users/john%20doe", "/users/john doe"},
		{"mixed case host stripped", "https://API.example.com:8443/Users/", "/users"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := NormalizeRoute(c.in)
			if got != c.want {
				t.Errorf("NormalizeRoute(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestNormalizeParam(t *testing.T) {
	cases := map[string]string{
		"":         "",
		"UserID":   "userid",
		"  id  ":   "id",
		"X-Auth":   "x-auth",
	}
	for in, want := range cases {
		if got := NormalizeParam(in); got != want {
			t.Errorf("NormalizeParam(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeFilePath(t *testing.T) {
	cases := map[string]string{
		"src/Foo.java":       "src/Foo.java",
		"./src/Foo.java":     "src/Foo.java",
		`src\Foo.java`:       "src/Foo.java",
		`.\src\Foo.java`:     "src/Foo.java",
	}
	for in, want := range cases {
		if got := NormalizeFilePath(in); got != want {
			t.Errorf("NormalizeFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:
```bash
go test ./internal/risk/ -run TestNormalize -v
```

Expected: FAIL, "undefined: NormalizeRoute" etc.

### Task 3.2: Implement normalization

- [ ] **Step 3: Create `internal/risk/fingerprint.go` with normalization**

```go
package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	uuidRegex  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	numRegex   = regexp.MustCompile(`^[0-9]+$`)
	alphaRegex = regexp.MustCompile(`[a-zA-Z]`)
	digitRegex = regexp.MustCompile(`[0-9]`)
)

// NormalizeRoute converts a raw URL (or path) into the canonical form used
// for DAST cluster fingerprinting. Applied in order:
//  1. strip scheme + host
//  2. strip query string
//  3. URL-decode path segments
//  4. lowercase the path
//  5. parameterize numeric / uuid / long-alnum segments positionally
//  6. rejoin, strip trailing slash except for root
func NormalizeRoute(raw string) string {
	if raw == "" {
		return ""
	}
	raw = strings.TrimSpace(raw)

	// Step 1+2: parse and keep only the path.
	path := raw
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			path = u.Path
		}
	} else if idx := strings.Index(raw, "?"); idx >= 0 {
		path = raw[:idx]
	}
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	if path == "" {
		path = "/"
	}

	// Step 3: URL-decode.
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}

	// Step 4: lowercase.
	path = strings.ToLower(path)

	// Step 5: parameterize segments.
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		segments[i] = classifySegment(seg)
	}
	path = strings.Join(segments, "/")

	// Step 6: strip trailing slash (but not for root).
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = strings.TrimRight(path, "/")
	}
	if path == "" {
		path = "/"
	}
	return path
}

// classifySegment replaces a single path segment with a parameter token if
// it matches the numeric / uuid / long-alnum patterns.
func classifySegment(seg string) string {
	if numRegex.MatchString(seg) {
		return ":num"
	}
	if uuidRegex.MatchString(seg) {
		return ":uuid"
	}
	if len(seg) > 16 && alphaRegex.MatchString(seg) && digitRegex.MatchString(seg) {
		return ":token"
	}
	return seg
}

// NormalizeParam lowercases and trims a DAST parameter name.
func NormalizeParam(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// NormalizeFilePath canonicalizes a SAST file path: forward slashes, no
// leading "./", no absolute prefixes.
func NormalizeFilePath(path string) string {
	path = strings.ReplaceAll(path, `\`, "/")
	path = strings.TrimPrefix(path, "./")
	return path
}

// LocationGroup computes the SAST discriminator inside a file. Prefers the
// enclosing method name; falls back to a line-bucketed + CWE-keyed form.
// See spec §5.2.
func LocationGroup(functionName string, lineStart, cweID int) string {
	if fn := strings.TrimSpace(functionName); fn != "" {
		return "m:" + fn
	}
	return fmt.Sprintf("b:%d:cwe_%d", lineStart/25, cweID)
}

// ComputeFingerprint returns (fingerprint, kind, version) for a finding.
// The version is not included in the hash — it lives on the cluster row
// as an administrative scope.
func ComputeFingerprint(f *Finding) (fp string, kind string, version int16) {
	switch f.Type {
	case "dast":
		input := []string{
			f.ProjectID,
			"dast",
			strconv.Itoa(f.CWEID),
			strings.ToUpper(f.HTTPMethod),
			NormalizeRoute(f.URL),
			NormalizeParam(f.Parameter),
		}
		return sha256hex(strings.Join(input, "|")), "dast_route", FingerprintVersion
	case "sast":
		input := []string{
			f.ProjectID,
			"sast",
			strconv.Itoa(f.CWEID),
			strings.ToLower(f.Language),
			NormalizeFilePath(f.FilePath),
			LocationGroup(f.FunctionName, f.LineStart, f.CWEID),
		}
		return sha256hex(strings.Join(input, "|")), "sast_file", FingerprintVersion
	}
	return "", "", 0
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
```

- [ ] **Step 4: Run normalization tests**

Run:
```bash
go test ./internal/risk/ -run TestNormalize -v
```

Expected: PASS for all subtests.

### Task 3.3: Location group and fingerprint tests

- [ ] **Step 5: Append location_group + fingerprint tests**

Append to `internal/risk/fingerprint_test.go`:

```go
func TestLocationGroup_PrefersMethod(t *testing.T) {
	got := LocationGroup("findUser", 42, 89)
	want := "m:findUser"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLocationGroup_BucketFallback(t *testing.T) {
	cases := []struct {
		function string
		line     int
		cwe      int
		want     string
	}{
		{"", 0, 89, "b:0:cwe_89"},
		{"", 24, 89, "b:0:cwe_89"},
		{"", 25, 89, "b:1:cwe_89"},
		{"", 200, 22, "b:8:cwe_22"},
		{"   ", 75, 89, "b:3:cwe_89"}, // whitespace-only treated as empty
	}
	for _, c := range cases {
		got := LocationGroup(c.function, c.line, c.cwe)
		if got != c.want {
			t.Errorf("LocationGroup(%q, %d, %d) = %q, want %q",
				c.function, c.line, c.cwe, got, c.want)
		}
	}
}

func TestComputeFingerprint_DAST(t *testing.T) {
	f := &Finding{
		Type:       "dast",
		ProjectID:  "proj-1",
		CWEID:      89,
		HTTPMethod: "POST",
		URL:        "https://api.example.com/api/users/42",
		Parameter:  "ID",
	}
	fp, kind, version := ComputeFingerprint(f)
	if kind != "dast_route" {
		t.Errorf("kind = %q, want dast_route", kind)
	}
	if version != FingerprintVersion {
		t.Errorf("version = %d, want %d", version, FingerprintVersion)
	}
	if fp == "" || len(fp) != 64 {
		t.Errorf("fingerprint = %q, want 64-char hex", fp)
	}

	// Deterministic: same input → same fingerprint.
	fp2, _, _ := ComputeFingerprint(f)
	if fp != fp2 {
		t.Errorf("fingerprint not deterministic: %q vs %q", fp, fp2)
	}

	// Different method → different fingerprint.
	f.HTTPMethod = "GET"
	fp3, _, _ := ComputeFingerprint(f)
	if fp == fp3 {
		t.Error("GET and POST on same route produced same fingerprint")
	}
}

func TestComputeFingerprint_SAST(t *testing.T) {
	f := &Finding{
		Type:         "sast",
		ProjectID:    "proj-1",
		CWEID:        89,
		Language:     "java",
		FilePath:     "src/main/UserRepo.java",
		LineStart:    42,
		FunctionName: "findUser",
	}
	fp, kind, _ := ComputeFingerprint(f)
	if kind != "sast_file" {
		t.Errorf("kind = %q, want sast_file", kind)
	}
	if fp == "" {
		t.Error("empty fingerprint")
	}

	// Different method → different fingerprint.
	f.FunctionName = "updateUser"
	fp2, _, _ := ComputeFingerprint(f)
	if fp == fp2 {
		t.Error("different methods in same file produced same fingerprint")
	}

	// No method → fallback bucket form.
	f.FunctionName = ""
	f.LineStart = 10
	fpBucket, _, _ := ComputeFingerprint(f)
	f.LineStart = 20
	fpBucket2, _, _ := ComputeFingerprint(f)
	if fpBucket != fpBucket2 {
		t.Error("lines 10 and 20 (same bucket) produced different fingerprints")
	}
	f.LineStart = 30
	fpBucket3, _, _ := ComputeFingerprint(f)
	if fpBucket == fpBucket3 {
		t.Error("lines 20 and 30 (different buckets) produced same fingerprint")
	}
}

func TestComputeFingerprint_PolyglotProject(t *testing.T) {
	base := Finding{
		Type:      "sast",
		ProjectID: "proj-1",
		CWEID:     89,
		FilePath:  "src/db.ext",
		LineStart: 10,
	}
	java := base
	java.Language = "java"
	python := base
	python.Language = "python"

	fpJava, _, _ := ComputeFingerprint(&java)
	fpPython, _, _ := ComputeFingerprint(&python)
	if fpJava == fpPython {
		t.Error("polyglot project fingerprints collided across languages")
	}
}
```

- [ ] **Step 6: Run all fingerprint tests**

Run:
```bash
go test ./internal/risk/ -v
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/risk/fingerprint.go internal/risk/fingerprint_test.go
git commit -m "feat(risk): fingerprinting and route/path normalization

Pure-logic helpers for the risk correlator:
- NormalizeRoute: scheme/host strip, query strip, URL-decode, lowercase,
  segment parameterization (:num, :uuid, :token), trailing slash handling
- NormalizeParam, NormalizeFilePath: trivial canonicalization
- LocationGroup: prefers m:<method>, falls back to b:<bucket>:cwe_<N>
- ComputeFingerprint: SHA-256 over DAST or SAST canonical tuple

Version is held separately on the cluster row; not part of the hash.
Tests cover polyglot projects, migration stability, positional params."
```

---

## Chunk 4: Scorer

**Files:**
- Create: `internal/risk/scorer.go`
- Create: `internal/risk/scorer_test.go`

### Task 4.1: Failing tests for base score

- [ ] **Step 1: Create `internal/risk/scorer_test.go`**

```go
package risk

import "testing"

func TestSeverityBase(t *testing.T) {
	cases := map[string]int{
		"critical": 60,
		"high":     45,
		"medium":   30,
		"low":      15,
		"info":     5,
		"unknown":  0,
		"":         0,
	}
	for sev, want := range cases {
		if got := SeverityBase(sev); got != want {
			t.Errorf("SeverityBase(%q) = %d, want %d", sev, got, want)
		}
	}
}

func TestComputeScore_BaseOnly(t *testing.T) {
	got := ComputeScore(ScoreInputs{Severity: "high"})
	if got.Total != 45 {
		t.Errorf("base-only total = %d, want 45", got.Total)
	}
	if len(got.Evidence) != 1 {
		t.Fatalf("expected 1 evidence row (base), got %d", len(got.Evidence))
	}
	if got.Evidence[0].Category != "score_base" {
		t.Errorf("first evidence category = %q, want score_base", got.Evidence[0].Category)
	}
	if got.Evidence[0].Code != "SEVERITY_BASE" {
		t.Errorf("first evidence code = %q, want SEVERITY_BASE", got.Evidence[0].Code)
	}
	if got.Evidence[0].Weight == nil || *got.Evidence[0].Weight != 45 {
		t.Errorf("first evidence weight = %v, want 45", got.Evidence[0].Weight)
	}
	if got.Evidence[0].SortOrder != 0 {
		t.Errorf("first evidence sort_order = %d, want 0", got.Evidence[0].SortOrder)
	}
}

func TestComputeScore_RuntimeConfirmed(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:          "critical",
		RuntimeConfirmed:  true,
	})
	if got.Total != 60+20 {
		t.Errorf("critical + runtime = %d, want 80", got.Total)
	}
	if !hasEvidenceCode(got.Evidence, "RUNTIME_CONFIRMED") {
		t.Error("missing RUNTIME_CONFIRMED evidence")
	}
}

func TestComputeScore_PublicExposure(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:       "medium",
		PublicExposure: true,
		PublicSurfaceURL: "/api/users",
	})
	if got.Total != 30+15 {
		t.Errorf("medium + public = %d, want 45", got.Total)
	}
	if !hasEvidenceCode(got.Evidence, "PUBLIC_EXPOSURE") {
		t.Error("missing PUBLIC_EXPOSURE evidence")
	}
}

func TestComputeScore_SameRouteSameParamDASTOnly(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:        "high",
		FingerprintKind: "dast_route",
		SameRoute:       true,
		SameParam:       true,
		CanonicalRoute:  "/api/users",
		CanonicalParam:  "id",
	})
	if got.Total != 45+5+5 {
		t.Errorf("high + route + param = %d, want 55", got.Total)
	}
	if !hasEvidenceCode(got.Evidence, "SAME_ROUTE") {
		t.Error("missing SAME_ROUTE evidence")
	}
	if !hasEvidenceCode(got.Evidence, "SAME_PARAM") {
		t.Error("missing SAME_PARAM evidence")
	}
}

func TestComputeScore_SameRouteIgnoredForSAST(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:        "high",
		FingerprintKind: "sast_file",
		SameRoute:       true, // should be ignored
		SameParam:       true, // should be ignored
	})
	if got.Total != 45 {
		t.Errorf("SAST cluster should ignore route/param boosts, got %d", got.Total)
	}
	if hasEvidenceCode(got.Evidence, "SAME_ROUTE") {
		t.Error("SAST cluster should not emit SAME_ROUTE evidence")
	}
}

func TestComputeScore_MaxReachable_CapAt100(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:         "critical",
		RuntimeConfirmed: true,
		PublicExposure:   true,
		FingerprintKind:  "dast_route",
		SameRoute:        true,
		SameParam:        true,
	})
	if got.Total != 100 {
		t.Errorf("fully boosted critical = %d, want 100 (capped)", got.Total)
	}
}

func TestComputeScore_EvidenceSortOrder(t *testing.T) {
	got := ComputeScore(ScoreInputs{
		Severity:         "critical",
		RuntimeConfirmed: true,
		PublicExposure:   true,
		FingerprintKind:  "dast_route",
		SameRoute:        true,
		SameParam:        true,
	})
	// Evidence must be in sort_order: base=0, runtime=10, public=20, route=30, param=40
	wantCodes := []string{
		"SEVERITY_BASE", "RUNTIME_CONFIRMED", "PUBLIC_EXPOSURE",
		"SAME_ROUTE", "SAME_PARAM",
	}
	if len(got.Evidence) != len(wantCodes) {
		t.Fatalf("got %d evidence rows, want %d", len(got.Evidence), len(wantCodes))
	}
	for i, want := range wantCodes {
		if got.Evidence[i].Code != want {
			t.Errorf("evidence[%d].Code = %q, want %q", i, got.Evidence[i].Code, want)
		}
		if got.Evidence[i].SortOrder != i*10 {
			t.Errorf("evidence[%d].SortOrder = %d, want %d", i, got.Evidence[i].SortOrder, i*10)
		}
	}
}

func hasEvidenceCode(rows []Evidence, code string) bool {
	for _, e := range rows {
		if e.Code == code {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run to verify failures**

Run:
```bash
go test ./internal/risk/ -run TestComputeScore -v
```

Expected: FAIL with "undefined: ComputeScore" etc.

### Task 4.2: Implement scorer

- [ ] **Step 3: Create `internal/risk/scorer.go`**

```go
package risk

import "fmt"

// ScoreInputs bundles everything the scorer needs for a single cluster.
// The correlator populates it by inspecting cluster_findings, relations,
// and linked surface entries before calling ComputeScore.
type ScoreInputs struct {
	Severity         string
	FingerprintKind  string // 'sast_file' | 'dast_route'
	RuntimeConfirmed bool   // a runtime_confirmation relation with confidence >= 0.80 exists
	PublicExposure   bool   // any linked surface_entry has exposure='public'
	PublicSurfaceURL string // populated when PublicExposure is true
	SameRoute        bool   // DAST only: >1 findings share the cluster's canonical_route
	SameParam        bool   // DAST only: >1 findings share the cluster's canonical_param
	CanonicalRoute   string
	CanonicalParam   string
}

// ScoreResult is the deterministic output of ComputeScore. Total is the
// final risk_score (0..100). Evidence is ordered by SortOrder ascending
// and is suitable for direct insertion into risk.cluster_evidence.
type ScoreResult struct {
	Total    int
	Evidence []Evidence
}

// SeverityBase maps a severity label to the integer base contribution.
// Unknown severities return 0.
func SeverityBase(severity string) int {
	switch severity {
	case "critical":
		return 60
	case "high":
		return 45
	case "medium":
		return 30
	case "low":
		return 15
	case "info":
		return 5
	}
	return 0
}

// ComputeScore is the only scoring entry point. It is a pure function —
// no DB access, no side effects — so it is trivially testable and safe
// to call inside the correlator's transaction.
//
// The caller persists the returned Evidence rows with cluster_id and
// source_run_id filled in.
func ComputeScore(in ScoreInputs) ScoreResult {
	out := ScoreResult{Evidence: make([]Evidence, 0, 5)}

	// Base score — always emitted.
	base := SeverityBase(in.Severity)
	out.Total = base
	out.Evidence = append(out.Evidence, Evidence{
		Category:  "score_base",
		Code:      "SEVERITY_BASE",
		Label:     fmt.Sprintf("Base score from %s severity", in.Severity),
		Weight:    intPtr(base),
		SortOrder: 0,
		Metadata:  map[string]any{"severity": in.Severity},
	})

	// Runtime confirmation boost.
	if in.RuntimeConfirmed {
		out.Total += 20
		out.Evidence = append(out.Evidence, Evidence{
			Category:  "score_boost",
			Code:      "RUNTIME_CONFIRMED",
			Label:     "Confirmed at runtime by DAST",
			Weight:    intPtr(20),
			SortOrder: 10,
		})
	}

	// Public exposure boost.
	if in.PublicExposure {
		label := "Exposed on a public surface"
		if in.PublicSurfaceURL != "" {
			label = fmt.Sprintf("Exposed on public surface %s", in.PublicSurfaceURL)
		}
		out.Evidence = append(out.Evidence, Evidence{
			Category:  "score_boost",
			Code:      "PUBLIC_EXPOSURE",
			Label:     label,
			Weight:    intPtr(15),
			SortOrder: 20,
			RefType:   "surface_entry",
			Metadata:  map[string]any{"surface_url": in.PublicSurfaceURL},
		})
		out.Total += 15
	}

	// Same route/param — DAST clusters only.
	if in.FingerprintKind == "dast_route" {
		if in.SameRoute {
			out.Total += 5
			out.Evidence = append(out.Evidence, Evidence{
				Category:  "score_boost",
				Code:      "SAME_ROUTE",
				Label:     fmt.Sprintf("Multiple findings on route %s", in.CanonicalRoute),
				Weight:    intPtr(5),
				SortOrder: 30,
			})
		}
		if in.SameParam {
			out.Total += 5
			out.Evidence = append(out.Evidence, Evidence{
				Category:  "score_boost",
				Code:      "SAME_PARAM",
				Label:     fmt.Sprintf("Multiple findings on param %s", in.CanonicalParam),
				Weight:    intPtr(5),
				SortOrder: 40,
			})
		}
	}

	// Cap at 100.
	if out.Total > 100 {
		out.Total = 100
	}
	return out
}

func intPtr(i int) *int { return &i }
```

- [ ] **Step 4: Run scorer tests**

Run:
```bash
go test ./internal/risk/ -run "TestSeverityBase|TestComputeScore" -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/risk/scorer.go internal/risk/scorer_test.go
git commit -m "feat(risk): deterministic scorer with base + 4 explainable boosts

Pure function ComputeScore returns the total risk_score (0..100, capped)
plus an ordered list of Evidence rows matching the categories and codes
defined in the spec:

- SEVERITY_BASE   (always, sort_order=0):  critical=60|high=45|medium=30|low=15|info=5
- RUNTIME_CONFIRMED (sort_order=10):       +20 when a runtime_confirmation relation exists
- PUBLIC_EXPOSURE   (sort_order=20):       +15 when any linked surface is public
- SAME_ROUTE        (sort_order=30, DAST): +5 when >1 findings share the route
- SAME_PARAM        (sort_order=40, DAST): +5 when >1 findings share the param

Route/param boosts are ignored for sast_file clusters. Cap applied once
at the end. No DB access; correlator persists the evidence rows."
```

---

## Chunk 5: Relations classifier

**Files:**
- Create: `internal/risk/relations.go`
- Create: `internal/risk/relations_test.go`

### Task 5.1: Failing tests

- [ ] **Step 1: Create `internal/risk/relations_test.go`**

```go
package risk

import "testing"

func TestClassifyRelation_RuntimeConfirmation_BaseConfidence(t *testing.T) {
	sast := &Cluster{ID: "a", FingerprintKind: "sast_file", CWEID: 89, VulnClass: "sql_injection"}
	dast := &Cluster{ID: "b", FingerprintKind: "dast_route", CWEID: 89, VulnClass: "sql_injection"}

	rt, conf, _ := ClassifyRelation(sast, dast, false)
	if rt != "runtime_confirmation" {
		t.Errorf("rt = %q, want runtime_confirmation", rt)
	}
	if conf != 0.80 {
		t.Errorf("base confidence = %v, want 0.80", conf)
	}
}

func TestClassifyRelation_RuntimeConfirmation_OWASPBonus(t *testing.T) {
	sast := &Cluster{FingerprintKind: "sast_file", CWEID: 89, OWASPCategory: "A03:2021"}
	dast := &Cluster{FingerprintKind: "dast_route", CWEID: 89, OWASPCategory: "A03:2021"}

	_, conf, _ := ClassifyRelation(sast, dast, false)
	if conf != 0.90 {
		t.Errorf("confidence with OWASP match = %v, want 0.90", conf)
	}
}

func TestClassifyRelation_RuntimeConfirmation_NoOWASPBonus_Empty(t *testing.T) {
	sast := &Cluster{FingerprintKind: "sast_file", CWEID: 89, OWASPCategory: ""}
	dast := &Cluster{FingerprintKind: "dast_route", CWEID: 89, OWASPCategory: ""}

	_, conf, _ := ClassifyRelation(sast, dast, false)
	if conf != 0.80 {
		t.Errorf("empty OWASP shouldn't trigger bonus, got %v", conf)
	}
}

func TestClassifyRelation_RuntimeConfirmation_NoOWASPBonus_Mismatch(t *testing.T) {
	sast := &Cluster{FingerprintKind: "sast_file", CWEID: 89, OWASPCategory: "A03:2021"}
	dast := &Cluster{FingerprintKind: "dast_route", CWEID: 89, OWASPCategory: "A01:2021"}

	_, conf, _ := ClassifyRelation(sast, dast, false)
	if conf != 0.80 {
		t.Errorf("mismatched OWASP shouldn't bonus, got %v", conf)
	}
}

func TestClassifyRelation_SameCWE(t *testing.T) {
	a := &Cluster{FingerprintKind: "sast_file", CWEID: 89}
	b := &Cluster{FingerprintKind: "sast_file", CWEID: 89}

	rt, conf, _ := ClassifyRelation(a, b, false)
	if rt != "same_cwe" || conf != 0.30 {
		t.Errorf("same_cwe: got (%q, %v), want (same_cwe, 0.30)", rt, conf)
	}
}

func TestClassifyRelation_RelatedSurface(t *testing.T) {
	a := &Cluster{FingerprintKind: "dast_route", CWEID: 89}
	b := &Cluster{FingerprintKind: "dast_route", CWEID: 22}

	// With sharesSurface = true
	rt, conf, _ := ClassifyRelation(a, b, true)
	if rt != "related_surface" || conf != 0.60 {
		t.Errorf("related_surface: got (%q, %v), want (related_surface, 0.60)", rt, conf)
	}
}

func TestClassifyRelation_NoRelation(t *testing.T) {
	a := &Cluster{FingerprintKind: "sast_file", CWEID: 89}
	b := &Cluster{FingerprintKind: "dast_route", CWEID: 22} // different CWE

	rt, _, _ := ClassifyRelation(a, b, false)
	if rt != "" {
		t.Errorf("unrelated clusters produced relation %q", rt)
	}
}

func TestCanonicalizePair(t *testing.T) {
	// Smaller UUID becomes source.
	src, tgt := CanonicalizePair("bbb", "aaa")
	if src != "aaa" || tgt != "bbb" {
		t.Errorf("got (%q, %q), want (aaa, bbb)", src, tgt)
	}
	src, tgt = CanonicalizePair("aaa", "bbb")
	if src != "aaa" || tgt != "bbb" {
		t.Errorf("already canonical: got (%q, %q)", src, tgt)
	}
}
```

- [ ] **Step 2: Run tests to verify failures**

Run:
```bash
go test ./internal/risk/ -run "TestClassifyRelation|TestCanonicalizePair" -v
```

Expected: FAIL with undefined symbols.

### Task 5.2: Implement classifier

- [ ] **Step 3: Create `internal/risk/relations.go`**

```go
package risk

import "fmt"

// ClassifyRelation returns the relation type, confidence, and rationale for
// a pair of clusters. Returns empty relType if the pair is unrelated.
//
// sharesSurface is a lookup the caller performs before invocation: it is
// true when both clusters are linked to at least one common surface_entry.
// The function itself does not query the database.
func ClassifyRelation(a, b *Cluster, sharesSurface bool) (relType string, confidence float64, rationale string) {
	// runtime_confirmation: SAST cluster + DAST cluster sharing a CWE.
	sastDast := (a.FingerprintKind == "sast_file" && b.FingerprintKind == "dast_route") ||
		(a.FingerprintKind == "dast_route" && b.FingerprintKind == "sast_file")
	if sastDast && a.CWEID != 0 && a.CWEID == b.CWEID {
		conf := 0.80
		if a.OWASPCategory != "" && a.OWASPCategory == b.OWASPCategory {
			conf += 0.10
		}
		if conf > 1.00 {
			conf = 1.00
		}
		return "runtime_confirmation", conf,
			fmt.Sprintf("SAST and DAST both detected CWE-%d (%s)", a.CWEID, nonEmpty(a.VulnClass, b.VulnClass))
	}

	// same_cwe: both same kind, same CWE (weaker signal).
	if a.FingerprintKind == b.FingerprintKind && a.CWEID != 0 && a.CWEID == b.CWEID {
		return "same_cwe", 0.30,
			fmt.Sprintf("Same vulnerability class (CWE-%d)", a.CWEID)
	}

	// related_surface: two DAST clusters touching the same surface entry.
	if a.FingerprintKind == "dast_route" && b.FingerprintKind == "dast_route" && sharesSurface {
		return "related_surface", 0.60, "Both clusters touch the same surface entry"
	}

	return "", 0, ""
}

// CanonicalizePair orders a pair of cluster IDs so the smaller is always
// the source. This satisfies the UNIQUE(source_cluster_id, target_cluster_id,
// relation_type) constraint without requiring the caller to remember which
// direction was previously inserted.
func CanonicalizePair(a, b string) (source, target string) {
	if a < b {
		return a, b
	}
	return b, a
}

// BoostThreshold is the minimum confidence at which a runtime_confirmation
// relation contributes the +20 RUNTIME_CONFIRMED score boost.
const BoostThreshold = 0.80

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
```

- [ ] **Step 4: Run relations tests**

Run:
```bash
go test ./internal/risk/ -run "TestClassifyRelation|TestCanonicalizePair" -v
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/risk/relations.go internal/risk/relations_test.go
git commit -m "feat(risk): deterministic cluster relation classifier

ClassifyRelation is a pure function that returns (relation_type,
confidence, rationale) for a pair of clusters:

- runtime_confirmation: SAST+DAST same CWE (base 0.80, +0.10 if OWASP match)
- same_cwe: same kind + same CWE (0.30, informational only)
- related_surface: two DAST clusters sharing a surface entry (0.60, info)

CanonicalizePair orders (source, target) so the smaller UUID is always
source, satisfying the unique index without requiring the caller to
remember prior insertion direction.

BoostThreshold = 0.80: runtime_confirmation relations at or above this
confidence drive the +20 RUNTIME_CONFIRMED score boost in the scorer."
```

---

## Chunk 6: Store queries

**Files:**
- Modify: `internal/risk/store.go` (replace skeleton with full implementation)
- Create: `internal/risk/store_test.go`

### Task 6.1: Implement the store

- [ ] **Step 1: Replace `internal/risk/store.go` with the full implementation**

```go
package risk

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the persistence layer for the risk package.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

var ErrNotFound = errors.New("risk: not found")

// BeginTx starts a new transaction for a rebuild. Callers MUST either
// Commit or Rollback before returning.
func (s *Store) BeginTx(ctx context.Context) (pgx.Tx, error) {
	return s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
}

// AcquireProjectLock takes a per-project advisory lock for the duration of
// the transaction. Released automatically on COMMIT or ROLLBACK. Blocks
// until the lock is available; use pg_try_advisory_xact_lock if you want
// non-blocking semantics (not used in MVP — rebuilds serialize per project).
func (s *Store) AcquireProjectLock(ctx context.Context, tx pgx.Tx, projectID string) error {
	key := hashProjectLock(projectID)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, key)
	return err
}

// hashProjectLock derives a stable int64 key for pg_advisory_xact_lock
// from a project UUID string. FNV-1a is used for speed and determinism.
func hashProjectLock(projectID string) int64 {
	h := fnv.New64a()
	h.Write([]byte("risk-correlation:"))
	h.Write([]byte(projectID))
	return int64(h.Sum64())
}

// CreateRun inserts a new row into risk.correlation_runs and returns its id.
func (s *Store) CreateRun(ctx context.Context, tx pgx.Tx, projectID, trigger string, triggeredByScan *string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO risk.correlation_runs (project_id, trigger, triggered_by_scan, status)
		VALUES ($1, $2, $3, 'running')
		RETURNING id
	`, projectID, trigger, triggeredByScan).Scan(&id)
	return id, err
}

// FinishRun marks a run as successful and records counters.
func (s *Store) FinishRun(ctx context.Context, tx pgx.Tx, runID string, r Run) error {
	_, err := tx.Exec(ctx, `
		UPDATE risk.correlation_runs SET
			finished_at = now(),
			status = 'ok',
			clusters_touched = $2,
			clusters_created = $3,
			clusters_resolved = $4,
			findings_processed = $5
		WHERE id = $1
	`, runID, r.ClustersTouched, r.ClustersCreated, r.ClustersResolved, r.FindingsProcessed)
	return err
}

// FailRun marks a run as errored. Called from the worker's error path.
func (s *Store) FailRun(ctx context.Context, tx pgx.Tx, runID, errMsg string) error {
	_, err := tx.Exec(ctx, `
		UPDATE risk.correlation_runs SET
			finished_at = now(),
			status = 'error',
			error_message = $2
		WHERE id = $1
	`, runID, errMsg)
	return err
}

// LoadActiveFindings returns every finding belonging to the project that
// should participate in correlation. "Active" means: not suppressed, not
// resolved. The risk correlator treats these as the authoritative set.
func (s *Store) LoadActiveFindings(ctx context.Context, tx pgx.Tx, projectID string) ([]*Finding, error) {
	rows, err := tx.Query(ctx, `
		SELECT
			id, project_id, scan_job_id, finding_type,
			COALESCE(rule_id, ''),
			title,
			COALESCE(cwe_id, 0),
			COALESCE(owasp_category, ''),
			severity, confidence,
			COALESCE(file_path, ''),
			COALESCE(line_start, 0),
			COALESCE(function_name, ''),
			COALESCE(url, ''),
			COALESCE(http_method, ''),
			COALESCE(parameter, '')
		FROM findings.findings
		WHERE project_id = $1
		  AND status NOT IN ('suppressed', 'resolved', 'false_positive')
	`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Finding
	for rows.Next() {
		f := &Finding{}
		if err := rows.Scan(
			&f.ID, &f.ProjectID, &f.ScanJobID, &f.Type,
			&f.RuleID, &f.Title, &f.CWEID, &f.OWASPCategory,
			&f.Severity, &f.Confidence,
			&f.FilePath, &f.LineStart, &f.FunctionName,
			&f.URL, &f.HTTPMethod, &f.Parameter,
		); err != nil {
			return nil, err
		}
		// Language is derived from file extension or rule_id prefix.
		// For MVP, a simple mapping from rule_id is sufficient.
		f.Language = languageFromRuleID(f.RuleID)
		out = append(out, f)
	}
	return out, rows.Err()
}

// languageFromRuleID infers language from a rule ID like SC-JAVA-SQL-001.
func languageFromRuleID(ruleID string) string {
	switch {
	case len(ruleID) >= 8 && ruleID[:8] == "SC-JAVA-":
		return "java"
	case len(ruleID) >= 6 && ruleID[:6] == "SC-JS-":
		return "javascript"
	case len(ruleID) >= 6 && ruleID[:6] == "SC-PY-":
		return "python"
	case len(ruleID) >= 10 && ruleID[:10] == "SC-CSHARP-":
		return "csharp"
	}
	return ""
}

// UpsertCluster atomically inserts or updates a cluster by fingerprint.
// Returns (clusterID, wasInserted).
//
// Auto-reactivation: auto_resolved clusters become active again on touch.
// muted clusters with expired muted_until become active.
// user_resolved clusters KEEP their status (never auto-reactivate).
func (s *Store) UpsertCluster(ctx context.Context, tx pgx.Tx, runID string, c *Cluster) (id string, inserted bool, err error) {
	err = tx.QueryRow(ctx, `
		INSERT INTO risk.clusters (
			project_id, fingerprint, fingerprint_version, fingerprint_kind,
			title, vuln_class, cwe_id, owasp_category, language,
			canonical_route, canonical_param, http_method,
			file_path, enclosing_method, location_group,
			severity, status, last_run_id, last_seen_at, first_seen_at,
			exposure
		)
		VALUES ($1, $2, $3, $4, $5, $6,
				NULLIF($7, 0),
				NULLIF($8, ''),
				NULLIF($9, ''),
				NULLIF($10, ''), NULLIF($11, ''), NULLIF($12, ''),
				NULLIF($13, ''), NULLIF($14, ''), NULLIF($15, ''),
				$16, 'active', $17, now(), now(),
				'unknown')
		ON CONFLICT (project_id, fingerprint_version, fingerprint) DO UPDATE SET
			title = EXCLUDED.title,
			severity = EXCLUDED.severity,
			last_seen_at = now(),
			last_run_id = EXCLUDED.last_run_id,
			missing_run_count = 0,
			status = CASE
				WHEN risk.clusters.status = 'auto_resolved' THEN 'active'
				WHEN risk.clusters.status = 'muted'
				     AND risk.clusters.muted_until IS NOT NULL
				     AND risk.clusters.muted_until < now() THEN 'active'
				ELSE risk.clusters.status
			END,
			resolved_at = CASE
				WHEN risk.clusters.status = 'auto_resolved' THEN NULL
				ELSE risk.clusters.resolved_at
			END
		RETURNING id, (xmax = 0) AS inserted
	`,
		c.ProjectID, c.Fingerprint, c.FingerprintVersion, c.FingerprintKind,
		c.Title, c.VulnClass, c.CWEID, c.OWASPCategory, c.Language,
		c.CanonicalRoute, c.CanonicalParam, c.HTTPMethod,
		c.FilePath, c.EnclosingMethod, c.LocationGroup,
		c.Severity, runID,
	).Scan(&id, &inserted)
	return
}

// UpsertClusterFinding attaches a finding to a cluster for the current run.
// Idempotent within a run — repeated calls refresh last_seen_run_id.
func (s *Store) UpsertClusterFinding(ctx context.Context, tx pgx.Tx, clusterID, findingID, role, runID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO risk.cluster_findings
			(cluster_id, finding_id, role, first_seen_run_id, last_seen_run_id)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (cluster_id, finding_id) DO UPDATE SET
			last_seen_run_id = EXCLUDED.last_seen_run_id
	`, clusterID, findingID, role, runID)
	return err
}

// DeleteStaleClusterFindings removes any cluster_findings row in the project
// whose last_seen_run_id is not the current run. This handles findings that
// migrated between clusters and findings that were removed entirely.
func (s *Store) DeleteStaleClusterFindings(ctx context.Context, tx pgx.Tx, projectID, runID string) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM risk.cluster_findings cf
		USING risk.clusters c
		WHERE cf.cluster_id = c.id
		  AND c.project_id = $1
		  AND cf.last_seen_run_id <> $2
	`, projectID, runID)
	return err
}

// RecomputeClusterAggregates refreshes finding_count, surface_count, and
// severity for every touched cluster based on current cluster_findings and
// surface_entries. Runs inside the same transaction as the rebuild.
func (s *Store) RecomputeClusterAggregates(ctx context.Context, tx pgx.Tx, clusterIDs []string) error {
	if len(clusterIDs) == 0 {
		return nil
	}
	// finding_count + severity (take the worst across members)
	_, err := tx.Exec(ctx, `
		UPDATE risk.clusters c SET
			finding_count = sub.cnt,
			severity = COALESCE(sub.worst_sev, c.severity)
		FROM (
			SELECT
				cf.cluster_id,
				count(*) AS cnt,
				(ARRAY_AGG(f.severity ORDER BY
					CASE f.severity
						WHEN 'critical' THEN 5
						WHEN 'high'     THEN 4
						WHEN 'medium'   THEN 3
						WHEN 'low'      THEN 2
						WHEN 'info'     THEN 1
						ELSE 0
					END DESC))[1] AS worst_sev
			FROM risk.cluster_findings cf
			JOIN findings.findings f ON f.id = cf.finding_id
			WHERE cf.cluster_id = ANY($1)
			GROUP BY cf.cluster_id
		) sub
		WHERE c.id = sub.cluster_id
	`, clusterIDs)
	if err != nil {
		return err
	}

	// Zero out clusters whose cluster_findings were all cleaned up.
	_, err = tx.Exec(ctx, `
		UPDATE risk.clusters c SET finding_count = 0
		WHERE c.id = ANY($1)
		  AND NOT EXISTS (
		      SELECT 1 FROM risk.cluster_findings cf
		      WHERE cf.cluster_id = c.id
		  )
	`, clusterIDs)
	if err != nil {
		return err
	}

	// surface_count + exposure (worst across linked surface entries).
	// Surface linkage for DAST clusters is by exact canonical_route match on
	// the surface entry URL (lowercased). SAST clusters have no surface link
	// in MVP — surface_count stays 0.
	_, err = tx.Exec(ctx, `
		UPDATE risk.clusters c SET
			surface_count = sub.cnt,
			exposure = sub.worst_exp
		FROM (
			SELECT
				c2.id AS cluster_id,
				count(s.id) AS cnt,
				COALESCE(
					(ARRAY_AGG(s.exposure ORDER BY
						CASE s.exposure
							WHEN 'public'        THEN 4
							WHEN 'both'          THEN 3
							WHEN 'authenticated' THEN 2
							WHEN 'unknown'       THEN 1
							ELSE 0
						END DESC))[1],
					'unknown'
				) AS worst_exp
			FROM risk.clusters c2
			LEFT JOIN scans.surface_entries s
			  ON s.project_id = c2.project_id
			 AND c2.fingerprint_kind = 'dast_route'
			 AND lower(regexp_replace(s.url, '^https?://[^/]+', '')) = c2.canonical_route
			WHERE c2.id = ANY($1)
			GROUP BY c2.id
		) sub
		WHERE c.id = sub.cluster_id
	`, clusterIDs)
	return err
}

// DeleteStaleEvidence removes old evidence rows for touched clusters so the
// next emission writes a fresh snapshot. See spec §14 for retention notes.
func (s *Store) DeleteStaleEvidence(ctx context.Context, tx pgx.Tx, clusterIDs []string, runID string) error {
	if len(clusterIDs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		DELETE FROM risk.cluster_evidence
		WHERE cluster_id = ANY($1) AND source_run_id <> $2
	`, clusterIDs, runID)
	return err
}

// InsertEvidence persists a single evidence row. Called once per evidence
// item emitted by the scorer or the surface-link logic.
func (s *Store) InsertEvidence(ctx context.Context, tx pgx.Tx, e *Evidence) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO risk.cluster_evidence
			(cluster_id, category, code, label, weight, ref_type, ref_id,
			 sort_order, source_run_id, metadata)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, ''), NULLIF($7, ''), $8, $9, COALESCE($10, '{}')::jsonb)
	`, e.ClusterID, e.Category, e.Code, e.Label, e.Weight, e.RefType, e.RefID,
		e.SortOrder, e.SourceRunID, metadataJSON(e.Metadata))
	return err
}

// metadataJSON marshals the metadata map safely, returning "{}" on nil.
func metadataJSON(m map[string]any) string {
	if m == nil {
		return "{}"
	}
	// Lightweight marshal — the risk package does not ship JSON utilities
	// of its own, so we defer to fmt for the common key=string case and
	// store richer metadata via the correlator helper below.
	// In practice ComputeScore only uses string values.
	out := "{"
	first := true
	for k, v := range m {
		if !first {
			out += ","
		}
		first = false
		out += fmt.Sprintf("%q:%q", k, fmt.Sprint(v))
	}
	out += "}"
	return out
}

// UpdateClusterScore writes the final risk_score computed by the scorer.
func (s *Store) UpdateClusterScore(ctx context.Context, tx pgx.Tx, clusterID string, score int) error {
	_, err := tx.Exec(ctx, `UPDATE risk.clusters SET risk_score = $1 WHERE id = $2`, score, clusterID)
	return err
}

// LoadTouchedClusters fetches full cluster rows for the set of ids touched
// in this run. Needed by the scorer and the relations classifier.
func (s *Store) LoadTouchedClusters(ctx context.Context, tx pgx.Tx, clusterIDs []string) (map[string]*Cluster, error) {
	out := map[string]*Cluster{}
	if len(clusterIDs) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `
		SELECT id, project_id, fingerprint, fingerprint_version, fingerprint_kind,
		       title, vuln_class, COALESCE(cwe_id, 0), COALESCE(owasp_category, ''),
		       COALESCE(language, ''),
		       COALESCE(canonical_route, ''), COALESCE(canonical_param, ''),
		       COALESCE(http_method, ''),
		       COALESCE(file_path, ''), COALESCE(enclosing_method, ''),
		       COALESCE(location_group, ''),
		       severity, risk_score, exposure, status, missing_run_count,
		       finding_count, surface_count,
		       first_seen_at, last_seen_at
		FROM risk.clusters
		WHERE id = ANY($1)
	`, clusterIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		c := &Cluster{}
		if err := rows.Scan(
			&c.ID, &c.ProjectID, &c.Fingerprint, &c.FingerprintVersion, &c.FingerprintKind,
			&c.Title, &c.VulnClass, &c.CWEID, &c.OWASPCategory,
			&c.Language,
			&c.CanonicalRoute, &c.CanonicalParam,
			&c.HTTPMethod,
			&c.FilePath, &c.EnclosingMethod,
			&c.LocationGroup,
			&c.Severity, &c.RiskScore, &c.Exposure, &c.Status, &c.MissingRunCount,
			&c.FindingCount, &c.SurfaceCount,
			&c.FirstSeenAt, &c.LastSeenAt,
		); err != nil {
			return nil, err
		}
		out[c.ID] = c
	}
	return out, rows.Err()
}

// DeleteStaleRelations removes relations touching the given cluster with
// a last_linked_run_id different from the current run. Called at the start
// of rebuildRelations before re-inserting.
func (s *Store) DeleteStaleRelations(ctx context.Context, tx pgx.Tx, clusterID, runID string) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM risk.cluster_relations
		WHERE (source_cluster_id = $1 OR target_cluster_id = $1)
		  AND last_linked_run_id <> $2
	`, clusterID, runID)
	return err
}

// UpsertRelation inserts or updates a cluster_relations row. Pair MUST be
// canonicalized by the caller via CanonicalizePair.
func (s *Store) UpsertRelation(ctx context.Context, tx pgx.Tx, r *Relation) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO risk.cluster_relations
			(project_id, source_cluster_id, target_cluster_id,
			 relation_type, confidence, rationale, last_linked_run_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (source_cluster_id, target_cluster_id, relation_type) DO UPDATE SET
			confidence = EXCLUDED.confidence,
			rationale = EXCLUDED.rationale,
			last_linked_run_id = EXCLUDED.last_linked_run_id
	`, r.ProjectID, r.SourceClusterID, r.TargetClusterID,
		r.RelationType, r.Confidence, r.Rationale, r.LastLinkedRunID)
	return err
}

// LoadRelationCandidatesByCWE returns other clusters in the same project
// with the same CWE. Used by rebuildRelations to find runtime_confirmation
// and same_cwe pairs.
func (s *Store) LoadRelationCandidatesByCWE(ctx context.Context, tx pgx.Tx, projectID string, cweID int, excludeClusterID string) ([]*Cluster, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, fingerprint_kind, COALESCE(cwe_id, 0), COALESCE(owasp_category, ''), vuln_class
		FROM risk.clusters
		WHERE project_id = $1
		  AND cwe_id = $2
		  AND id <> $3
		  AND status IN ('active', 'user_resolved', 'muted')
	`, projectID, cweID, excludeClusterID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Cluster
	for rows.Next() {
		c := &Cluster{}
		if err := rows.Scan(&c.ID, &c.FingerprintKind, &c.CWEID, &c.OWASPCategory, &c.VulnClass); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasActiveRuntimeConfirmation returns true if any runtime_confirmation
// relation with confidence >= BoostThreshold touches the cluster.
func (s *Store) HasActiveRuntimeConfirmation(ctx context.Context, tx pgx.Tx, clusterID string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM risk.cluster_relations
			WHERE (source_cluster_id = $1 OR target_cluster_id = $1)
			  AND relation_type = 'runtime_confirmation'
			  AND confidence >= $2
		)
	`, clusterID, BoostThreshold).Scan(&exists)
	return exists, err
}

// FirstPublicSurfaceForCluster returns the URL of any linked public
// surface entry for a DAST cluster, or empty string if none.
func (s *Store) FirstPublicSurfaceForCluster(ctx context.Context, tx pgx.Tx, clusterID string) (string, error) {
	var url string
	err := tx.QueryRow(ctx, `
		SELECT s.url
		FROM risk.clusters c
		JOIN scans.surface_entries s
		  ON s.project_id = c.project_id
		 AND lower(regexp_replace(s.url, '^https?://[^/]+', '')) = c.canonical_route
		WHERE c.id = $1
		  AND s.exposure = 'public'
		LIMIT 1
	`, clusterID).Scan(&url)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return url, nil
}

// FindingCountsByRouteAndParam reports whether >1 cluster_findings share
// the cluster's canonical route or param. Used by the scorer for
// SAME_ROUTE / SAME_PARAM boosts.
func (s *Store) FindingCountsByRouteAndParam(ctx context.Context, tx pgx.Tx, clusterID string) (sameRoute, sameParam bool, err error) {
	err = tx.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM risk.cluster_findings WHERE cluster_id = $1) > 1
	`, clusterID).Scan(&sameRoute)
	if err != nil {
		return false, false, err
	}
	// In the MVP, we treat "multiple findings in the cluster" as both
	// same_route and same_param for DAST clusters — the cluster itself
	// is already defined by (route, param), so >1 members implies both.
	sameParam = sameRoute
	return
}

// MarkMissingClustersAndResolve bumps missing_run_count for active
// clusters not touched in the current run and auto-resolves any that
// have exceeded the grace period. Returns the count of newly-resolved
// clusters.
func (s *Store) MarkMissingClustersAndResolve(ctx context.Context, tx pgx.Tx, projectID, runID string) (int, error) {
	if _, err := tx.Exec(ctx, `
		UPDATE risk.clusters
		SET missing_run_count = missing_run_count + 1
		WHERE project_id = $1
		  AND status = 'active'
		  AND (last_run_id IS NULL OR last_run_id <> $2)
	`, projectID, runID); err != nil {
		return 0, err
	}
	var resolved int
	err := tx.QueryRow(ctx, `
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
	`, projectID).Scan(&resolved)
	return resolved, err
}
```

- [ ] **Step 2: Verify compilation**

Run:
```bash
go build ./internal/risk/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/risk/store.go
git commit -m "feat(risk): store with cluster/finding/evidence/relation queries

Adds the full persistence layer for the risk correlator. All queries run
inside a caller-supplied transaction so the entire rebuild is atomic.

Highlights:
- AcquireProjectLock via pg_advisory_xact_lock(FNV(project_id))
- UpsertCluster with auto-reactivation for auto_resolved and expired muted;
  user_resolved status is never auto-cleared
- UpsertClusterFinding with PK (cluster_id, finding_id) upsert
- DeleteStaleClusterFindings by project scope (catches cluster migration)
- RecomputeClusterAggregates updates finding_count, surface_count, severity,
  exposure by joining cluster_findings + surface_entries with ordered max
- MarkMissingClustersAndResolve increments missing_run_count and auto-
  resolves after 3 consecutive misses (grace period)"
```

---

## Chunk 7: Correlator pipeline

**Files:**
- Create: `internal/risk/correlator.go`
- Create: `internal/risk/correlator_test.go`
- Create: `internal/risk/testhelpers_test.go`

### Task 7.1: Correlator implementation

- [ ] **Step 1: Create `internal/risk/correlator.go`**

```go
package risk

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
)

// Correlator is the main rebuild engine. It is stateless except for its
// dependencies — a Store and a logger — and is safe to reuse across runs.
type Correlator struct {
	store  *Store
	logger zerolog.Logger
}

func NewCorrelator(store *Store, logger zerolog.Logger) *Correlator {
	return &Correlator{store: store, logger: logger.With().Str("component", "risk-correlator").Logger()}
}

// RebuildProject is the single entry point for a correlation run. It
// opens a transaction, acquires the project lock, processes every
// active finding, and commits atomically. Any error aborts and rolls
// back the entire run.
func (c *Correlator) RebuildProject(ctx context.Context, projectID, trigger string, triggeredByScan *string) error {
	start := time.Now()
	tx, err := c.store.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := c.store.AcquireProjectLock(ctx, tx, projectID); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}

	runID, err := c.store.CreateRun(ctx, tx, projectID, trigger, triggeredByScan)
	if err != nil {
		return fmt.Errorf("create run: %w", err)
	}

	findings, err := c.store.LoadActiveFindings(ctx, tx, projectID)
	if err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("load findings: %w", err)
	}

	touched := make(map[string]struct{})
	created := 0

	for _, f := range findings {
		fp, kind, version := ComputeFingerprint(f)
		if fp == "" {
			continue // unsupported finding type
		}
		cl := buildClusterFromFinding(f, fp, kind, version)
		clusterID, wasInserted, err := c.store.UpsertCluster(ctx, tx, runID, cl)
		if err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("upsert cluster: %w", err)
		}
		if wasInserted {
			created++
		}
		touched[clusterID] = struct{}{}

		if err := c.store.UpsertClusterFinding(ctx, tx, clusterID, f.ID, f.Type, runID); err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("upsert cluster_finding: %w", err)
		}
	}

	// Project-scoped stale cleanup (catches finding migrations).
	if err := c.store.DeleteStaleClusterFindings(ctx, tx, projectID, runID); err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("delete stale cluster_findings: %w", err)
	}

	touchedIDs := keysOf(touched)

	if err := c.store.RecomputeClusterAggregates(ctx, tx, touchedIDs); err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("recompute aggregates: %w", err)
	}

	// Evidence rebuild: delete prior, then re-emit from fresh relations + scorer.
	if err := c.store.DeleteStaleEvidence(ctx, tx, touchedIDs, runID); err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("delete stale evidence: %w", err)
	}

	clusters, err := c.store.LoadTouchedClusters(ctx, tx, touchedIDs)
	if err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("load touched clusters: %w", err)
	}

	for clusterID := range touched {
		cluster := clusters[clusterID]
		if cluster == nil {
			continue
		}
		if err := c.rebuildRelations(ctx, tx, projectID, cluster, runID); err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("rebuild relations: %w", err)
		}
		if err := c.rescoreCluster(ctx, tx, cluster, runID); err != nil {
			_ = c.store.FailRun(ctx, tx, runID, err.Error())
			return fmt.Errorf("rescore cluster: %w", err)
		}
	}

	resolved, err := c.store.MarkMissingClustersAndResolve(ctx, tx, projectID, runID)
	if err != nil {
		_ = c.store.FailRun(ctx, tx, runID, err.Error())
		return fmt.Errorf("mark missing: %w", err)
	}

	if err := c.store.FinishRun(ctx, tx, runID, Run{
		ClustersTouched:   len(touched),
		ClustersCreated:   created,
		ClustersResolved:  resolved,
		FindingsProcessed: len(findings),
	}); err != nil {
		return fmt.Errorf("finish run: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}

	c.logger.Info().
		Str("project_id", projectID).
		Str("run_id", runID).
		Int("touched", len(touched)).
		Int("created", created).
		Int("resolved", resolved).
		Int("findings", len(findings)).
		Dur("duration", time.Since(start)).
		Msg("risk correlation run completed")

	return nil
}

// rebuildRelations finds candidate clusters with the same CWE and emits
// relation rows. Stale relations are deleted first so a single rebuild
// produces an exact snapshot.
func (c *Correlator) rebuildRelations(ctx context.Context, tx pgx.Tx, projectID string, cluster *Cluster, runID string) error {
	if err := c.store.DeleteStaleRelations(ctx, tx, cluster.ID, runID); err != nil {
		return err
	}
	if cluster.CWEID == 0 {
		return nil
	}
	candidates, err := c.store.LoadRelationCandidatesByCWE(ctx, tx, projectID, cluster.CWEID, cluster.ID)
	if err != nil {
		return err
	}
	for _, cand := range candidates {
		relType, conf, rationale := ClassifyRelation(cluster, cand, false)
		if relType == "" {
			continue
		}
		src, tgt := CanonicalizePair(cluster.ID, cand.ID)
		r := &Relation{
			ProjectID:       projectID,
			SourceClusterID: src,
			TargetClusterID: tgt,
			RelationType:    relType,
			Confidence:      conf,
			Rationale:       rationale,
			LastLinkedRunID: runID,
		}
		if err := c.store.UpsertRelation(ctx, tx, r); err != nil {
			return err
		}
	}
	return nil
}

// rescoreCluster consults the store for all scoring inputs, runs the pure
// ComputeScore function, and persists the result + evidence rows.
func (c *Correlator) rescoreCluster(ctx context.Context, tx pgx.Tx, cluster *Cluster, runID string) error {
	runtime, err := c.store.HasActiveRuntimeConfirmation(ctx, tx, cluster.ID)
	if err != nil {
		return err
	}

	var publicURL string
	if cluster.FingerprintKind == "dast_route" {
		publicURL, err = c.store.FirstPublicSurfaceForCluster(ctx, tx, cluster.ID)
		if err != nil {
			return err
		}
	}

	sameRoute, sameParam := false, false
	if cluster.FingerprintKind == "dast_route" && cluster.FindingCount > 1 {
		sameRoute = cluster.CanonicalRoute != ""
		sameParam = cluster.CanonicalParam != ""
	}

	result := ComputeScore(ScoreInputs{
		Severity:         cluster.Severity,
		FingerprintKind:  cluster.FingerprintKind,
		RuntimeConfirmed: runtime,
		PublicExposure:   publicURL != "",
		PublicSurfaceURL: publicURL,
		SameRoute:        sameRoute,
		SameParam:        sameParam,
		CanonicalRoute:   cluster.CanonicalRoute,
		CanonicalParam:   cluster.CanonicalParam,
	})

	for i := range result.Evidence {
		e := &result.Evidence[i]
		e.ClusterID = cluster.ID
		e.SourceRunID = runID
		if err := c.store.InsertEvidence(ctx, tx, e); err != nil {
			return err
		}
	}

	return c.store.UpdateClusterScore(ctx, tx, cluster.ID, result.Total)
}

// buildClusterFromFinding derives the cluster-level fields from a source
// finding. For DAST clusters the canonical route/param come from the
// finding's normalized URL; for SAST clusters the file path and location
// group carry the identity.
func buildClusterFromFinding(f *Finding, fp, kind string, version int16) *Cluster {
	cl := &Cluster{
		ProjectID:          f.ProjectID,
		Fingerprint:        fp,
		FingerprintVersion: version,
		FingerprintKind:    kind,
		VulnClass:          vulnClassFromCWE(f.CWEID),
		CWEID:              f.CWEID,
		OWASPCategory:      f.OWASPCategory,
		Severity:           f.Severity,
	}
	switch kind {
	case "dast_route":
		cl.CanonicalRoute = NormalizeRoute(f.URL)
		cl.CanonicalParam = NormalizeParam(f.Parameter)
		cl.HTTPMethod = strings.ToUpper(f.HTTPMethod)
		cl.Title = fmt.Sprintf("%s on %s %s", titleCase(cl.VulnClass), cl.HTTPMethod, cl.CanonicalRoute)
	case "sast_file":
		cl.Language = strings.ToLower(f.Language)
		cl.FilePath = NormalizeFilePath(f.FilePath)
		cl.EnclosingMethod = f.FunctionName
		cl.LocationGroup = LocationGroup(f.FunctionName, f.LineStart, f.CWEID)
		where := cl.FilePath
		if cl.EnclosingMethod != "" {
			where = cl.EnclosingMethod + " in " + cl.FilePath
		}
		cl.Title = fmt.Sprintf("%s in %s", titleCase(cl.VulnClass), where)
	}
	return cl
}

// vulnClassFromCWE maps a CWE id to a short vuln_class string. The mapping
// is deliberately coarse for MVP; any unmapped CWE returns "other".
func vulnClassFromCWE(cweID int) string {
	switch cweID {
	case 89:
		return "sql_injection"
	case 78:
		return "command_injection"
	case 22:
		return "path_traversal"
	case 79:
		return "xss"
	case 502:
		return "unsafe_deserialization"
	case 918:
		return "ssrf"
	case 798, 259:
		return "hardcoded_secret"
	case 327, 328:
		return "weak_crypto"
	case 601:
		return "open_redirect"
	case 611:
		return "xxe"
	case 532:
		return "sensitive_logging"
	}
	return "other"
}

func titleCase(class string) string {
	if class == "" {
		return "Risk"
	}
	parts := strings.Split(class, "_")
	for i, p := range parts {
		if len(p) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, " ")
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
```

- [ ] **Step 2: Verify compilation**

Run:
```bash
go build ./internal/risk/
```

Expected: no errors.

### Task 7.2: Integration test against real DB

- [ ] **Step 3: Create `internal/risk/testhelpers_test.go`**

```go
package risk

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPool connects to the local sentinelcore DB if available. Tests that
// need a database call testPool(t) and t.Skip when unavailable.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("RISK_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://sentinelcore:dev-password@localhost:5432/sentinelcore"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("no test DB available: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("test DB ping failed: %v", err)
	}
	return pool
}

// cleanupProject wipes all risk.* rows for a project so a test starts
// from a deterministic state.
func cleanupProject(t *testing.T, pool *pgxpool.Pool, projectID string) {
	t.Helper()
	ctx := context.Background()
	_, _ = pool.Exec(ctx, `SET LOCAL app.org_id = '11111111-1111-1111-1111-111111111111'`)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.cluster_evidence WHERE cluster_id IN (SELECT id FROM risk.clusters WHERE project_id = $1)`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.cluster_findings WHERE cluster_id IN (SELECT id FROM risk.clusters WHERE project_id = $1)`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.cluster_relations WHERE project_id = $1`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.clusters WHERE project_id = $1`, projectID)
	_, _ = pool.Exec(ctx, `DELETE FROM risk.correlation_runs WHERE project_id = $1`, projectID)
}

// insertTestFinding writes a synthetic finding directly into findings.findings
// so the correlator can pick it up. Returns the finding id.
func insertTestFinding(t *testing.T, pool *pgxpool.Pool, projectID string, f map[string]any) string {
	t.Helper()
	ctx := context.Background()
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO findings.findings (
			project_id, scan_job_id, finding_type, fingerprint,
			title, description, severity, confidence, status,
			cwe_id, owasp_category, rule_id, file_path, line_start,
			function_name, url, http_method, parameter
		)
		VALUES ($1, '66666666-6666-6666-6666-666666666601', $2, gen_random_uuid()::text,
		        $3, 'test', $4, 'medium', 'new',
		        $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id
	`,
		projectID, f["finding_type"], f["title"], f["severity"],
		f["cwe_id"], f["owasp_category"], f["rule_id"],
		f["file_path"], f["line_start"], f["function_name"],
		f["url"], f["http_method"], f["parameter"],
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}
```

- [ ] **Step 4: Create `internal/risk/correlator_test.go`**

```go
package risk

import (
	"context"
	"testing"

	"github.com/rs/zerolog"
)

const testProjectID = "44444444-4444-4444-4444-444444444401"

// TestRebuild_SingleDASTFinding verifies the happy path: one DAST finding
// produces one cluster with the expected score and evidence.
func TestRebuild_SingleDASTFinding(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "dast",
		"title":          "SQL Injection via id",
		"severity":       "critical",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-DAST-SQLI-001",
		"url":            "https://stg.example.com/api/users/42",
		"http_method":    "GET",
		"parameter":      "id",
		"file_path":      nil,
		"line_start":     0,
		"function_name":  nil,
	})

	ctx := context.Background()
	_, _ = pool.Exec(ctx, `SET LOCAL app.org_id = '11111111-1111-1111-1111-111111111111'`)

	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	var clusterCount, findingLinkCount, evidenceCount int
	var score int
	pool.QueryRow(ctx, `SELECT count(*) FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&clusterCount)
	pool.QueryRow(ctx, `SELECT count(*) FROM risk.cluster_findings cf JOIN risk.clusters c ON c.id = cf.cluster_id WHERE c.project_id = $1`, testProjectID).Scan(&findingLinkCount)
	pool.QueryRow(ctx, `SELECT count(*) FROM risk.cluster_evidence e JOIN risk.clusters c ON c.id = e.cluster_id WHERE c.project_id = $1`, testProjectID).Scan(&evidenceCount)
	pool.QueryRow(ctx, `SELECT risk_score FROM risk.clusters WHERE project_id = $1 LIMIT 1`, testProjectID).Scan(&score)

	if clusterCount != 1 {
		t.Errorf("cluster count = %d, want 1", clusterCount)
	}
	if findingLinkCount != 1 {
		t.Errorf("cluster_findings count = %d, want 1", findingLinkCount)
	}
	if evidenceCount < 1 {
		t.Errorf("evidence count = %d, want >= 1 (SEVERITY_BASE)", evidenceCount)
	}
	if score < 60 {
		t.Errorf("score = %d, want >= 60 (critical base)", score)
	}
}

// TestRebuild_SASTDASTRuntimeConfirmation verifies the core unification
// contract: a SAST and a DAST finding with the same CWE create two
// clusters linked by a runtime_confirmation relation, and both clusters
// get the +20 boost.
func TestRebuild_SASTDASTRuntimeConfirmation(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "sast",
		"title":          "SQL Injection in findUser",
		"severity":       "high",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-JAVA-SQL-001",
		"file_path":      "src/main/UserRepo.java",
		"line_start":     42,
		"function_name":  "findUser",
		"url":            nil,
		"http_method":    nil,
		"parameter":      nil,
	})
	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type":   "dast",
		"title":          "SQL Injection via id",
		"severity":       "high",
		"cwe_id":         89,
		"owasp_category": "A03:2021",
		"rule_id":        "SC-DAST-SQLI-001",
		"url":            "https://stg.example.com/api/users",
		"http_method":    "GET",
		"parameter":      "id",
		"file_path":      nil,
		"line_start":     0,
		"function_name":  nil,
	})

	ctx := context.Background()
	_, _ = pool.Exec(ctx, `SET LOCAL app.org_id = '11111111-1111-1111-1111-111111111111'`)

	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	var clusterCount, relationCount int
	pool.QueryRow(ctx, `SELECT count(*) FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&clusterCount)
	pool.QueryRow(ctx, `SELECT count(*) FROM risk.cluster_relations WHERE project_id = $1 AND relation_type = 'runtime_confirmation'`, testProjectID).Scan(&relationCount)

	if clusterCount != 2 {
		t.Errorf("cluster count = %d, want 2 (one SAST, one DAST)", clusterCount)
	}
	if relationCount != 1 {
		t.Errorf("runtime_confirmation relation count = %d, want 1", relationCount)
	}

	// Both clusters should score >= 65 (45 base + 20 runtime).
	rows, _ := pool.Query(ctx, `SELECT risk_score FROM risk.clusters WHERE project_id = $1`, testProjectID)
	defer rows.Close()
	for rows.Next() {
		var score int
		rows.Scan(&score)
		if score < 65 {
			t.Errorf("cluster score = %d, want >= 65", score)
		}
	}
}

// TestRebuild_UserResolvedStaysResolved verifies user triage is sticky.
func TestRebuild_UserResolvedStaysResolved(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	ctx := context.Background()
	_, _ = pool.Exec(ctx, `SET LOCAL app.org_id = '11111111-1111-1111-1111-111111111111'`)

	insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type": "dast", "title": "X", "severity": "medium",
		"cwe_id": 89, "owasp_category": "A03:2021", "rule_id": "SC-DAST-SQLI-001",
		"url": "https://x.com/q", "http_method": "GET", "parameter": "id",
	})

	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}

	// User marks the cluster resolved.
	pool.Exec(ctx, `UPDATE risk.clusters SET status = 'user_resolved', resolved_at = now() WHERE project_id = $1`, testProjectID)

	// Second rebuild — finding is still there, but status must NOT revert to active.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}

	var status string
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "user_resolved" {
		t.Errorf("status after rebuild = %q, want user_resolved", status)
	}
}

// TestRebuild_AutoResolveGracePeriod verifies the 3-run grace period.
func TestRebuild_AutoResolveGracePeriod(t *testing.T) {
	pool := testPool(t)
	defer pool.Close()
	cleanupProject(t, pool, testProjectID)
	defer cleanupProject(t, pool, testProjectID)

	ctx := context.Background()
	_, _ = pool.Exec(ctx, `SET LOCAL app.org_id = '11111111-1111-1111-1111-111111111111'`)

	fID := insertTestFinding(t, pool, testProjectID, map[string]any{
		"finding_type": "dast", "title": "X", "severity": "medium",
		"cwe_id": 89, "owasp_category": "A03:2021", "rule_id": "SC-DAST-SQLI-001",
		"url": "https://x.com/q", "http_method": "GET", "parameter": "id",
	})

	cor := NewCorrelator(NewStore(pool), zerolog.Nop())
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}

	// Delete the finding (simulate it disappearing from scans).
	pool.Exec(ctx, `DELETE FROM findings.findings WHERE id = $1`, fID)

	// Run 1 empty — should NOT auto-resolve yet.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}
	var status string
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "active" {
		t.Errorf("after 1 empty run, status = %q, want active", status)
	}

	// Run 2 empty — still active.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "active" {
		t.Errorf("after 2 empty runs, status = %q, want active", status)
	}

	// Run 3 empty — should auto-resolve.
	if err := cor.RebuildProject(ctx, testProjectID, "manual", nil); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT status FROM risk.clusters WHERE project_id = $1`, testProjectID).Scan(&status)
	if status != "auto_resolved" {
		t.Errorf("after 3 empty runs, status = %q, want auto_resolved", status)
	}
}
```

- [ ] **Step 5: Run integration tests against local DB**

Run:
```bash
go test ./internal/risk/ -v -run TestRebuild
```

Expected: all 4 tests PASS. If no DB is available, tests skip — that's acceptable for local work but the CI must have a DB.

- [ ] **Step 6: Commit**

```bash
git add internal/risk/correlator.go internal/risk/correlator_test.go internal/risk/testhelpers_test.go
git commit -m "feat(risk): correlator pipeline with end-to-end integration tests

Correlator.RebuildProject wires together the full rebuild flow:
1. BEGIN TX + pg_advisory_xact_lock(project)
2. CreateRun
3. LoadActiveFindings
4. For each: ComputeFingerprint -> UpsertCluster -> UpsertClusterFinding
5. DeleteStaleClusterFindings (project-scoped)
6. RecomputeClusterAggregates
7. DeleteStaleEvidence
8. For each touched cluster: rebuildRelations + rescoreCluster
9. MarkMissingClustersAndResolve
10. FinishRun + COMMIT

Integration tests cover: single DAST finding, SAST+DAST runtime
confirmation, user_resolved stickiness, 3-run auto-resolve grace."
```

---

## Chunk 8: Worker + legacy cleanup

**Files:**
- Create: `internal/risk/worker.go`
- Modify: `cmd/correlation-engine/main.go`
- Delete: `internal/correlation/engine.go`, `engine_test.go`, `memstore.go`, `natshandler.go`

### Task 8.1: Debouncing worker

- [ ] **Step 1: Create `internal/risk/worker.go`**

```go
package risk

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
)

// DebounceWindow is the per-project window during which additional
// scan.completed events are absorbed into the same run.
const DebounceWindow = 30 * time.Second

// MinRebuildInterval is a minimum gap between consecutive runs for the
// same project. Events arriving inside this window are dropped.
const MinRebuildInterval = 10 * time.Second

// Worker subscribes to scan.status.update, debounces per project, and
// invokes the correlator.
type Worker struct {
	js         jetstream.JetStream
	correlator *Correlator
	logger     zerolog.Logger

	mu            sync.Mutex
	pending       map[string]*time.Timer // projectID -> firing timer
	lastRunEnd    map[string]time.Time
}

// NewWorker wires a worker against a NATS JetStream context and a correlator.
func NewWorker(js jetstream.JetStream, pool *pgxpool.Pool, logger zerolog.Logger) *Worker {
	return &Worker{
		js:         js,
		correlator: NewCorrelator(NewStore(pool), logger),
		logger:     logger.With().Str("component", "risk-worker").Logger(),
		pending:    make(map[string]*time.Timer),
		lastRunEnd: make(map[string]time.Time),
	}
}

// Run subscribes to scan.status.update and blocks until ctx is cancelled.
// Events are filtered: only status=completed triggers a rebuild.
func (w *Worker) Run(ctx context.Context) error {
	cons, err := w.js.CreateOrUpdateConsumer(ctx, "SCANS", jetstream.ConsumerConfig{
		Durable:       "risk-correlation",
		FilterSubject: "scan.status.update",
		AckPolicy:     jetstream.AckExplicitPolicy,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	w.logger.Info().Msg("risk worker subscribed to scan.status.update")

	for {
		select {
		case <-ctx.Done():
			w.logger.Info().Msg("risk worker shutting down")
			return nil
		default:
		}

		msgs, err := cons.Fetch(1, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			continue
		}
		for msg := range msgs.Messages() {
			w.handleMessage(ctx, msg)
		}
	}
}

// handleMessage parses the scan status payload and schedules a debounced
// rebuild if status == "completed".
func (w *Worker) handleMessage(ctx context.Context, msg jetstream.Msg) {
	defer msg.Ack()

	var payload struct {
		ScanJobID string `json:"scan_job_id"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(msg.Data(), &payload); err != nil {
		w.logger.Error().Err(err).Msg("invalid scan.status.update payload")
		return
	}
	if payload.Status != "completed" {
		return
	}

	projectID, err := w.projectForScan(ctx, payload.ScanJobID)
	if err != nil {
		w.logger.Error().Err(err).Str("scan_job_id", payload.ScanJobID).Msg("cannot resolve project for scan")
		return
	}

	w.schedule(projectID, &payload.ScanJobID)
}

// schedule debounces: if a timer is already pending for this project,
// reset it; otherwise create a new one. Drops if the last run completed
// less than MinRebuildInterval ago.
func (w *Worker) schedule(projectID string, scanID *string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if last, ok := w.lastRunEnd[projectID]; ok && time.Since(last) < MinRebuildInterval {
		w.logger.Debug().Str("project_id", projectID).Msg("dropping event (last run too recent)")
		return
	}

	if t, ok := w.pending[projectID]; ok {
		t.Reset(DebounceWindow)
		return
	}
	t := time.AfterFunc(DebounceWindow, func() {
		w.fireRebuild(projectID, scanID)
	})
	w.pending[projectID] = t
}

// fireRebuild runs the correlator and records the completion time for the
// MinRebuildInterval gate.
func (w *Worker) fireRebuild(projectID string, scanID *string) {
	w.mu.Lock()
	delete(w.pending, projectID)
	w.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := w.correlator.RebuildProject(ctx, projectID, "scan_completed", scanID); err != nil {
		w.logger.Error().Err(err).Str("project_id", projectID).Msg("risk rebuild failed")
		return
	}
	w.mu.Lock()
	w.lastRunEnd[projectID] = time.Now()
	w.mu.Unlock()
}

// projectForScan resolves scan_job_id to project_id via a direct DB lookup.
// Needed because the scan.status.update payload does not carry the project.
func (w *Worker) projectForScan(ctx context.Context, scanJobID string) (string, error) {
	var projectID string
	err := w.correlator.store.pool.QueryRow(ctx,
		`SELECT project_id::text FROM scans.scan_jobs WHERE id = $1`, scanJobID).Scan(&projectID)
	return projectID, err
}

// RebuildProjectManually bypasses the debouncer. Used by the API's
// manual-recompute endpoint.
func (w *Worker) RebuildProjectManually(ctx context.Context, projectID string) error {
	err := w.correlator.RebuildProject(ctx, projectID, "manual", nil)
	if err == nil {
		w.mu.Lock()
		w.lastRunEnd[projectID] = time.Now()
		w.mu.Unlock()
	}
	return err
}
```

- [ ] **Step 2: Verify compilation**

Run:
```bash
go build ./internal/risk/
```

Expected: no errors.

### Task 8.2: Rewire correlation-engine binary

- [ ] **Step 3: Replace `cmd/correlation-engine/main.go`**

```go
// Command correlation-engine runs the SentinelCore risk correlation worker.
// It subscribes to scan.status.update, debounces per project, rebuilds
// risk clusters in PostgreSQL, and exits on SIGINT/SIGTERM.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	sc_nats "github.com/sentinelcore/sentinelcore/pkg/nats"
	"github.com/sentinelcore/sentinelcore/pkg/observability"
	"github.com/sentinelcore/sentinelcore/internal/risk"
)

func main() {
	logger := observability.NewLogger("risk-worker")
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dsn := getEnv("DATABASE_URL", "postgres://sentinelcore:dev-password@localhost:5432/sentinelcore")
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("pg connect failed")
	}
	defer pool.Close()

	nc, js, err := sc_nats.Connect(sc_nats.Config{URL: getEnv("NATS_URL", "nats://localhost:4222")})
	if err != nil {
		logger.Fatal().Err(err).Msg("nats connect failed")
	}
	defer nc.Close()

	if err := sc_nats.EnsureStreams(ctx, js); err != nil {
		logger.Fatal().Err(err).Msg("ensure streams failed")
	}

	worker := risk.NewWorker(js, pool, logger)
	logger.Info().Msg("risk correlation worker starting")
	if err := worker.Run(ctx); err != nil {
		logger.Fatal().Err(err).Msg("worker exited with error")
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
```

### Task 8.3: Delete legacy code

- [ ] **Step 4: Delete the legacy correlation files**

Run:
```bash
rm internal/correlation/engine.go
rm internal/correlation/engine_test.go
rm internal/correlation/memstore.go
rm internal/correlation/natshandler.go
rmdir internal/correlation 2>/dev/null || true
```

- [ ] **Step 5: Verify everything builds**

Run:
```bash
go build ./...
```

Expected: no errors. If `pkg/correlation/` helpers are still needed (they are, for CWE hierarchy), they remain untouched.

- [ ] **Step 6: Run the full test suite**

Run:
```bash
go test ./... -count=1
```

Expected: all packages pass. The legacy `internal/correlation` tests are gone; the new `internal/risk` tests pass (or skip if no DB).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(risk): debounced NATS worker + rewire correlation-engine binary

internal/risk/worker.go:
- Subscribes to scan.status.update with durable 'risk-correlation'
- Filters payload to status=completed
- Per-project debouncer with 30s window + 10s min gap
- fireRebuild invokes Correlator.RebuildProject with 5min timeout

cmd/correlation-engine/main.go: rewritten to boot the new risk.Worker.
No Docker/deploy changes; the binary name is unchanged.

Deleted legacy in-memory correlation code:
- internal/correlation/engine.go
- internal/correlation/engine_test.go
- internal/correlation/memstore.go
- internal/correlation/natshandler.go

pkg/correlation/ helpers (CWE hierarchy, scorer helpers) are retained."
```

---

## Chunk 9: API handlers

**Files:**
- Create: `internal/controlplane/api/risks.go`
- Create: `internal/controlplane/api/risks_test.go`
- Modify: `internal/controlplane/server.go` (register routes)

### Task 9.1: Handlers

- [ ] **Step 1: Create `internal/controlplane/api/risks.go`**

Read the existing handler pattern first:
```bash
head -60 internal/controlplane/api/findings.go
```

Use the same logger/pool injection pattern. Create `internal/controlplane/api/risks.go`:

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/sentinelcore/sentinelcore/internal/risk"
)

// RisksHandler exposes the risk correlation API.
type RisksHandler struct {
	pool   *pgxpool.Pool
	logger zerolog.Logger
	worker *risk.Worker // for manual rebuild endpoint
}

func NewRisksHandler(pool *pgxpool.Pool, worker *risk.Worker, logger zerolog.Logger) *RisksHandler {
	return &RisksHandler{pool: pool, worker: worker, logger: logger.With().Str("handler", "risks").Logger()}
}

// ListRisks handles GET /api/v1/risks?project_id=...&status=active&severity=...
func (h *RisksHandler) ListRisks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	projectID := q.Get("project_id")
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required", "BAD_REQUEST")
		return
	}

	status := q.Get("status")
	if status == "" {
		status = "active"
	}

	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	whereStatus := "status = $2"
	args := []any{projectID, status}
	if status == "all" {
		whereStatus = "1=1"
		args = []any{projectID}
	}

	severityFilter := ""
	if sev := q.Get("severity"); sev != "" {
		args = append(args, sev)
		severityFilter = " AND severity = $" + strconv.Itoa(len(args))
	}
	vulnFilter := ""
	if vc := q.Get("vuln_class"); vc != "" {
		args = append(args, vc)
		vulnFilter = " AND vuln_class = $" + strconv.Itoa(len(args))
	}
	args = append(args, limit, offset)

	query := `
		SELECT id, title, vuln_class, COALESCE(cwe_id, 0), severity, risk_score, exposure,
		       status, finding_count, surface_count, first_seen_at, last_seen_at
		FROM risk.clusters
		WHERE project_id = $1 AND ` + whereStatus + severityFilter + vulnFilter + `
		ORDER BY risk_score DESC, last_seen_at DESC
		LIMIT $` + strconv.Itoa(len(args)-1) + ` OFFSET $` + strconv.Itoa(len(args))

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		h.logger.Error().Err(err).Msg("list risks query failed")
		writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
		return
	}
	defer rows.Close()

	type risksRow struct {
		ID           string `json:"id"`
		Title        string `json:"title"`
		VulnClass    string `json:"vuln_class"`
		CWEID        int    `json:"cwe_id"`
		Severity     string `json:"severity"`
		RiskScore    int    `json:"risk_score"`
		Exposure     string `json:"exposure"`
		Status       string `json:"status"`
		FindingCount int    `json:"finding_count"`
		SurfaceCount int    `json:"surface_count"`
		FirstSeenAt  string `json:"first_seen_at"`
		LastSeenAt   string `json:"last_seen_at"`
		TopReasons   []any  `json:"top_reasons"`
	}
	items := []risksRow{}
	for rows.Next() {
		var item risksRow
		var first, last interface{}
		if err := rows.Scan(
			&item.ID, &item.Title, &item.VulnClass, &item.CWEID, &item.Severity,
			&item.RiskScore, &item.Exposure, &item.Status,
			&item.FindingCount, &item.SurfaceCount, &first, &last,
		); err != nil {
			h.logger.Error().Err(err).Msg("list risks scan failed")
			writeError(w, http.StatusInternalServerError, "internal error", "INTERNAL_ERROR")
			return
		}
		item.FirstSeenAt = toRFC3339(first)
		item.LastSeenAt = toRFC3339(last)
		item.TopReasons = h.loadTopReasons(ctx, item.ID, 2)
		items = append(items, item)
	}

	var total int
	_ = h.pool.QueryRow(ctx, `SELECT count(*) FROM risk.clusters WHERE project_id = $1`, projectID).Scan(&total)

	writeJSON(w, http.StatusOK, map[string]any{
		"risks":  items,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// loadTopReasons returns up to n evidence rows ordered by sort_order.
func (h *RisksHandler) loadTopReasons(ctx interface{}, clusterID string, n int) []any {
	c, ok := ctx.(interface {
		Deadline() (interface{}, bool)
	})
	_ = c
	_ = ok
	rows, err := h.pool.Query(r(ctx), `
		SELECT code, label, weight
		FROM risk.cluster_evidence
		WHERE cluster_id = $1 AND category IN ('score_base','score_boost','score_penalty')
		ORDER BY sort_order
		LIMIT $2
	`, clusterID, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []any
	for rows.Next() {
		var code, label string
		var weight *int
		rows.Scan(&code, &label, &weight)
		out = append(out, map[string]any{
			"code":   code,
			"label":  label,
			"weight": weight,
		})
	}
	return out
}

// helper: strip the funny context cast (kept simple)
func r(ctx interface{}) interface{ Done() <-chan struct{} } { // stub signature for pgx
	return nil
}
```

**Note:** The `loadTopReasons` helper and context handling above are sketched — the final implementation should use the request's `context.Context` directly and pass it to `pool.Query`. The shape is correct; adjust signatures to use `context.Context` explicitly (the plan uses a simplified form for space). The implementing engineer should clean this up to:

```go
func (h *RisksHandler) loadTopReasons(ctx context.Context, clusterID string, n int) []map[string]any {
    rows, err := h.pool.Query(ctx, `...`, clusterID, n)
    ...
}
```

- [ ] **Step 2: Add GetRisk, ResolveRisk, ReopenRisk, MuteRisk, RebuildRisks handlers**

Continue `internal/controlplane/api/risks.go` with the remaining handlers. Each follows the same pattern: parse URL path param, look up / update, return JSON. The full detail endpoint (`GetRisk`) must return the evidence, findings, and relations arrays as specified in design spec §9.3. The plan delegates the exact shapes to the engineer because they are straightforward JSON marshalling over queries that the store already exposes.

Required endpoints:
- `GetRisk(w, r)` — `GET /api/v1/risks/{id}` — returns the cluster detail with evidence, findings, and relations
- `ResolveRisk(w, r)` — `POST /api/v1/risks/{id}/resolve` — sets `status='user_resolved'`, `resolved_at=now()`, `resolved_by=<jwt user>`
- `ReopenRisk(w, r)` — `POST /api/v1/risks/{id}/reopen` — sets `status='active'`, clears `resolved_at`
- `MuteRisk(w, r)` — `POST /api/v1/risks/{id}/mute` — body `{ "until": "RFC3339" }`; sets `status='muted'`, `muted_until=<ts>`
- `RebuildRisks(w, r)` — `POST /api/v1/projects/{id}/risks/rebuild` — calls `h.worker.RebuildProjectManually(ctx, projectID)` and returns 202 Accepted

Each handler uses the existing `writeError` and `writeJSON` helpers from `handlers.go`, and each must verify the caller has permission to access the project (reuse the existing RBAC helper).

### Task 9.2: Register routes

- [ ] **Step 3: Register routes in `internal/controlplane/server.go`**

Find the section where existing handlers are registered (look for `handlers.Findings`, `handlers.Scans`, etc.) and add:

```go
// Risk correlation
risksHandler := api.NewRisksHandler(pool, riskWorker, logger) // riskWorker wired in step 4
mux.HandleFunc("GET /api/v1/risks", risksHandler.ListRisks)
mux.HandleFunc("GET /api/v1/risks/{id}", risksHandler.GetRisk)
mux.HandleFunc("POST /api/v1/risks/{id}/resolve", risksHandler.ResolveRisk)
mux.HandleFunc("POST /api/v1/risks/{id}/reopen", risksHandler.ReopenRisk)
mux.HandleFunc("POST /api/v1/risks/{id}/mute", risksHandler.MuteRisk)
mux.HandleFunc("POST /api/v1/projects/{id}/risks/rebuild", risksHandler.RebuildRisks)
```

- [ ] **Step 4: Wire a risk.Worker instance into the control plane**

The control plane doesn't need the NATS worker loop — it only needs `RebuildProjectManually`. Construct a dedicated instance:

```go
riskWorker := risk.NewWorker(js, pool, logger)
// Don't call riskWorker.Run() — the correlation-engine binary does that.
// The control plane only uses RebuildProjectManually() for POST /rebuild.
```

### Task 9.3: Handler tests

- [ ] **Step 5: Create `internal/controlplane/api/risks_test.go`**

Add table-driven tests following the existing `findings_test.go` pattern. At minimum:

- `TestListRisks_DefaultActiveOnly` — insert 3 clusters (2 active, 1 resolved), assert only 2 are returned
- `TestListRisks_RequiresProjectID` — missing `project_id` → 400
- `TestGetRisk_IncludesEvidenceAndRelations` — insert a cluster with 2 evidence + 1 relation, assert response shape
- `TestResolveRisk_SetsStatus` — POST /resolve → status='user_resolved'
- `TestRebuildRisks_ReturnsAccepted` — POST /rebuild → 202

- [ ] **Step 6: Verify build + tests**

Run:
```bash
go build ./...
go test ./internal/controlplane/api/ -run TestRisks -v
```

Expected: build passes, handler tests pass (or skip if no DB).

- [ ] **Step 7: Commit**

```bash
git add internal/controlplane/api/risks.go internal/controlplane/api/risks_test.go internal/controlplane/server.go
git commit -m "feat(risk): HTTP API for risk clusters

New handlers in internal/controlplane/api/risks.go:
- GET  /api/v1/risks                         (list, active-only default)
- GET  /api/v1/risks/{id}                    (detail w/ evidence + relations)
- POST /api/v1/risks/{id}/resolve            (user_resolved)
- POST /api/v1/risks/{id}/reopen             (active)
- POST /api/v1/risks/{id}/mute               (muted + muted_until)
- POST /api/v1/projects/{id}/risks/rebuild   (manual recompute)

ListRisks params: status, severity, vuln_class, limit, offset.
Response includes top_reasons (first 2 evidence rows by sort_order) for
list rendering. Detail response includes full evidence, findings,
relations arrays.

All routes enforce RLS via app.org_id. Manual rebuild invokes
risk.Worker.RebuildProjectManually which bypasses the debouncer."
```

---

## Chunk 10: Frontend — types, API client, hooks

**Files:**
- Modify: `web/lib/types.ts`
- Create: `web/features/risks/api.ts`
- Create: `web/features/risks/hooks.ts`
- Create: `web/features/risks/schemas.ts`

### Task 10.1: Add TypeScript types

- [ ] **Step 1: Append risk types to `web/lib/types.ts`**

```typescript
// ---------- Risk Correlation ----------
export type RiskStatus = 'active' | 'auto_resolved' | 'user_resolved' | 'muted';
export type RiskExposure = 'public' | 'authenticated' | 'both' | 'unknown';
export type RiskFingerprintKind = 'dast_route' | 'sast_file';

export interface RiskReason {
  code: string;
  label: string;
  weight: number | null;
}

export interface RiskCluster {
  id: string;
  title: string;
  vuln_class: string;
  cwe_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  risk_score: number;
  exposure: RiskExposure;
  status: RiskStatus;
  finding_count: number;
  surface_count: number;
  first_seen_at: string;
  last_seen_at: string;
  top_reasons: RiskReason[];
}

export interface RiskEvidence {
  category: 'score_base' | 'score_boost' | 'score_penalty' | 'link' | 'context';
  code: string;
  label: string;
  weight: number | null;
  ref_type: string | null;
  ref_id: string | null;
  sort_order: number;
}

export interface RiskMemberFinding {
  id: string;
  role: 'sast' | 'dast' | 'sca';
  title: string;
  severity: string;
  file_path: string | null;
  url: string | null;
  line_start: number | null;
}

export interface RiskRelation {
  id: string;
  related_cluster_id: string;
  relation_type: 'runtime_confirmation' | 'same_cwe' | 'related_surface';
  confidence: number;
  rationale: string;
  related_cluster_title: string;
}

export interface RiskClusterDetail extends RiskCluster {
  project_id: string;
  owasp_category: string | null;
  fingerprint_kind: RiskFingerprintKind;
  canonical_route: string | null;
  http_method: string | null;
  canonical_param: string | null;
  file_path: string | null;
  enclosing_method: string | null;
  last_run_id: string | null;
  evidence: RiskEvidence[];
  findings: RiskMemberFinding[];
  relations: RiskRelation[];
}

export interface RiskListResponse {
  risks: RiskCluster[];
  total: number;
  limit: number;
  offset: number;
}

export interface RiskListParams {
  project_id: string;
  status?: RiskStatus | 'all';
  severity?: string;
  vuln_class?: string;
  limit?: number;
  offset?: number;
}
```

### Task 10.2: API client

- [ ] **Step 2: Create `web/features/risks/api.ts`**

```typescript
import { apiClient } from '@/lib/api-client';
import type {
  RiskClusterDetail,
  RiskListParams,
  RiskListResponse,
} from '@/lib/types';

export const risksApi = {
  list: async (params: RiskListParams): Promise<RiskListResponse> => {
    const qs = new URLSearchParams();
    qs.set('project_id', params.project_id);
    if (params.status) qs.set('status', params.status);
    if (params.severity) qs.set('severity', params.severity);
    if (params.vuln_class) qs.set('vuln_class', params.vuln_class);
    if (params.limit != null) qs.set('limit', String(params.limit));
    if (params.offset != null) qs.set('offset', String(params.offset));
    return apiClient.get<RiskListResponse>(`/api/v1/risks?${qs.toString()}`);
  },

  get: (id: string): Promise<{ risk: RiskClusterDetail }> =>
    apiClient.get(`/api/v1/risks/${id}`),

  resolve: (id: string, reason?: string): Promise<{ risk: RiskClusterDetail }> =>
    apiClient.post(`/api/v1/risks/${id}/resolve`, { reason }),

  reopen: (id: string): Promise<{ risk: RiskClusterDetail }> =>
    apiClient.post(`/api/v1/risks/${id}/reopen`, {}),

  mute: (id: string, until: string): Promise<{ risk: RiskClusterDetail }> =>
    apiClient.post(`/api/v1/risks/${id}/mute`, { until }),

  rebuild: (projectId: string): Promise<void> =>
    apiClient.post(`/api/v1/projects/${projectId}/risks/rebuild`, {}),
};
```

### Task 10.3: TanStack Query hooks

- [ ] **Step 3: Create `web/features/risks/hooks.ts`**

```typescript
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { risksApi } from './api';
import type { RiskListParams } from '@/lib/types';

const keys = {
  all: ['risks'] as const,
  lists: () => [...keys.all, 'list'] as const,
  list: (params: RiskListParams) => [...keys.lists(), params] as const,
  details: () => [...keys.all, 'detail'] as const,
  detail: (id: string) => [...keys.details(), id] as const,
};

export function useRisks(params: RiskListParams) {
  return useQuery({
    queryKey: keys.list(params),
    queryFn: () => risksApi.list(params),
    enabled: Boolean(params.project_id),
  });
}

export function useRisk(id: string | undefined) {
  return useQuery({
    queryKey: keys.detail(id ?? ''),
    queryFn: () => risksApi.get(id!),
    enabled: Boolean(id),
  });
}

export function useResolveRisk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason?: string }) =>
      risksApi.resolve(id, reason),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: keys.lists() });
      qc.invalidateQueries({ queryKey: keys.detail(vars.id) });
    },
  });
}

export function useReopenRisk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => risksApi.reopen(id),
    onSuccess: (_, id) => {
      qc.invalidateQueries({ queryKey: keys.lists() });
      qc.invalidateQueries({ queryKey: keys.detail(id) });
    },
  });
}

export function useMuteRisk() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, until }: { id: string; until: string }) =>
      risksApi.mute(id, until),
    onSuccess: (_, vars) => {
      qc.invalidateQueries({ queryKey: keys.lists() });
      qc.invalidateQueries({ queryKey: keys.detail(vars.id) });
    },
  });
}

export function useRebuildRisks() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (projectId: string) => risksApi.rebuild(projectId),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.all }),
  });
}
```

- [ ] **Step 4: Frontend build check**

Run:
```bash
cd web && npm run build
```

Expected: build succeeds with no type errors. If `apiClient.post` returns `void` in some overloads, adjust the mutation return types accordingly.

- [ ] **Step 5: Commit**

```bash
git add web/lib/types.ts web/features/risks/
git commit -m "feat(risk): frontend types, API client, and TanStack Query hooks

Types in web/lib/types.ts:
- RiskCluster, RiskClusterDetail, RiskEvidence, RiskMemberFinding,
  RiskRelation, RiskListResponse, RiskListParams
- Status/exposure/fingerprint_kind string literal types

API client in web/features/risks/api.ts matches the backend shape.

Hooks in web/features/risks/hooks.ts follow the existing queryKey
convention used by features/findings. Mutations invalidate both the
list and the individual detail on success."
```

---

## Chunk 11: Frontend — pages and dashboard card

**Files:**
- Create: `web/features/risks/risks-table.tsx`
- Create: `web/features/risks/risk-detail.tsx`
- Create: `web/features/risks/risk-evidence-panel.tsx`
- Create: `web/features/risks/top-risks-card.tsx`
- Create: `web/app/(dashboard)/risks/page.tsx`
- Create: `web/app/(dashboard)/risks/[id]/page.tsx`
- Modify: `web/components/layout/sidebar.tsx` (add Risks link)

### Task 11.1: Risks list page

- [ ] **Step 1: Create `web/features/risks/risks-table.tsx`**

Follow the existing pattern in `web/features/findings/findings-table.tsx`. Columns: risk score (colored bar), severity badge, title, vuln class, exposure badge, finding count, surface count, last seen. Clicking a row routes to `/risks/[id]`.

The "risk score" cell should be a horizontal bar whose fill width is `risk_score%` and whose color matches severity: critical=red, high=orange, medium=yellow, low=blue, info=gray. Reuse the existing severity badge component if present.

Below the table, render the `top_reasons` as a one-line summary: "Base (60) · Runtime confirmed (+20) · Public exposure (+15)".

- [ ] **Step 2: Create `web/features/risks/risk-evidence-panel.tsx`**

Renders the evidence list for the detail page. Groups rows by category. `score_base` row at the top in bold; `score_boost` rows with a "+" prefix on the weight; `link` rows render the `label` with optional ref link. Iterate `evidence` sorted by `sort_order` (API already returns it ordered, but sort defensively in the client).

- [ ] **Step 3: Create `web/features/risks/risk-detail.tsx`**

Full detail view. Sections in order:
1. Header — title, severity badge, risk score big number, status badge, actions (Resolve / Mute / Reopen depending on status).
2. **Why ranked highly?** — `<RiskEvidencePanel evidence={data.evidence} />`
3. **Findings in this risk** — list of `data.findings`, each with role badge (SAST/DAST/SCA) and a link to `/findings/{id}`.
4. **Related risks** — list of `data.relations`, each showing relation_type, confidence (formatted as percentage), rationale, and a link to the related cluster.
5. **Context** — fingerprint_kind, canonical_route + http_method (DAST) or file_path + enclosing_method (SAST), first/last seen timestamps.

Use the existing `useResolveRisk`, `useReopenRisk`, `useMuteRisk` mutations. Confirm dialogs follow the existing modal pattern from `features/findings/finding-detail.tsx`.

### Task 11.2: Pages

- [ ] **Step 4: Create `web/app/(dashboard)/risks/page.tsx`**

```typescript
'use client';

import { useState } from 'react';
import { RisksTable } from '@/features/risks/risks-table';
import { useRisks } from '@/features/risks/hooks';
import { useActiveProject } from '@/features/projects/hooks'; // or existing project context

export default function RisksPage() {
  const project = useActiveProject();
  const [status, setStatus] = useState<'active' | 'auto_resolved' | 'user_resolved' | 'muted' | 'all'>('active');
  const { data, isLoading } = useRisks({
    project_id: project?.id ?? '',
    status,
    limit: 50,
  });

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Risks</h1>
        <StatusTabs value={status} onChange={setStatus} />
      </div>
      <RisksTable
        data={data?.risks ?? []}
        isLoading={isLoading}
        total={data?.total ?? 0}
      />
    </div>
  );
}

function StatusTabs({ value, onChange }: { value: string; onChange: (s: any) => void }) {
  const tabs = [
    { id: 'active', label: 'Active' },
    { id: 'user_resolved', label: 'Resolved' },
    { id: 'muted', label: 'Muted' },
    { id: 'auto_resolved', label: 'Auto-resolved' },
    { id: 'all', label: 'All' },
  ];
  return (
    <div className="flex gap-1 rounded-lg border bg-background p-1">
      {tabs.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`rounded-md px-3 py-1 text-sm ${
            value === t.id ? 'bg-primary text-primary-foreground' : 'text-muted-foreground'
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
```

- [ ] **Step 5: Create `web/app/(dashboard)/risks/[id]/page.tsx`**

```typescript
'use client';

import { useParams } from 'next/navigation';
import { RiskDetail } from '@/features/risks/risk-detail';
import { useRisk } from '@/features/risks/hooks';

export default function RiskDetailPage() {
  const params = useParams<{ id: string }>();
  const { data, isLoading, error } = useRisk(params.id);

  if (isLoading) return <div className="p-6">Loading…</div>;
  if (error || !data) return <div className="p-6">Risk not found.</div>;

  return <RiskDetail risk={data.risk} />;
}
```

### Task 11.3: Dashboard Top Risks card

- [ ] **Step 6: Create `web/features/risks/top-risks-card.tsx`**

```typescript
'use client';

import Link from 'next/link';
import { useRisks } from './hooks';
import { SeverityBadge } from '@/components/badges/severity-badge';

export function TopRisksCard({ projectId }: { projectId: string }) {
  const { data, isLoading } = useRisks({ project_id: projectId, status: 'active', limit: 5 });

  return (
    <div className="rounded-lg border bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="font-semibold">Top Risks</h2>
        <Link href="/risks" className="text-xs text-muted-foreground hover:underline">
          View all
        </Link>
      </div>
      {isLoading && <div className="text-sm text-muted-foreground">Loading…</div>}
      {!isLoading && (data?.risks.length ?? 0) === 0 && (
        <div className="text-sm text-muted-foreground">No active risks.</div>
      )}
      <ul className="space-y-2">
        {data?.risks.map(r => (
          <li key={r.id}>
            <Link href={`/risks/${r.id}`} className="flex items-center gap-3 rounded-md p-2 hover:bg-accent">
              <div className="w-10 text-right text-lg font-semibold">{r.risk_score}</div>
              <SeverityBadge severity={r.severity} />
              <div className="flex-1 truncate text-sm">{r.title}</div>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

### Task 11.4: Sidebar link

- [ ] **Step 7: Add the Risks link to `web/components/layout/sidebar.tsx`**

Locate the existing nav item array (Findings, Scans, Surface, etc.) and insert a new entry:

```typescript
{ href: '/risks', label: 'Risks', icon: ShieldAlert }, // add between Findings and Scans
```

Use any reasonable lucide-react icon (`ShieldAlert`, `Target`, `AlertTriangle`).

- [ ] **Step 8: Frontend build check**

Run:
```bash
cd web && npm run build
```

Expected: build succeeds. Fix any type errors — the most likely source is the `apiClient` return-type signature on mutations.

- [ ] **Step 9: Commit**

```bash
git add web/features/risks/ web/app/\(dashboard\)/risks/ web/components/layout/sidebar.tsx
git commit -m "feat(risk): Risks list, detail, and Top Risks dashboard card

- RisksTable with colored score bar and severity column
- RiskEvidencePanel renders the 'Why ranked highly?' list in sort_order
- RiskDetail page sections: header, evidence, findings, relations, context
- Resolve / Mute / Reopen actions wired to the mutation hooks
- TopRisksCard reuses the same list API with limit=5
- Sidebar entry /risks between Findings and Scans"
```

---

## Chunk 12: Live verification

**Files:** none — this is a verification pass.

### Task 12.1: Apply the migration in the live env

- [ ] **Step 1: Stop the running correlation-engine if any**

Run:
```bash
pkill -f correlation-engine 2>/dev/null || true
```

- [ ] **Step 2: Apply the migration**

Run:
```bash
psql -U sentinelcore -d sentinelcore -f migrations/023_risk_clusters.up.sql
```

Expected: no errors. If `findings.function_name` already exists from a previous partial run, the `IF NOT EXISTS` guard absorbs it.

### Task 12.2: Build and start services

- [ ] **Step 3: Rebuild the binaries**

Run:
```bash
go build -o /tmp/sentinelcore-api ./cmd/controlplane
go build -o /tmp/sentinelcore-correlation-engine ./cmd/correlation-engine
go build -o /tmp/sentinelcore-sast-worker ./cmd/sast-worker
```

Expected: all three build with no errors.

- [ ] **Step 4: Restart the API + worker**

```bash
# Stop old
kill $(lsof -t -i :8080) 2>/dev/null || true
pkill -f sentinelcore-sast-worker 2>/dev/null || true
sleep 2

# Start API
ARTIFACT_STORAGE_ROOT=/tmp/sentinelcore-artifacts nohup /tmp/sentinelcore-api >/tmp/sentinelcore-api.log 2>&1 &
sleep 3

# Start sast worker
ARTIFACT_STORAGE_ROOT=/tmp/sentinelcore-artifacts nohup /tmp/sentinelcore-sast-worker >/tmp/sentinelcore-sast-worker.log 2>&1 &
sleep 2

# Start risk correlation engine
nohup /tmp/sentinelcore-correlation-engine >/tmp/sentinelcore-risk.log 2>&1 &
sleep 2

curl -s http://localhost:8080/healthz && echo ""
tail -5 /tmp/sentinelcore-risk.log
```

Expected: `{"status":"ok"}` and the risk worker log showing `risk worker subscribed to scan.status.update`.

### Task 12.3: End-to-end scan → cluster flow

- [ ] **Step 5: Upload the existing release-gate artifact (SAST)**

Reuse the existing `release-gate.zip` from the Parser Accuracy sprint or the C# release-gate. Upload and scan via the API (same pattern as previous sprints):

```bash
TOKEN=$(curl -s http://localhost:8080/api/v1/auth/login -H "Content-Type: application/json" -d '{"email":"admin@sentinel.io","password":"SentinelDemo1!"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
PROJECT_ID="44444444-4444-4444-4444-444444444401"

ARTIFACT_ID=$(curl -s -X POST "http://localhost:8080/api/v1/projects/${PROJECT_ID}/artifacts" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/release-gate.zip" \
  -F "name=risk-sprint-verification" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['source_artifact']['id'])")

SCAN_ID=$(curl -s -X POST "http://localhost:8080/api/v1/projects/${PROJECT_ID}/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"scan_type\":\"sast\",\"source_artifact_id\":\"${ARTIFACT_ID}\",\"scan_profile\":\"standard\",\"trigger_type\":\"manual\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan']['id'])")

echo "Scan: $SCAN_ID"
```

- [ ] **Step 6: Wait for scan + debounce window**

The debouncer holds for 30 seconds. Wait ~45s, then check the risk log:

```bash
sleep 45
grep "risk correlation run completed" /tmp/sentinelcore-risk.log | tail -5
```

Expected: at least one "risk correlation run completed" entry with `touched > 0`.

- [ ] **Step 7: Query the Risks API**

```bash
curl -s "http://localhost:8080/api/v1/risks?project_id=${PROJECT_ID}&status=active&limit=10" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Expected: a `risks` array with at least one entry whose `top_reasons` contains a `SEVERITY_BASE` row.

- [ ] **Step 8: Query a cluster detail**

Pick an id from the list response:

```bash
CLUSTER_ID=<from-previous-step>
curl -s "http://localhost:8080/api/v1/risks/${CLUSTER_ID}" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Expected: `evidence` array starts with `SEVERITY_BASE`, `findings` array is populated, `relations` may be empty (depends on whether there are matching DAST findings in the same project).

- [ ] **Step 9: UI smoke check**

Open `http://localhost:3000/risks` in a browser. Verify:
- List page renders with at least one cluster
- Clicking a row opens the detail page
- The "Why ranked highly?" panel shows the base score as the first row
- "Resolve" button is present and works (updates status to `user_resolved`)
- Dashboard Top Risks card (wherever it was added) shows the same top 5

### Task 12.4: Final regression check

- [ ] **Step 10: Run the full Go test suite**

Run:
```bash
go test ./... -count=1
```

Expected: all packages pass.

- [ ] **Step 11: Run the benchmark to confirm no SAST regression**

Run:
```bash
go test ./internal/sast/bench/ -run TestBenchmark
```

Expected: overall F1 unchanged from pre-sprint baseline.

- [ ] **Step 12: Cleanup commit**

If any verification work required small fixes (e.g. a frontend type nit, a log line tweak), commit them:

```bash
git add -A
git commit -m "chore(risk): live verification fixes and tweaks"
```

---

## Rollout checklist (production)

When promoting this sprint to a production environment, follow this sequence:

1. **Pre-deploy (DB)**
   - Apply `migrations/023_risk_clusters.up.sql` during a maintenance window. The migration adds tables and one column — no data rewrite, sub-second runtime on typical projects.
   - Verify `\dt risk.*` shows 5 tables and `findings.function_name` exists.

2. **Deploy the control plane first**
   - The new API routes are additive — old clients keep working.
   - Deploy any API server instances serving the organization.

3. **Deploy the correlation-engine binary**
   - Same binary name, new internals. On start it will create the durable consumer `risk-correlation` on the existing `SCANS` stream.
   - Watch the log for `risk worker subscribed to scan.status.update`.

4. **Trigger a warm-up rebuild**
   - For each active project, invoke `POST /api/v1/projects/{id}/risks/rebuild` once. This populates the cluster cache for the project without waiting for the next scan.
   - Script: loop over `SELECT id FROM core.projects WHERE status='active'`.

5. **Deploy the frontend**
   - New routes `/risks` and `/risks/[id]`, new sidebar entry. Old users see the new nav link.

6. **Monitor for 24 hours**
   - Watch the `risk.correlation_runs` table for entries with `status='error'`.
   - Alert threshold: >1 error per project per day.
   - Watch worker log for advisory lock wait times > 60s.

7. **Feature flag** (optional)
   - If a feature flag is desired, add a `RISK_CORRELATION_ENABLED` env var in `cmd/correlation-engine/main.go` that gates the `worker.Run(ctx)` call. When unset, the binary starts and exits idle. The frontend sidebar entry can be gated similarly via a `NEXT_PUBLIC_RISK_CORRELATION` env var. MVP ships without a flag unless the deployment team requests one.

---

## Concurrency and safety summary (for reference during review)

| Concern | Mechanism |
|---|---|
| Two runs for the same project | `pg_advisory_xact_lock(hashProjectLock(project_id))` — second run blocks until first commits |
| Race between scan writer and correlation | Worker subscribes to `scan.status.update`, fires only after status=completed, which scan workers publish after commit |
| Flaky scans auto-resolving clusters | 3-run grace period (`missing_run_count >= 3`) |
| Partial rebuild on failure | Single transaction; any error rolls back the entire run — DB state reverts to prior good state |
| Idempotency | Every upsert uses ON CONFLICT; re-running the same event is a no-op if state is already correct |
| Debounce storms | `MinRebuildInterval = 10s` drops events while a recent run is still being applied |
| Cluster identity drift | `fingerprint_version` coexists with `fingerprint`; bumping the version creates v2 clusters alongside v1 without destroying history |
| Stale cluster_findings after migration | Project-scoped `DELETE ... WHERE last_seen_run_id <> current_run_id` catches orphans in untouched clusters |
| Stale evidence after score change | Touched clusters have their prior evidence deleted and fresh rows emitted by the scorer |
| User triage sticky | `user_resolved` never auto-reactivates; the upsert's `CASE` only touches `auto_resolved` and expired `muted` |

---

## Plan complete

Plan saved to `docs/superpowers/plans/2026-04-10-risk-correlation-mvp.md`.

Chunks: 12. Each chunk ends in a commit. TDD flow for pure-logic components (fingerprint, scorer, relations). Integration tests for the correlator against a real DB. Live verification at the end.

**Ready to execute.**

To implement: use `superpowers:subagent-driven-development` if subagents are available (recommended — fresh context per chunk + two-stage review), or `superpowers:executing-plans` if running in a single session.
