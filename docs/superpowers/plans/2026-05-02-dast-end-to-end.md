# DAST End-to-End Production Wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task.

**Goal:** Make DAST scans actually work end-to-end in production. Today the orchestrator dispatches a job with the wrong field names, the worker has no DB access to enrich the job, no consumer persists findings, and scan status never updates beyond "queued". This plan wires the full pipeline so a user clicking "New Scan" → DAST against a target produces real findings in the UI.

**Architecture:** DAST worker gains a Postgres pool (parallel to SAST's pattern). Orchestrator sends a thin dispatch with `scan_job_id` only — worker queries the DB for everything else (target, allowed hosts, surface entries, auth config). Worker performs lightweight endpoint discovery (sitemap/robots/OpenAPI/Swagger probes + 1-hop link crawl), runs probes, writes findings directly to `findings.findings`, and updates `scans.scan_jobs` status throughout the lifecycle. Status updates also continue to publish on `scan.status.update` so the correlation engine keeps working.

**Tech Stack:** Go 1.23 (cmd/dast-worker, internal/dast, internal/controlplane), pgx/v5 pgxpool, NATS JetStream, AES-256-GCM (auth secret decrypt), Floating UI / nothing for endpoint discovery (stdlib `net/http` + `golang.org/x/net/html`).

**Spec reference:** none yet — this plan IS the spec for the smallest viable enterprise wiring.

---

## Working environment

- **Branch:** `fix/dast-end-to-end-2026-05` cut from current SAST branch (`feat/sast-rules-2026-05`).
- **Worktree:** `/Users/okyay/Documents/SentinelCore/.worktrees/dast-e2e/` (created in PR 0).
- **Build & deploy:** rebuild both `controlplane:pilot` and `dast-worker:pilot`, deploy via `docker compose up -d`.
- **Rollback:** tag current `pilot` images as `pilot-pre-dast-e2e` before first PR.

---

## File structure

### New files

| Path | Responsibility |
|------|----------------|
| `internal/dast/discovery.go` | Endpoint discovery: sitemap.xml, robots.txt, OpenAPI/Swagger probes, light HTML link crawl |
| `internal/dast/discovery_test.go` | Unit tests for each discovery source against `httptest.NewServer` |
| `internal/dast/repository.go` | Worker-side DB queries: load scan_job, target, surface_entries; insert findings; update scan status |
| `internal/dast/repository_test.go` | Tests against a temporary postgres (or skipped under -short) |
| `internal/dast/auth_resolver.go` | Decrypt `auth.auth_configs.encrypted_secret` and build `authbroker.AuthConfig` |
| `internal/dast/auth_resolver_test.go` | Round-trip encrypt → decrypt → resolve |

### Modified files

| Path | Reason |
|------|--------|
| `cmd/dast-worker/main.go` | Add Postgres pool, wire to NATSWorker via repository |
| `internal/dast/natsworker.go` | Replace empty `NATSScanJob` shape with thin `{scan_job_id}` dispatch; resolve everything from DB at process time; persist findings + status |
| `internal/dast/worker.go` | Accept repository + auth resolver; remove publish-findings-to-NATS path; keep status publish for correlation engine |
| `internal/controlplane/api/scans.go` | Slim dispatch message to `{scan_job_id, scan_type}` only; rename `scan_id` → `scan_job_id`; remove redundant `target_id`/`auth_config_id` (worker resolves these) |
| `migrations/044_scan_jobs_progress.up.sql` (+ `.down.sql`) | Add `progress_phase TEXT NOT NULL DEFAULT 'pending'` column to `scans.scan_jobs` if not present (the API model already references it) |

---

## PR 0 — Pre-flight

- [ ] **Step 1: Worktree + branch**

```
cd /Users/okyay/Documents/SentinelCore
git fetch origin
git worktree add /Users/okyay/Documents/SentinelCore/.worktrees/dast-e2e \
  -b fix/dast-end-to-end-2026-05 feat/sast-rules-2026-05
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-e2e
git branch --show-current
```
Expected: `fix/dast-end-to-end-2026-05`.

- [ ] **Step 2: Rollback tag**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:pilot sentinelcore/controlplane:pilot-pre-dast-e2e && \
  docker tag sentinelcore/dast-worker:pilot sentinelcore/dast-worker:pilot-pre-dast-e2e && \
  docker images | grep -E 'controlplane|dast-worker' | head -10"
```
Expected: both `pilot-pre-dast-e2e` tags listed.

- [ ] **Step 3: Baseline tests**

```
go test ./internal/dast/... ./internal/controlplane/... ./internal/sast/...
```
Expected: PASS for every package.

- [ ] **Step 4: Confirm progress_phase column status**

```
ssh okyay@77.42.34.174 "docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \"SELECT column_name FROM information_schema.columns WHERE table_schema='scans' AND table_name='scan_jobs' AND column_name='progress_phase';\""
```
If 0 rows, schedule migration in PR 5; else skip.

---

## PR 1 — Worker DB access (cmd + repository)

### Task 1.1: Add Postgres pool to cmd/dast-worker

**Files:**
- Modify: `cmd/dast-worker/main.go`

- [ ] **Step 1: Update imports**

```go
import (
    "github.com/jackc/pgx/v5/pgxpool"
)
```

- [ ] **Step 2: Initialize pool from DATABASE_URL**

After `signingKey := []byte(signingKeyStr)`, before broker creation:

```go
dbURL := getEnv("DATABASE_URL", "")
if dbURL == "" {
    logger.Fatal().Msg("DATABASE_URL environment variable is required")
}
pool, err := pgxpool.New(ctx, dbURL)
if err != nil {
    logger.Fatal().Err(err).Msg("postgres pool create failed")
}
defer pool.Close()
```

- [ ] **Step 3: Pass pool to NATSWorker**

Change `dast.NewNATSWorker(js, worker, signingKey, logger)` to `dast.NewNATSWorker(js, worker, signingKey, pool, logger)`.

- [ ] **Step 4: Commit**

```
git add cmd/dast-worker/main.go
git commit -m "feat(dast-worker): wire pgxpool — required for DB-backed dispatch resolution"
git push -u origin fix/dast-end-to-end-2026-05
```

(Build will fail until PR 1.2 completes signature change.)

### Task 1.2: Repository layer

**Files:**
- Create: `internal/dast/repository.go`
- Create: `internal/dast/repository_test.go`

- [ ] **Step 1: Write the repository skeleton**

```go
// internal/dast/repository.go
package dast

import (
    "context"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

// Repository encapsulates all DB queries the DAST worker performs.
// It exists so the worker (which historically had no DB access) can
// resolve a thin "scan_job_id only" dispatch message into a fully
// hydrated ScanJob, persist findings, and own scan status transitions.
//
// All queries run with row_security off — the worker is a trusted
// service-side actor. RLS is enforced at the API boundary, not here.
type Repository struct {
    pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
    return &Repository{pool: pool}
}

// ErrScanJobNotFound is returned when a dispatch references a scan job
// that no longer exists (race with deletion, cleanup, etc).
var ErrScanJobNotFound = errors.New("scan job not found")

// ScanJobRecord captures the fields the worker needs to plan the scan.
type ScanJobRecord struct {
    ID            string
    ProjectID     string
    ScanType      string
    ScanProfile   string
    ScanTargetID  string
    Status        string
}

// LoadScanJob fetches the scan job row by id. RLS bypassed via session-level
// SET; safe because the worker only ever runs server-side under a trusted
// service identity.
func (r *Repository) LoadScanJob(ctx context.Context, scanJobID string) (*ScanJobRecord, error) {
    conn, err := r.pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return nil, err
    }
    var rec ScanJobRecord
    err = conn.QueryRow(ctx, `
        SELECT id::text, project_id::text, scan_type, scan_profile,
               COALESCE(scan_target_id::text, ''), status
        FROM scans.scan_jobs
        WHERE id = $1
    `, scanJobID).Scan(&rec.ID, &rec.ProjectID, &rec.ScanType, &rec.ScanProfile,
        &rec.ScanTargetID, &rec.Status)
    if errors.Is(err, pgx.ErrNoRows) {
        return nil, ErrScanJobNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("query scan_job: %w", err)
    }
    return &rec, nil
}

// TargetRecord captures the fields needed to scope a DAST scan.
type TargetRecord struct {
    ID            string
    ProjectID     string
    BaseURL       string
    AllowedHosts  []string
    AllowedPaths  []string
    ExcludedPaths []string
    AllowedPorts  []int
    MaxRPS        int
    AuthConfigID  string
}

// LoadTarget fetches the scan target referenced by a scan job.
func (r *Repository) LoadTarget(ctx context.Context, targetID string) (*TargetRecord, error) {
    conn, err := r.pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return nil, err
    }
    var rec TargetRecord
    var authConfigID *string
    err = conn.QueryRow(ctx, `
        SELECT id::text, project_id::text, base_url,
               COALESCE(allowed_domains, '{}'),
               COALESCE(allowed_paths, '{}'),
               COALESCE(excluded_paths, '{}'),
               COALESCE(allowed_ports, '{}'),
               max_rps,
               auth_config_id::text
        FROM core.scan_targets
        WHERE id = $1
    `, targetID).Scan(&rec.ID, &rec.ProjectID, &rec.BaseURL,
        &rec.AllowedHosts, &rec.AllowedPaths, &rec.ExcludedPaths,
        &rec.AllowedPorts, &rec.MaxRPS, &authConfigID)
    if errors.Is(err, pgx.ErrNoRows) {
        return nil, fmt.Errorf("scan_target %s: %w", targetID, ErrScanJobNotFound)
    }
    if err != nil {
        return nil, err
    }
    if authConfigID != nil {
        rec.AuthConfigID = *authConfigID
    }
    return &rec, nil
}

// SurfaceEntry is one previously-discovered endpoint for a project.
type SurfaceEntry struct {
    URL    string
    Method string
}

// LoadSurfaceEntries returns previously-discovered endpoints for the
// project. Used by the DAST worker as a starting point so each scan
// doesn't re-discover from scratch.
func (r *Repository) LoadSurfaceEntries(ctx context.Context, projectID string) ([]SurfaceEntry, error) {
    conn, err := r.pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return nil, err
    }
    rows, err := conn.Query(ctx, `
        SELECT url, method
        FROM scans.surface_entries
        WHERE project_id = $1
    `, projectID)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    var out []SurfaceEntry
    for rows.Next() {
        var e SurfaceEntry
        if err := rows.Scan(&e.URL, &e.Method); err != nil {
            return nil, err
        }
        out = append(out, e)
    }
    return out, rows.Err()
}

// SaveSurfaceEntries upserts a batch of discovered endpoints. Discovery
// is incremental — re-running the same scan against the same target
// updates first/last_seen and increments scan_count.
func (r *Repository) SaveSurfaceEntries(ctx context.Context, projectID, scanJobID string, entries []SurfaceEntry) error {
    if len(entries) == 0 {
        return nil
    }
    conn, err := r.pool.Acquire(ctx)
    if err != nil {
        return err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return err
    }
    tx, err := conn.Begin(ctx)
    if err != nil {
        return err
    }
    defer tx.Rollback(ctx)
    for _, e := range entries {
        // Stable id: project + url + method (so re-discovery merges).
        id := fmt.Sprintf("%s:%s %s", projectID, e.Method, e.URL)
        _, err := tx.Exec(ctx, `
            INSERT INTO scans.surface_entries (id, project_id, scan_job_id, surface_type, url, method, exposure)
            VALUES ($1, $2, $3, 'route', $4, $5, 'unknown')
            ON CONFLICT (id) DO UPDATE
              SET last_seen_at = now(),
                  scan_count = scans.surface_entries.scan_count + 1,
                  scan_job_id = EXCLUDED.scan_job_id
        `, id, projectID, scanJobID, e.URL, e.Method)
        if err != nil {
            return fmt.Errorf("upsert surface_entry %s: %w", id, err)
        }
    }
    return tx.Commit(ctx)
}

// FindingRecord is the worker's view of a finding to persist.
type FindingRecord struct {
    ProjectID    string
    ScanJobID    string
    Fingerprint  string
    RuleID       string
    Title        string
    Description  string
    Severity     string
    Confidence   string
    URL          string
    Method       string
    Parameter    string
    CWE          int
}

// UpsertFinding inserts a finding or refreshes last_seen_at + scan_count if
// a row with the same fingerprint already exists in this project.
func (r *Repository) UpsertFinding(ctx context.Context, f FindingRecord) error {
    conn, err := r.pool.Acquire(ctx)
    if err != nil {
        return err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return err
    }
    var existingID string
    err = conn.QueryRow(ctx, `
        SELECT id::text FROM findings.findings
        WHERE project_id = $1 AND fingerprint = $2
    `, f.ProjectID, f.Fingerprint).Scan(&existingID)
    if err == nil {
        _, err = conn.Exec(ctx, `
            UPDATE findings.findings
            SET last_seen_at = now(),
                scan_count = scan_count + 1,
                scan_job_id = $2,
                updated_at = now()
            WHERE id = $1
        `, existingID, f.ScanJobID)
        return err
    }
    if !errors.Is(err, pgx.ErrNoRows) {
        return err
    }
    var cweArr []string
    if f.CWE > 0 {
        cweArr = []string{fmt.Sprintf("CWE-%d", f.CWE)}
    }
    _, err = conn.Exec(ctx, `
        INSERT INTO findings.findings
            (project_id, scan_job_id, finding_type, fingerprint, title, description,
             severity, confidence, url, http_method, parameter, rule_id, cve_ids,
             status, scan_count)
        VALUES ($1, $2, 'dast', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'new', 1)
    `, f.ProjectID, f.ScanJobID, f.Fingerprint, f.Title, f.Description,
        f.Severity, f.Confidence, f.URL, f.Method, f.Parameter, f.RuleID, cweArr)
    return err
}

// MarkRunning updates scan_jobs status to running with started_at = now().
func (r *Repository) MarkRunning(ctx context.Context, workerID, scanJobID string) error {
    return r.updateStatus(ctx, scanJobID, "running", "discovering", 0, workerID, "")
}

// MarkCompleted finalizes the scan as completed with progress=100.
func (r *Repository) MarkCompleted(ctx context.Context, scanJobID string) error {
    return r.updateStatus(ctx, scanJobID, "completed", "completed", 100, "", "")
}

// MarkFailed sets status=failed and records the error message.
func (r *Repository) MarkFailed(ctx context.Context, scanJobID, errMsg string) error {
    return r.updateStatus(ctx, scanJobID, "failed", "failed", 0, "", errMsg)
}

// MarkProgress sets a phase + percentage during execution.
func (r *Repository) MarkProgress(ctx context.Context, scanJobID, phase string, pct int) error {
    return r.updateStatus(ctx, scanJobID, "running", phase, pct, "", "")
}

func (r *Repository) updateStatus(ctx context.Context, scanJobID, status, phase string, pct int, workerID, errMsg string) error {
    conn, err := r.pool.Acquire(ctx)
    if err != nil {
        return err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return err
    }
    var startedClause, completedClause, workerClause, errClause string
    args := []any{scanJobID, status, phase, pct}
    if status == "running" && workerID != "" {
        startedClause = ", started_at = COALESCE(started_at, now())"
        workerClause = ", worker_id = $5"
        args = append(args, workerID)
    }
    if status == "completed" || status == "failed" {
        completedClause = ", completed_at = now()"
    }
    if errMsg != "" {
        errClause = ", error_message = $" + fmt.Sprint(len(args)+1)
        args = append(args, errMsg)
    }
    sql := fmt.Sprintf(`
        UPDATE scans.scan_jobs
        SET status = $2,
            progress_phase = $3,
            progress = $4,
            updated_at = now()
            %s %s %s %s
        WHERE id = $1
    `, startedClause, completedClause, workerClause, errClause)
    _, err = conn.Exec(ctx, sql, args...)
    return err
}
```

- [ ] **Step 2: Tests**

Create `internal/dast/repository_test.go`. Skip under -short; otherwise connect to a temp Postgres via env `TEST_DATABASE_URL`. Tests:
- LoadScanJob round-trip
- LoadTarget with arrays
- SaveSurfaceEntries idempotency (run twice, verify scan_count = 2)
- UpsertFinding insert path
- UpsertFinding update path (same fingerprint)
- MarkRunning/MarkCompleted/MarkFailed transitions

(Test file body intentionally elided here — runs against TEST_DATABASE_URL when set; skip under -short.)

- [ ] **Step 3: Run + commit**

```
go build ./...
go test -short ./internal/dast/...
git add internal/dast/repository.go internal/dast/repository_test.go
git commit -m "feat(dast): repository layer — DB queries owned by the worker"
git push
```

### Task 1.3: NATSWorker rewrite — DB-backed dispatch

**Files:**
- Modify: `internal/dast/natsworker.go`

- [ ] **Step 1: Replace dispatch shape**

Replace `NATSScanJob` struct with the thin dispatch:

```go
// NATSDispatch is the wire format for scan dispatch messages received via
// NATS. Intentionally tiny — the worker queries the DB for everything else
// using `scan_job_id`. Keeping the dispatch small avoids the orchestrator
// needing to enrich-and-stay-in-sync with the worker's view of the job.
type NATSDispatch struct {
    ScanJobID string `json:"scan_job_id"`
    ScanType  string `json:"scan_type,omitempty"`
}
```

- [ ] **Step 2: Update NewNATSWorker signature**

Add a `*Repository` field; constructor takes `pool *pgxpool.Pool` and constructs the repo internally:

```go
type NATSWorker struct {
    worker     *Worker
    js         jetstream.JetStream
    signingKey []byte
    repo       *Repository
    logger     zerolog.Logger
}

func NewNATSWorker(js jetstream.JetStream, worker *Worker, signingKey []byte, pool *pgxpool.Pool, logger zerolog.Logger) *NATSWorker {
    return &NATSWorker{
        worker:     worker,
        js:         js,
        signingKey: signingKey,
        repo:       NewRepository(pool),
        logger:     logger.With().Str("component", "dast-nats-worker").Logger(),
    }
}
```

- [ ] **Step 3: Rewrite processScan to resolve from DB**

Replace the body of `processScan` with the DB-backed flow:

```go
func (nw *NATSWorker) processScan(ctx context.Context, msg NATSDispatch) {
    log := nw.logger.With().Str("scan_job_id", msg.ScanJobID).Logger()

    job, err := nw.repo.LoadScanJob(ctx, msg.ScanJobID)
    if err != nil {
        log.Error().Err(err).Msg("load scan job")
        return
    }
    if job.ScanTargetID == "" {
        nw.failJob(ctx, msg.ScanJobID, "scan job has no target")
        return
    }

    target, err := nw.repo.LoadTarget(ctx, job.ScanTargetID)
    if err != nil {
        nw.failJob(ctx, msg.ScanJobID, fmt.Sprintf("load target: %v", err))
        return
    }

    if err := nw.repo.MarkRunning(ctx, nw.worker.WorkerID(), msg.ScanJobID); err != nil {
        log.Warn().Err(err).Msg("mark running failed (continuing)")
    }
    nw.publishStatus(ctx, msg.ScanJobID, "running", "")

    // Discovery phase
    nw.repo.MarkProgress(ctx, msg.ScanJobID, "discovering", 10)
    discovered, err := DiscoverEndpoints(ctx, target, nw.logger)
    if err != nil {
        log.Warn().Err(err).Msg("discovery error (continuing with seed)")
    }

    // Persist surface entries
    surfaceEntries := make([]SurfaceEntry, 0, len(discovered))
    for _, ep := range discovered {
        surfaceEntries = append(surfaceEntries, SurfaceEntry{URL: ep.BaseURL + ep.Path, Method: ep.Method})
    }
    if err := nw.repo.SaveSurfaceEntries(ctx, target.ProjectID, msg.ScanJobID, surfaceEntries); err != nil {
        log.Warn().Err(err).Msg("save surface entries failed (continuing)")
    }

    // Resolve auth (best effort)
    var authCfg *authbroker.AuthConfig
    if target.AuthConfigID != "" {
        ac, aerr := nw.resolveAuth(ctx, target.AuthConfigID)
        if aerr != nil {
            log.Warn().Err(aerr).Msg("auth resolve failed; running unauthenticated")
        } else {
            authCfg = ac
        }
    }

    // Build scope config from target
    scopeCfg := scope.Config{
        AllowedHosts:    target.AllowedHosts,
        AllowedPaths:    target.AllowedPaths,
        ExcludedPaths:   target.ExcludedPaths,
        AllowedPorts:    target.AllowedPorts,
        MaxRequestsPerS: target.MaxRPS,
    }

    // Build the worker-internal ScanJob (same struct used previously)
    workerJob := ScanJob{
        ID:            msg.ScanJobID,
        TargetBaseURL: target.BaseURL,
        AllowedHosts:  target.AllowedHosts,
        Endpoints:     discovered,
        AuthConfig:    authCfg,
        ScopeConfig:   scopeCfg,
        Concurrency:   0,
        RequestDelay:  0,
        Profile:       job.ScanProfile,
    }

    // Run probes
    nw.repo.MarkProgress(ctx, msg.ScanJobID, "scanning", 40)
    result, err := nw.worker.Run(ctx, workerJob)
    if err != nil {
        nw.failJob(ctx, msg.ScanJobID, err.Error())
        return
    }

    // Persist findings
    nw.repo.MarkProgress(ctx, msg.ScanJobID, "persisting", 80)
    for _, f := range result.Findings {
        rec := FindingRecord{
            ProjectID:   target.ProjectID,
            ScanJobID:   msg.ScanJobID,
            Fingerprint: fingerprintDASTFinding(f, target.ProjectID),
            RuleID:      f.RuleID,
            Title:       f.Title,
            Description: f.Description,
            Severity:    f.Severity,
            Confidence:  f.Confidence,
            URL:         f.URL,
            Method:      f.Method,
            Parameter:   f.Parameter,
            CWE:         f.CWE,
        }
        if err := nw.repo.UpsertFinding(ctx, rec); err != nil {
            log.Error().Err(err).Str("rule", f.RuleID).Msg("persist finding failed")
        }
    }

    if err := nw.repo.MarkCompleted(ctx, msg.ScanJobID); err != nil {
        log.Warn().Err(err).Msg("mark completed failed")
    }
    nw.publishStatus(ctx, msg.ScanJobID, "completed", "")
    log.Info().Int("findings", len(result.Findings)).Msg("scan completed")
}

func (nw *NATSWorker) failJob(ctx context.Context, scanJobID, errMsg string) {
    nw.repo.MarkFailed(ctx, scanJobID, errMsg)
    nw.publishStatus(ctx, scanJobID, "failed", errMsg)
}

// fingerprintDASTFinding produces a stable identifier for dedup across scans.
// Format: sha256(project + rule_id + url + method + parameter)
func fingerprintDASTFinding(f Finding, projectID string) string {
    h := sha256.New()
    h.Write([]byte(projectID))
    h.Write([]byte("|" + f.RuleID))
    h.Write([]byte("|" + f.URL))
    h.Write([]byte("|" + f.Method))
    h.Write([]byte("|" + f.Parameter))
    return hex.EncodeToString(h.Sum(nil))
}
```

Add the imports `crypto/sha256`, `encoding/hex`, `github.com/jackc/pgx/v5/pgxpool`.

- [ ] **Step 4: Update Start() to receive thin dispatch**

In `Start()`, replace `var job NATSScanJob` with `var msg NATSDispatch`, and call `nw.processScan(ctx, msg)` accordingly.

- [ ] **Step 5: Verify build + commit**

```
go build ./...
git add internal/dast/natsworker.go
git commit -m "refactor(dast): worker resolves dispatch from DB instead of trusting wire format"
git push
```

### Task 1.4: Worker.Run signature alignment + Worker.WorkerID accessor

**Files:**
- Modify: `internal/dast/worker.go`

- [ ] **Step 1: Add `Profile` field to ScanJob (already added in PR D1 — verify present)**
- [ ] **Step 2: Expose WorkerID accessor**

```go
func (w *Worker) WorkerID() string {
    return w.cfg.WorkerID
}
```

- [ ] **Step 3: Build + commit**

```
go build ./...
git add internal/dast/worker.go
git commit -m "feat(dast): expose WorkerID accessor for status persistence"
git push
```

### Task 1.5: Build + deploy PR 1 (worker still missing discovery + auth_resolver — won't fully run yet)

This step intentionally just verifies the build. End-to-end deploy waits until PR 4.

```
go build ./...
go test -short ./internal/dast/...
```

PR 1 is a foundation; runtime e2e verification happens in PR 4.

---

## PR 2 — Endpoint discovery

### Task 2.1: discovery.go skeleton

**Files:**
- Create: `internal/dast/discovery.go`
- Create: `internal/dast/discovery_test.go`

- [ ] **Step 1: Implement DiscoverEndpoints**

```go
// internal/dast/discovery.go
package dast

import (
    "context"
    "encoding/json"
    "encoding/xml"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"

    "github.com/rs/zerolog"
    "golang.org/x/net/html"
)

// DiscoverEndpoints performs lightweight endpoint discovery against a target.
// Sources, in priority order:
//   1. OpenAPI/Swagger spec (probes /openapi.json, /swagger.json, /api-docs)
//   2. sitemap.xml + robots.txt sitemap directive
//   3. One-hop HTML link crawl from base URL
//   4. Common API path probes (/api, /api/v1, /graphql, /actuator/health)
//
// Discovery is bounded: max 50 unique endpoints, 30 s wall clock, 10
// concurrent requests. Discovered endpoints are scoped to the target's
// allowed hosts; out-of-scope candidates are dropped before returning.
func DiscoverEndpoints(ctx context.Context, target *TargetRecord, logger zerolog.Logger) ([]Endpoint, error) {
    log := logger.With().Str("phase", "discovery").Str("base_url", target.BaseURL).Logger()
    timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    httpClient := &http.Client{Timeout: 10 * time.Second}

    discovered := make(map[string]Endpoint) // de-dup by url+method

    // 1. OpenAPI / Swagger
    for _, path := range []string{"/openapi.json", "/swagger.json", "/api-docs", "/v3/api-docs"} {
        if eps := tryOpenAPI(timeoutCtx, httpClient, target.BaseURL+path, target.BaseURL); len(eps) > 0 {
            log.Info().Int("count", len(eps)).Str("source", path).Msg("openapi discovery")
            for _, ep := range eps {
                key := ep.Method + " " + ep.BaseURL + ep.Path
                discovered[key] = ep
            }
            break
        }
    }

    // 2. sitemap.xml
    for _, path := range []string{"/sitemap.xml", "/sitemap_index.xml"} {
        if urls := trySitemap(timeoutCtx, httpClient, target.BaseURL+path); len(urls) > 0 {
            log.Info().Int("count", len(urls)).Str("source", path).Msg("sitemap discovery")
            for _, u := range urls {
                ep, ok := normalize(u, target)
                if !ok {
                    continue
                }
                discovered[ep.Method+" "+ep.BaseURL+ep.Path] = ep
            }
        }
    }

    // 3. robots.txt
    if urls := tryRobots(timeoutCtx, httpClient, target.BaseURL+"/robots.txt"); len(urls) > 0 {
        log.Info().Int("count", len(urls)).Msg("robots discovery")
        for _, u := range urls {
            if ep, ok := normalize(u, target); ok {
                discovered[ep.Method+" "+ep.BaseURL+ep.Path] = ep
            }
        }
    }

    // 4. One-hop HTML link crawl from base
    for _, u := range crawlOneHop(timeoutCtx, httpClient, target.BaseURL) {
        if ep, ok := normalize(u, target); ok {
            discovered[ep.Method+" "+ep.BaseURL+ep.Path] = ep
        }
    }

    // 5. Common API path probes
    for _, path := range []string{"/api", "/api/v1", "/graphql", "/healthz", "/health", "/actuator/health"} {
        u := target.BaseURL + path
        if probeExists(timeoutCtx, httpClient, u) {
            if ep, ok := normalize(u, target); ok {
                discovered[ep.Method+" "+ep.BaseURL+ep.Path] = ep
            }
        }
    }

    // Always include the root.
    if ep, ok := normalize(target.BaseURL, target); ok {
        if _, exists := discovered[ep.Method+" "+ep.BaseURL+ep.Path]; !exists {
            discovered[ep.Method+" "+ep.BaseURL+ep.Path] = ep
        }
    }

    out := make([]Endpoint, 0, len(discovered))
    for _, ep := range discovered {
        out = append(out, ep)
        if len(out) >= 50 {
            break
        }
    }
    log.Info().Int("total", len(out)).Msg("discovery complete")
    return out, nil
}

// normalize parses a candidate URL, validates it against the target's allowed
// hosts, and produces an Endpoint with split BaseURL + Path.
func normalize(rawURL string, target *TargetRecord) (Endpoint, bool) {
    u, err := url.Parse(strings.TrimSpace(rawURL))
    if err != nil || u.Scheme == "" || u.Host == "" {
        return Endpoint{}, false
    }
    hostAllowed := false
    for _, h := range target.AllowedHosts {
        if strings.EqualFold(u.Host, h) {
            hostAllowed = true
            break
        }
    }
    if !hostAllowed {
        return Endpoint{}, false
    }
    base := u.Scheme + "://" + u.Host
    ep := Endpoint{
        Path:    u.Path,
        Method:  "GET",
        BaseURL: base,
    }
    return ep, true
}

func probeExists(ctx context.Context, c *http.Client, u string) bool {
    req, err := http.NewRequestWithContext(ctx, "HEAD", u, nil)
    if err != nil {
        return false
    }
    resp, err := c.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    return resp.StatusCode < 500 && resp.StatusCode != 404
}

func tryOpenAPI(ctx context.Context, c *http.Client, u, base string) []Endpoint {
    req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
    resp, err := c.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil
    }
    body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
    if err != nil {
        return nil
    }
    var spec struct {
        Paths map[string]map[string]any `json:"paths"`
    }
    if err := json.Unmarshal(body, &spec); err != nil {
        return nil
    }
    out := make([]Endpoint, 0, len(spec.Paths))
    for path, methods := range spec.Paths {
        for method := range methods {
            method = strings.ToUpper(method)
            if method == "PARAMETERS" {
                continue
            }
            out = append(out, Endpoint{Path: path, Method: method, BaseURL: base})
        }
    }
    return out
}

func trySitemap(ctx context.Context, c *http.Client, u string) []string {
    req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
    resp, err := c.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil
    }
    body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
    if err != nil {
        return nil
    }
    var sm struct {
        URLs []struct {
            Loc string `xml:"loc"`
        } `xml:"url"`
    }
    if err := xml.Unmarshal(body, &sm); err != nil {
        return nil
    }
    out := make([]string, 0, len(sm.URLs))
    for _, u := range sm.URLs {
        out = append(out, u.Loc)
    }
    return out
}

func tryRobots(ctx context.Context, c *http.Client, u string) []string {
    req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
    resp, err := c.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        return nil
    }
    body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
    if err != nil {
        return nil
    }
    var sitemaps []string
    for _, line := range strings.Split(string(body), "\n") {
        line = strings.TrimSpace(line)
        if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
            sitemaps = append(sitemaps, strings.TrimSpace(line[len("sitemap:"):]))
        }
    }
    var out []string
    for _, s := range sitemaps {
        out = append(out, trySitemap(ctx, c, s)...)
    }
    return out
}

func crawlOneHop(ctx context.Context, c *http.Client, base string) []string {
    req, _ := http.NewRequestWithContext(ctx, "GET", base, nil)
    resp, err := c.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "html") {
        return nil
    }
    body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
    if err != nil {
        return nil
    }
    doc, err := html.Parse(strings.NewReader(string(body)))
    if err != nil {
        return nil
    }
    baseURL, _ := url.Parse(base)
    seen := make(map[string]struct{})
    var out []string
    var walk func(*html.Node)
    walk = func(n *html.Node) {
        if n.Type == html.ElementNode && (n.Data == "a" || n.Data == "form") {
            for _, attr := range n.Attr {
                if attr.Key == "href" || attr.Key == "action" {
                    if abs, err := baseURL.Parse(attr.Val); err == nil {
                        s := abs.String()
                        if _, ok := seen[s]; !ok {
                            seen[s] = struct{}{}
                            out = append(out, s)
                        }
                    }
                }
            }
        }
        for c := n.FirstChild; c != nil; c = c.NextSibling {
            walk(c)
        }
    }
    walk(doc)
    return out
}
```

- [ ] **Step 2: Tests against httptest**

`internal/dast/discovery_test.go` — table-driven tests with mock servers:
- OpenAPI spec serving — verify endpoints extracted
- Sitemap.xml — verify URLs extracted
- Robots.txt with `Sitemap:` directive — chain to sitemap fetch
- HTML page with `<a href>` links — verify one-hop crawl
- Out-of-scope hosts dropped (allowed_hosts filter)

- [ ] **Step 3: Build + commit**

```
go test ./internal/dast/... -run Discover -v
git add internal/dast/discovery.go internal/dast/discovery_test.go
git commit -m "feat(dast): endpoint discovery (openapi + sitemap + robots + crawl + common paths)"
git push
```

---

## PR 3 — Auth resolution

### Task 3.1: auth_resolver.go

**Files:**
- Create: `internal/dast/auth_resolver.go`
- Create: `internal/dast/auth_resolver_test.go`

- [ ] **Step 1: Implement decrypt + AuthConfig builder**

The `auth.auth_configs.encrypted_secret` column is AES-256-GCM ciphertext keyed by `AUTH_PROFILE_ENCRYPTION_KEY` (env var). The schema's `config` jsonb column carries non-secret metadata (token prefix, header names, endpoint URL, username).

```go
// internal/dast/auth_resolver.go
package dast

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "os"

    "github.com/jackc/pgx/v5"

    "github.com/sentinelcore/sentinelcore/internal/authbroker"
)

func (nw *NATSWorker) resolveAuth(ctx context.Context, authConfigID string) (*authbroker.AuthConfig, error) {
    conn, err := nw.repo.pool.Acquire(ctx)
    if err != nil {
        return nil, err
    }
    defer conn.Release()
    if _, err := conn.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
        return nil, err
    }
    var (
        authType  string
        configRaw []byte
        encrypted []byte
    )
    err = conn.QueryRow(ctx, `
        SELECT auth_type, config, COALESCE(encrypted_secret, '\x'::bytea)
        FROM auth.auth_configs
        WHERE id = $1
    `, authConfigID).Scan(&authType, &configRaw, &encrypted)
    if errors.Is(err, pgx.ErrNoRows) {
        return nil, fmt.Errorf("auth config %s not found", authConfigID)
    }
    if err != nil {
        return nil, err
    }

    var config map[string]any
    if err := json.Unmarshal(configRaw, &config); err != nil {
        return nil, fmt.Errorf("config jsonb: %w", err)
    }

    var secret string
    if len(encrypted) > 0 {
        secret, err = decryptSecret(encrypted)
        if err != nil {
            return nil, fmt.Errorf("decrypt secret: %w", err)
        }
    }

    cfg := &authbroker.AuthConfig{
        Type:     authType,
        Config:   config,
        Secret:   secret,
    }
    return cfg, nil
}

// decryptSecret decrypts an AES-256-GCM ciphertext using the
// AUTH_PROFILE_ENCRYPTION_KEY env var. Layout: nonce(12) || ciphertext.
func decryptSecret(blob []byte) (string, error) {
    keyB64 := os.Getenv("AUTH_PROFILE_ENCRYPTION_KEY")
    if keyB64 == "" {
        return "", errors.New("AUTH_PROFILE_ENCRYPTION_KEY not set")
    }
    key, err := base64.StdEncoding.DecodeString(keyB64)
    if err != nil || len(key) != 32 {
        return "", errors.New("AUTH_PROFILE_ENCRYPTION_KEY must be base64-encoded 32 bytes")
    }
    if len(blob) < 12 {
        return "", errors.New("ciphertext too short")
    }
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }
    aead, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    nonce, ct := blob[:12], blob[12:]
    pt, err := aead.Open(nil, nonce, ct, nil)
    if err != nil {
        return "", err
    }
    return string(pt), nil
}
```

(Note: `authbroker.AuthConfig` may have different field names — adapt to the existing struct.)

- [ ] **Step 2: Round-trip tests**

`internal/dast/auth_resolver_test.go`:
- Set AUTH_PROFILE_ENCRYPTION_KEY to a known base64-32-byte
- Encrypt a sample with stdlib AES-GCM
- Pass to decryptSecret
- Assert plaintext matches

- [ ] **Step 3: Build + commit**

```
go test ./internal/dast/... -run Auth -v
git add internal/dast/auth_resolver.go internal/dast/auth_resolver_test.go
git commit -m "feat(dast): auth resolver — decrypt encrypted_secret + build AuthConfig"
git push
```

---

## PR 4 — Orchestrator dispatch slim-down

### Task 4.1: Simplify dispatch in scans.go

**Files:**
- Modify: `internal/controlplane/api/scans.go`

- [ ] **Step 1: Reduce dispatch to thin shape**

Replace the dispatchMsg construction with:
```go
subject := fmt.Sprintf("scan.%s.dispatch", req.ScanType)
dispatchMsg := map[string]any{
    "scan_job_id": id,
    "scan_type":   req.ScanType,
}
msgData, _ := json.Marshal(dispatchMsg)
```

Drop the conditional target_id / source_artifact_id / auth_config_id keys — the worker now reads everything from the DB by scan_job_id.

- [ ] **Step 2: Build + test**

```
go build ./...
go test ./internal/controlplane/...
```

- [ ] **Step 3: Commit**

```
git add internal/controlplane/api/scans.go
git commit -m "refactor(controlplane): slim DAST dispatch to {scan_job_id, scan_type}"
git push
```

### Task 4.2: SAST dispatch alignment (optional consistency)

Check `cmd/sast-worker/main.go` — if SAST also uses `scan_id` field, leave it (working as-is) unless clean-up is desired. Don't break a working pipeline.

---

## PR 5 — Migrations + deploy

### Task 5.1: progress_phase column migration (only if missing)

If PR 0 step 4 found `progress_phase` missing, create:

`migrations/044_scan_jobs_progress_phase.up.sql`:
```sql
ALTER TABLE scans.scan_jobs
    ADD COLUMN IF NOT EXISTS progress_phase TEXT NOT NULL DEFAULT 'pending';
```

`migrations/044_scan_jobs_progress_phase.down.sql`:
```sql
ALTER TABLE scans.scan_jobs DROP COLUMN IF EXISTS progress_phase;
```

Apply to production:
```
ssh okyay@77.42.34.174 "docker exec -i sentinelcore_postgres psql -U sentinelcore -d sentinelcore -v ON_ERROR_STOP=1" < migrations/044_scan_jobs_progress_phase.up.sql
```

### Task 5.2: Build + deploy controlplane + dast-worker

- [ ] **Step 1: Sync source**

```
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-e2e
rsync -az --delete --exclude .git --exclude .next --exclude node_modules --exclude .worktrees --exclude '*.test' \
  ./ okyay@77.42.34.174:/tmp/sentinelcore-src/
```

- [ ] **Step 2: Build both images**

```
ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build -t sentinelcore/controlplane:dast-e2e . 2>&1 | tail -3 && \
  docker build --build-arg SERVICE=dast-worker -t sentinelcore/dast-worker:dast-e2e . 2>&1 | tail -3"
```

- [ ] **Step 3: Add DATABASE_URL + AUTH_PROFILE_ENCRYPTION_KEY to dast-worker compose env**

DB URL is in `/opt/sentinelcore/env/sentinelcore.env`. The dast-worker compose service already loads that env_file (per the override file I wrote earlier). Verify the env file contains `DATABASE_URL` and `AUTH_PROFILE_ENCRYPTION_KEY`. If missing:
```
ssh okyay@77.42.34.174 "grep -E 'DATABASE_URL|AUTH_PROFILE_ENCRYPTION_KEY' /opt/sentinelcore/env/sentinelcore.env"
```
If `AUTH_PROFILE_ENCRYPTION_KEY` is missing, generate one:
```
ssh okyay@77.42.34.174 "echo 'AUTH_PROFILE_ENCRYPTION_KEY='\$(openssl rand -base64 32) | sudo tee -a /opt/sentinelcore/env/sentinelcore.env"
```
(Note: requires sudo — coordinate with user to avoid invalidating existing encrypted secrets if the key is already in use.)

- [ ] **Step 4: Deploy**

```
ssh okyay@77.42.34.174 "docker tag sentinelcore/controlplane:dast-e2e sentinelcore/controlplane:pilot && \
  docker tag sentinelcore/dast-worker:dast-e2e sentinelcore/dast-worker:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d controlplane dast-worker 2>&1 | tail -5 && \
  sleep 3 && docker ps --filter name=sentinelcore_dast_worker --format '{{.Status}}'"
```

- [ ] **Step 5: Smoke test — trigger a scan via the UI or curl**

Login, create a scan against the target. Verify in DB:
```
ssh okyay@77.42.34.174 "docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \"SET row_security=off; SELECT id, scan_type, status, progress_phase, started_at, completed_at FROM scans.scan_jobs ORDER BY created_at DESC LIMIT 3;\""
```
Expected: status transitions queued → running → completed; completed_at set.

```
ssh okyay@77.42.34.174 "docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -c \"SET row_security=off; SELECT rule_id, severity, COUNT(*) FROM findings.findings WHERE finding_type='dast' GROUP BY rule_id, severity;\""
```
Expected: ≥ 1 row (the scan exercised at least one probe — header-injection always fires once even on a static target).

---

## Self-review

| Spec section | Implementing task |
|---|---|
| Worker DB access | PR 1 (1.1, 1.2) |
| Dispatch contract | PR 1 (1.3, 1.4) + PR 4 (4.1) |
| Endpoint discovery | PR 2 |
| Auth resolution | PR 3 |
| Findings persistence | PR 1 repository + 1.3 processScan |
| Status lifecycle | PR 1 repository + 1.3 processScan |
| Tests | PR 1 (repo), PR 2 (discovery), PR 3 (auth) |
| Migration | PR 5 (5.1) |
| Deploy + smoke | PR 5 (5.2) |

Coverage complete.

---

## Execution handoff

Plan covers 5 PRs. Subagent-Driven: per PR.
