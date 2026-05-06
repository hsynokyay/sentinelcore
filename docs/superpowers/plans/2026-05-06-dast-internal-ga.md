# DAST Internal GA — Implementation Plan (Plan #6 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the DAST authentication roadmap by lifting the subsystem to internal GA: a pen-test harness validating the threat model end-to-end, a Prometheus-based observability layer, screenshot-based replay forensics on failure, a 1-command re-record UX, an operations runbook, and an explicit GA checklist.

**Architecture:** 4 PRs. PR A ships `tests/pentest/` with five STRIDE-based black-box attack scripts and a `run.sh` orchestrator producing `report.json`. PR B adds `internal/metrics/dast.go` (Prometheus counters/gauges) + `/metrics` endpoint on controlplane + `deploy/grafana/dast-replay-dashboard.json` + migration 050 (`screenshot_refs` column). PR C adds `internal/authbroker/replay/forensics.go` capturing screenshots on failure into MinIO with envelope encryption + the `forensics-cleanup-worker` for 7-day retention. PR D adds the re-record API + CLI (migration 051) and writes the runbook + GA checklist docs.

**Tech Stack:** Go 1.23, `prometheus/client_golang` (already a transitive dep via NATS lib; verify or add), `chromedp.CaptureScreenshot`, MinIO Go SDK (already in repo), pgx for migrations, no new external services.

**Spec reference:** `docs/superpowers/specs/2026-05-06-dast-internal-ga-design.md`.

**Plan #6 of 6 — final.** Plans #1–#5 merged or in review.

**Scope cuts (deferred to plan #7+):**
- SIEM forwarder for `dast.replay.*` audit events.
- Multi-language customer SDKs (bypass token verifiers).
- External Vault adapters (HashiCorp Vault / AWS SM / Azure KV / GCP SM).
- Distributed circuit breaker (Redis-backed).
- Customer-facing GA artefacts (status page, public SLA, on-call rotation rules).
- Replay anomaly historical analytics / trend charts.

---

## Working environment

- **Branch:** `feat/dast-internal-ga-2026-05` cut from `phase2/api-dast` HEAD.
- **Worktree:** `/Users/okyay/Documents/SentinelCore/.worktrees/dast-internal-ga`.
- **Migrations** start at **050**.
- **Build/deploy** controlplane + new `forensics-cleanup-worker`.

If plans #4 (PR #14) and #5 (PR #15) are not yet merged into `phase2/api-dast` at branch-cut time, base off `feat/dast-replay-hardening-2026-05` (plan #5 branch) instead and adjust the merge target later.

---

## Existing infrastructure (verified post-Plan-#5)

- `internal/authbroker/replay/replayer.go` — `Engine.Replay` with circuit/anomaly/postate/principal hooks.
- `internal/authbroker/replay/circuit.go` — `CircuitStore` interface + `PostgresCircuitStore`. We extend `RecordFailure` to accept screenshot refs.
- `internal/dast/credentials/store.go` — credential store (PR A.5 of plan #5).
- `internal/kms/envelope.go` — `EncryptEnvelope` / `DecryptEnvelope` reused for screenshot bytes.
- `pkg/audit.Emitter` — used everywhere; we add new event types.
- `cmd/notification-worker/main.go` and `cmd/retention-worker/main.go` — model for the new `forensics-cleanup-worker`.
- `deploy/docker-compose/docker-compose.yml` — already joins external `sc-proxy` network. We add the new worker service.

---

## File structure

### New files

| Path | Responsibility |
|------|----------------|
| `migrations/050_dast_forensics.up.sql` | `screenshot_refs JSONB` column on `dast_replay_failures` |
| `migrations/050_dast_forensics.down.sql` | Rollback |
| `migrations/051_dast_bundle_supersede.up.sql` | `superseded_by UUID NULL` + `superseded` status enum |
| `migrations/051_dast_bundle_supersede.down.sql` | Rollback |
| `internal/metrics/dast.go` | Prometheus counters/gauges + `Register` |
| `internal/metrics/dast_test.go` | Counter wiring tests |
| `internal/authbroker/replay/forensics.go` | `Forensics.Capture` + `MinIO`/`KMS` deps |
| `internal/authbroker/replay/forensics_test.go` | Capture/persist behavioural tests |
| `cmd/forensics-cleanup-worker/main.go` | 7-day MinIO cleanup loop |
| `cmd/forensics-cleanup-worker/main_test.go` | Loop unit test |
| `internal/dast/bundles/re_record.go` | `ReRecord(ctx, oldID)` business logic |
| `internal/dast/bundles/re_record_test.go` | Status transition tests |
| `internal/controlplane/re_record_handler.go` | `POST /api/v1/dast/bundles/:id/re-record` |
| `internal/controlplane/re_record_handler_test.go` | Auth + state tests |
| `internal/cli/dast_bundles.go` | `list --status` filter + `re-record` shortcut |
| `internal/cli/dast_bundles_test.go` | Flag parser + dispatcher tests |
| `tests/pentest/stride/spoof_bundle_integrity_test.go` | pt-01 |
| `tests/pentest/stride/jwt_replay_test.go` | pt-02 |
| `tests/pentest/stride/rls_bypass_test.go` | pt-03 |
| `tests/pentest/stride/sql_injection_credentials_test.go` | pt-04 |
| `tests/pentest/stride/csrf_circuit_reset_test.go` | pt-05 |
| `tests/pentest/run.sh` | Orchestrator + `report.json` |
| `tests/pentest/README.md` | Execution + interpretation |
| `deploy/grafana/dast-replay-dashboard.json` | Customer-imported dashboard |
| `docs/runbooks/dast-replay.md` | Operations runbook |
| `docs/superpowers/specs/2026-05-06-dast-ga-checklist.md` | GA pass criteria |

### Modified files

| Path | Reason |
|------|--------|
| `internal/authbroker/replay/replayer.go` | Call `metrics.*.Inc` per branch; on failure call `Forensics.Capture` |
| `internal/authbroker/replay/circuit.go` | `RecordFailure(ctx, id, errMsg, screenshotRef)` accepts new ref; appends to JSONB |
| `cmd/controlplane/main.go` | Mount `/metrics` route + register dast metrics |
| `internal/dast/credentials/store.go` | `Load` increments `metrics.CredentialLoadTotal` |
| `internal/dast/bundles/store.go` | Status enum + `superseded_by` column |
| `deploy/docker-compose/docker-compose.yml` | New `forensics-cleanup-worker` service |
| `cmd/cli/dast.go` | Wire `bundles list/re-record` subcommand |

---

## PR 0 — Pre-flight

- [ ] **Step 1: Worktree**

```
cd /Users/okyay/Documents/SentinelCore
git fetch origin
git worktree add /Users/okyay/Documents/SentinelCore/.worktrees/dast-internal-ga \
  -b feat/dast-internal-ga-2026-05 origin/phase2/api-dast
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-internal-ga
```

If plan #5 is unmerged, swap `origin/phase2/api-dast` for `feat/dast-replay-hardening-2026-05`.

- [ ] **Step 2: Verify deps**

```
go list -m all | grep prometheus
```

If `github.com/prometheus/client_golang` is absent, run `go get github.com/prometheus/client_golang` and verify `go.mod` change is minimal.

- [ ] **Step 3: Sanity build**

```
go build ./internal/... ./cmd/...
```

Expected: clean.

- [ ] **Step 4: Rollback tag**

```
git tag pre-internal-ga-$(date +%Y%m%d)
git push origin pre-internal-ga-$(date +%Y%m%d)
```

---

## PR A — Pen-test harness (3 tasks)

### Task A.1: Harness skeleton + orchestrator

**Files:**
- Create: `tests/pentest/run.sh`
- Create: `tests/pentest/README.md`
- Create: `tests/pentest/stride/doc.go`

- [ ] **Step 1: README**

Document execution: `SENTINELCORE_HOST=https://staging.sentinelcore.example SENTINELCORE_API_TOKEN=xxx ./run.sh`. Document interpretation: `report.json` schema with per-test `{id, status, duration_ms, evidence}`. Document PASS criterion: every test status=PASS.

- [ ] **Step 2: Orchestrator**

```bash
#!/usr/bin/env bash
# tests/pentest/run.sh
set -euo pipefail
: "${SENTINELCORE_HOST:?must export}"
: "${SENTINELCORE_API_TOKEN:?must export}"

OUT=tests/pentest/report.json
RAW=tests/pentest/raw.jsonl

go test -tags pentest -json ./tests/pentest/stride/... > "$RAW" || true

jq -s '
  [.[] | select(.Action == "pass" or .Action == "fail")
       | { id: (.Test // "unknown"),
           status: (.Action | ascii_upcase),
           pkg: .Package,
           elapsed_s: (.Elapsed // 0) }]
  | { run_at: now | todate, total: length,
      passed: ([.[] | select(.status=="PASS")] | length),
      failed: ([.[] | select(.status=="FAIL")] | length),
      tests: . }' "$RAW" > "$OUT"

jq -r 'if .failed > 0 then "FAIL: \(.failed)/\(.total)" else "PASS: \(.passed)/\(.total)" end' "$OUT"
```

- [ ] **Step 3: doc.go**

```go
//go:build pentest

// Package stride contains black-box pen-test scripts for the SentinelCore
// DAST authentication subsystem. Each test exercises a distinct STRIDE
// threat against a deployed staging stack. Build tag `pentest` keeps the
// suite out of normal CI runs; invoke explicitly via tests/pentest/run.sh.
package stride
```

- [ ] **Step 4: Commit**

```
chmod +x tests/pentest/run.sh
git add tests/pentest/
git commit -m "test(pentest): harness skeleton + orchestrator"
```

### Task A.2: STRIDE attack scripts pt-01..05

**Files:**
- Create: `tests/pentest/stride/spoof_bundle_integrity_test.go`
- Create: `tests/pentest/stride/jwt_replay_test.go`
- Create: `tests/pentest/stride/rls_bypass_test.go`
- Create: `tests/pentest/stride/sql_injection_credentials_test.go`
- Create: `tests/pentest/stride/csrf_circuit_reset_test.go`

Each script is a single Go test with build tag `pentest`. Each reads `os.Getenv("SENTINELCORE_HOST")` and `os.Getenv("SENTINELCORE_API_TOKEN")`, performs the attack, asserts the expected refusal. Skeleton:

```go
//go:build pentest

package stride

import (
    "net/http"
    "os"
    "testing"
)

func TestPT_NN_AttackName(t *testing.T) {
    host := os.Getenv("SENTINELCORE_HOST")
    if host == "" {
        t.Skip("SENTINELCORE_HOST not set")
    }
    // ... craft attack
    // assert response code / body / state
}
```

- [ ] **Step 1: pt-01 spoof_bundle_integrity_test.go**

The test fetches a bundle's canonical JSON (via API), tampers a single byte, recomputes a wrong HMAC, submits via the bundle update endpoint, asserts 400 with body containing `"integrity"`. If no bundle update endpoint exists, exercise the integrity check via a direct DB INSERT path through the staging admin API and assert the bundle Load returns an integrity error.

- [ ] **Step 2: pt-02 jwt_replay_test.go**

Mint a JWT for customer A (via the staging auth endpoint or a fixture). Try to GET `/api/v1/dast/bundles/<customer-B-bundle-id>` with that token. Assert 403 or 404 (RLS suppresses the row).

- [ ] **Step 3: pt-03 rls_bypass_test.go**

Connect to postgres directly with a service-role connection string. Set `SET LOCAL app.customer_id = '<victim-uuid>'`. Run `SELECT * FROM dast_credential_secrets`. Assert 0 rows OR an error from the policy. Connection string from env `PT_DB_URL`; skip if absent.

- [ ] **Step 4: pt-04 sql_injection_credentials_test.go**

Invoke the credentials CLI with `--key "x'); DROP TABLE dast_credential_secrets; --"`. Capture output; verify the table still exists by querying it post-attack. Assert no rows were silently dropped.

- [ ] **Step 5: pt-05 csrf_circuit_reset_test.go**

Issue an unauthenticated cross-origin POST to `/api/v1/dast/bundles/<id>/circuit/reset` with `Origin: https://evil.example`. Assert 401 or 403. Also issue an authenticated request from a low-priv role (NOT `recording_admin`); assert 403.

- [ ] **Step 6: Run + commit**

```
SENTINELCORE_HOST=https://localhost:8443 SENTINELCORE_API_TOKEN=fake \
  go test -tags pentest -count=1 ./tests/pentest/stride/...
```

(Tests skip on missing env / unreachable host — that's expected for offline development.)

```
git add tests/pentest/stride/
git commit -m "test(pentest): pt-01..05 STRIDE attack scripts"
```

### Task A.3: Push

```
git push -u origin feat/dast-internal-ga-2026-05
```

PR A complete.

---

## PR B — Metrics + dashboard (4 tasks)

### Task B.1: Migration 050

**Files:**
- Create: `migrations/050_dast_forensics.up.sql`
- Create: `migrations/050_dast_forensics.down.sql`

- [ ] **Step 1: Up**

```sql
ALTER TABLE dast_replay_failures
    ADD COLUMN IF NOT EXISTS screenshot_refs JSONB NOT NULL DEFAULT '[]'::jsonb;
```

- [ ] **Step 2: Down**

```sql
ALTER TABLE dast_replay_failures DROP COLUMN IF EXISTS screenshot_refs;
```

- [ ] **Step 3: Commit**

```
git add migrations/050_dast_forensics.up.sql migrations/050_dast_forensics.down.sql
git commit -m "feat(db): dast_replay_failures.screenshot_refs JSONB"
```

### Task B.2: Metrics package

**Files:**
- Create: `internal/metrics/dast.go`
- Create: `internal/metrics/dast_test.go`

- [ ] **Step 1: Implement**

```go
// internal/metrics/dast.go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    ReplayTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "dast_replay_total",
        Help: "DAST replay attempts by result",
    }, []string{"result"})

    CircuitState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
        Name: "dast_replay_circuit_state",
        Help: "Circuit state per bundle (0=closed, 1=open)",
    }, []string{"bundle_id"})

    AnomalyTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "dast_replay_anomaly_total",
        Help: "Replay anomaly events",
    })

    PostStateMismatchTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "dast_replay_postate_mismatch_total",
        Help: "Replay post-state hash mismatches",
    })

    PrincipalMismatchTotal = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "dast_replay_principal_mismatch_total",
        Help: "Replay principal binding mismatches",
    })

    CredentialLoadTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "dast_credential_load_total",
        Help: "Credential store Load attempts by result",
    }, []string{"result"})
)

// Register registers all DAST metrics with r. Call from controlplane main.
func Register(r prometheus.Registerer) error {
    for _, c := range []prometheus.Collector{
        ReplayTotal, CircuitState, AnomalyTotal,
        PostStateMismatchTotal, PrincipalMismatchTotal, CredentialLoadTotal,
    } {
        if err := r.Register(c); err != nil {
            // tolerate already-registered (e.g. test reruns)
            if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
                return err
            }
        }
    }
    return nil
}
```

- [ ] **Step 2: Test**

```go
// internal/metrics/dast_test.go
package metrics

import (
    "testing"

    "github.com/prometheus/client_golang/prometheus"
    dto "github.com/prometheus/client_model/go"
)

func gather(t *testing.T, c prometheus.Collector) []*dto.Metric {
    ch := make(chan prometheus.Metric, 16)
    c.Collect(ch)
    close(ch)
    out := []*dto.Metric{}
    for m := range ch {
        var pb dto.Metric
        if err := m.Write(&pb); err != nil {
            t.Fatal(err)
        }
        out = append(out, &pb)
    }
    return out
}

func TestReplayTotalIncrements(t *testing.T) {
    ReplayTotal.WithLabelValues("success").Inc()
    metrics := gather(t, ReplayTotal)
    if len(metrics) == 0 {
        t.Fatal("no metrics gathered")
    }
}

func TestRegisterIsIdempotent(t *testing.T) {
    r := prometheus.NewRegistry()
    if err := Register(r); err != nil {
        t.Fatal(err)
    }
    if err := Register(r); err != nil {
        t.Fatalf("second register must be tolerant: %v", err)
    }
}
```

- [ ] **Step 3: Run + commit**

```
go test ./internal/metrics/ -v
git add internal/metrics/dast.go internal/metrics/dast_test.go
git commit -m "feat(metrics): dast replay + credential prometheus collectors"
```

### Task B.3: Wire metrics into engine + credentials + circuit

**Files:**
- Modify: `internal/authbroker/replay/replayer.go`
- Modify: `internal/authbroker/replay/circuit.go`
- Modify: `internal/dast/credentials/store.go`

- [ ] **Step 1: Engine.Replay**

Add `metrics.ReplayTotal.WithLabelValues("success").Inc()` on the success return. Add `metrics.ReplayTotal.WithLabelValues("failure_circuit").Inc()` when circuit-open path returns. Similar for `failure_anomaly`, `failure_postate`, `failure_principal`, `failure_other`.

In the post-state mismatch branch: `metrics.PostStateMismatchTotal.Inc()` plus `ReplayTotal.failure_postate`. In the principal mismatch: `metrics.PrincipalMismatchTotal.Inc()` plus `ReplayTotal.failure_principal`. Anomaly: `AnomalyTotal.Inc()` plus `ReplayTotal.failure_anomaly`.

- [ ] **Step 2: Circuit state gauge**

Extend `PostgresCircuitStore.IsOpen` to call `metrics.CircuitState.WithLabelValues(bundleID.String()).Set(0 or 1)` before returning. Keep the gauge eventually consistent — no separate broadcast pump needed.

- [ ] **Step 3: Credentials**

In `PostgresStore.Load`, on success: `metrics.CredentialLoadTotal.WithLabelValues("success").Inc()`. On `pgx.ErrNoRows` / `ErrNotFound`: `"not_found"`. On AAD/decrypt error: `"decrypt_error"`.

- [ ] **Step 4: Run + commit**

```
go build ./internal/authbroker/... ./internal/dast/...
go test ./internal/authbroker/... ./internal/dast/credentials/...
git add internal/authbroker/replay/replayer.go \
        internal/authbroker/replay/circuit.go \
        internal/dast/credentials/store.go
git commit -m "feat(replay,credentials): emit prometheus metrics on each branch"
```

### Task B.4: /metrics endpoint + dashboard JSON

**Files:**
- Modify: `cmd/controlplane/main.go` (or wherever the controlplane HTTP server boots)
- Create: `deploy/grafana/dast-replay-dashboard.json`

- [ ] **Step 1: Mount route**

In the controlplane bootstrap, after server constructor:

```go
import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/sentinelcore/sentinelcore/internal/metrics"
)

reg := prometheus.NewRegistry()
if err := metrics.Register(reg); err != nil {
    log.Fatalf("metrics register: %v", err)
}
mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
```

The route is intentionally unauthenticated; rely on network isolation (compose `expose:` only).

- [ ] **Step 2: Dashboard JSON**

Hand-craft a minimal Grafana dashboard JSON with 6 panels (success rate, open circuits, anomalies/5m, postate/5m, principal/1h, credential failures/5m). The JSON only needs to be valid Grafana 11.x format — no need to test it programmatically. Reference an existing repo's dashboard if available; otherwise produce a hand-edited template.

- [ ] **Step 3: Smoke**

Run controlplane locally, `curl http://localhost:8080/metrics` and confirm output includes `dast_replay_total`. (Document the curl command in the runbook later.)

- [ ] **Step 4: Commit + push**

```
git add cmd/controlplane/main.go deploy/grafana/dast-replay-dashboard.json
git commit -m "feat(controlplane): /metrics endpoint + dast dashboard JSON"
git push
```

PR B complete.

---

## PR C — Screenshot forensics on failure (4 tasks)

### Task C.1: Forensics package

**Files:**
- Create: `internal/authbroker/replay/forensics.go`
- Create: `internal/authbroker/replay/forensics_test.go`

- [ ] **Step 1: Implement**

```go
// internal/authbroker/replay/forensics.go
package replay

import (
    "context"
    "fmt"
    "time"

    "github.com/chromedp/chromedp"
    "github.com/google/uuid"
    "github.com/minio/minio-go/v7"

    "github.com/sentinelcore/sentinelcore/internal/kms"
)

const ForensicsBucket = "dast-forensics"

// MinIOClient is the subset of *minio.Client we need; allows test fakes.
type MinIOClient interface {
    PutObject(ctx context.Context, bucket, object string, reader interface{}, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
    RemoveObject(ctx context.Context, bucket, object string, opts minio.RemoveObjectOptions) error
}

type Forensics struct {
    KMS   kms.Provider
    MinIO MinIOClient
}

// Capture grabs a PNG screenshot from the active chromedp context, envelope-
// encrypts it with bundleID as AAD, and PUTs to MinIO. Returns the object
// key on success.
func (f *Forensics) Capture(ctx context.Context, bundleID uuid.UUID, actionIdx int) (string, error) {
    if f == nil || f.KMS == nil || f.MinIO == nil {
        return "", fmt.Errorf("forensics: not configured")
    }

    var png []byte
    if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&png)); err != nil {
        return "", fmt.Errorf("forensics: screenshot: %w", err)
    }

    env, err := kms.EncryptEnvelope(ctx, f.KMS, "dast.forensic", png, []byte(bundleID.String()))
    if err != nil {
        return "", fmt.Errorf("forensics: encrypt: %w", err)
    }

    key := fmt.Sprintf("bundle/%s/%s-%d.png.enc",
        bundleID,
        time.Now().UTC().Format("20060102T150405Z"),
        actionIdx,
    )
    payload, err := serializeEnvelope(env)
    if err != nil { return "", err }

    _, err = f.MinIO.PutObject(ctx, ForensicsBucket, key,
        bytesReader(payload), int64(len(payload)),
        minio.PutObjectOptions{ContentType: "application/octet-stream"})
    if err != nil {
        return "", fmt.Errorf("forensics: upload: %w", err)
    }
    return key, nil
}

// serializeEnvelope packs the kms.Envelope into a byte slice for storage.
// Use the existing helper if one already exists in pkg/kms or internal/kms.
func serializeEnvelope(env *kms.Envelope) ([]byte, error) {
    // implement using existing canonical encoding (e.g. JSON or gob)
    return nil, nil // TODO: link to existing helper if present
}

// bytesReader wraps a []byte as an io.Reader; replace with bytes.NewReader.
func bytesReader(b []byte) interface{} {
    panic("inline bytes.NewReader(b) at call site")
}
```

(The plan uses placeholders for `serializeEnvelope` and `bytesReader` — replace at implementation time with `bytes.NewReader` directly and the project's existing envelope serialization helper if present, or `json.Marshal(env)` if not.)

- [ ] **Step 2: Tests**

Tests use a fake MinIO client to assert:
- `Capture` rejects when not configured.
- Successful PutObject path stores under the right key format `bundle/<id>/<ts>-<idx>.png.enc`.
- Encrypt failure surfaces wrapped error.
- chromedp screenshot failure surfaces wrapped error (use a context that has no chromedp target).

- [ ] **Step 3: Commit**

```
go test ./internal/authbroker/replay/ -run TestForensics -v
git add internal/authbroker/replay/forensics.go internal/authbroker/replay/forensics_test.go
git commit -m "feat(replay): forensics package — chromedp screenshot + envelope-encrypted MinIO put"
```

### Task C.2: Engine integration + circuit ref persistence

**Files:**
- Modify: `internal/authbroker/replay/replayer.go`
- Modify: `internal/authbroker/replay/circuit.go`

- [ ] **Step 1: Engine carries Forensics**

```go
type Engine struct {
    rateLimit *RateLimit
    circuit   CircuitStore
    creds     credentials.Store
    forensics *Forensics  // optional; nil → skip capture
}

func (e *Engine) WithForensics(f *Forensics) *Engine { e.forensics = f; return e }
```

- [ ] **Step 2: Capture on failure**

In every error-return path inside the per-action loop AND the pre-flight chain, call (best-effort):

```go
if e.forensics != nil {
    if ref, capErr := e.forensics.Capture(timeoutCtx, mustParseUUID(b.ID), i); capErr == nil {
        screenshotRef = ref
    }
}
if e.circuit != nil {
    _ = e.circuit.RecordFailure(ctx, mustParseUUID(b.ID), err.Error(), screenshotRef)
}
```

- [ ] **Step 3: Circuit JSONB append**

Change the `CircuitStore` interface signature:

```go
type CircuitStore interface {
    IsOpen(ctx context.Context, bundleID uuid.UUID) (bool, error)
    RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg, screenshotRef string) error
    Reset(ctx context.Context, bundleID uuid.UUID) error
}
```

Update the SQL in `PostgresCircuitStore.RecordFailure`:

```go
INSERT INTO dast_replay_failures (bundle_id, consecutive_failures, last_failure_at, last_error, screenshot_refs)
VALUES ($1, 1, NOW(), $2, CASE WHEN $3 = '' THEN '[]'::jsonb ELSE jsonb_build_array($3) END)
ON CONFLICT (bundle_id) DO UPDATE
SET consecutive_failures = dast_replay_failures.consecutive_failures + 1,
    last_failure_at      = EXCLUDED.last_failure_at,
    last_error           = EXCLUDED.last_error,
    screenshot_refs      = CASE WHEN $3 = '' THEN dast_replay_failures.screenshot_refs
                                ELSE dast_replay_failures.screenshot_refs || jsonb_build_array($3)
                           END
```

Update `Reset` to also clear `screenshot_refs = '[]'::jsonb`.

- [ ] **Step 4: Run + commit**

```
go build ./internal/authbroker/... ./internal/dast/...
go test ./internal/authbroker/replay/...
git add internal/authbroker/replay/replayer.go internal/authbroker/replay/circuit.go
git commit -m "feat(replay): capture forensic screenshot on failure + persist refs to circuit row"
```

### Task C.3: Forensics cleanup worker

**Files:**
- Create: `cmd/forensics-cleanup-worker/main.go`
- Create: `cmd/forensics-cleanup-worker/main_test.go`
- Modify: `deploy/docker-compose/docker-compose.yml`

- [ ] **Step 1: Implement**

```go
package main

import (
    "context"
    "encoding/json"
    "log"
    "os"
    "time"

    "github.com/google/uuid"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/minio/minio-go/v7"
)

func main() {
    interval := envDuration("INTERVAL", 1*time.Hour)
    olderThan := envDuration("OLDER_THAN", 7*24*time.Hour)
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    pool, mc := mustConnect()
    defer pool.Close()
    for {
        if err := runOnce(context.Background(), pool, mc, olderThan); err != nil {
            log.Printf("cleanup: %v", err)
        }
        <-ticker.C
    }
}

func runOnce(ctx context.Context, pool *pgxpool.Pool, mc *minio.Client, olderThan time.Duration) error {
    rows, err := pool.Query(ctx, `
        SELECT bundle_id, screenshot_refs
        FROM dast_replay_failures
        WHERE last_failure_at < NOW() - $1::interval
          AND jsonb_array_length(screenshot_refs) > 0
    `, fmt.Sprintf("%d seconds", int(olderThan.Seconds())))
    if err != nil { return err }
    defer rows.Close()
    for rows.Next() {
        var bundleID uuid.UUID
        var refsJSON []byte
        if err := rows.Scan(&bundleID, &refsJSON); err != nil { return err }
        var refs []string
        _ = json.Unmarshal(refsJSON, &refs)
        for _, key := range refs {
            _ = mc.RemoveObject(ctx, "dast-forensics", key, minio.RemoveObjectOptions{})
        }
        _, err = pool.Exec(ctx,
            `UPDATE dast_replay_failures SET screenshot_refs = '[]'::jsonb WHERE bundle_id = $1`,
            bundleID)
        if err != nil { return err }
    }
    return rows.Err()
}
```

(Helper functions `envDuration`, `mustConnect` defined inline; copy from `cmd/retention-worker/main.go`.)

- [ ] **Step 2: Test**

`runOnce` with a mock pool / mock MinIO client. Assert that rows older than the threshold trigger RemoveObject + UPDATE; rows newer than threshold are untouched.

- [ ] **Step 3: Compose service**

Add to `deploy/docker-compose/docker-compose.yml`:

```yaml
forensics-cleanup-worker:
  build:
    context: ../..
    dockerfile: Dockerfile
    args:
      SERVICE: forensics-cleanup-worker
  environment:
    DB_HOST: postgres
    DB_NAME: sentinelcore
    DB_USER: sentinelcore
    DB_PASSWORD: ${DB_PASSWORD:?required}
    INTERVAL: 1h
    OLDER_THAN: 168h
    MINIO_ENDPOINT: minio:9000
    MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY:?required}
    MINIO_SECRET_KEY: ${MINIO_SECRET_KEY:?required}
  depends_on:
    postgres:
      condition: service_healthy
    minio:
      condition: service_started
```

- [ ] **Step 4: Build + commit**

```
go build ./cmd/forensics-cleanup-worker/
go test ./cmd/forensics-cleanup-worker/
git add cmd/forensics-cleanup-worker/ deploy/docker-compose/docker-compose.yml
git commit -m "feat(forensics): cleanup-worker for 7-day screenshot retention"
```

### Task C.4: Sec regression — successful replays produce no screenshot

**Files:**
- Modify: `internal/dast/security_regression_replay_test.go`

- [ ] **Step 1: Add test**

```go
// sec-10: forensics privacy — successful replay does NOT capture screenshots.
func TestSec10_ForensicsOnlyOnFailure(t *testing.T) {
    fakeF := &fakeForensics{}
    e := replay.NewEngine().WithForensics(fakeF) // assumes WithForensics accepts *Forensics-shaped iface
    // Drive a happy-path replay (use the existing happy-path setup from replayer_test.go).
    // ...
    if fakeF.calls != 0 {
        t.Fatalf("Capture called %d times on success path", fakeF.calls)
    }
}
```

(If `WithForensics` accepts a concrete `*Forensics`, refactor to accept an interface to allow test injection.)

- [ ] **Step 2: Run + commit + push**

```
go test ./internal/dast/ -run "TestSec1[0]" -v
git add internal/dast/security_regression_replay_test.go
git commit -m "test(dast): sec-10 forensics privacy — no capture on success path"
git push
```

PR C complete.

---

## PR D — Re-record UX + runbook + GA checklist (5 tasks)

### Task D.1: Migration 051

**Files:**
- Create: `migrations/051_dast_bundle_supersede.up.sql`
- Create: `migrations/051_dast_bundle_supersede.down.sql`

- [ ] **Step 1: Up**

```sql
ALTER TABLE dast_auth_bundles
    ADD COLUMN IF NOT EXISTS superseded_by UUID NULL REFERENCES dast_auth_bundles(id);

-- Add 'superseded' to the status check constraint.
ALTER TABLE dast_auth_bundles DROP CONSTRAINT IF EXISTS dast_auth_bundles_status_check;
ALTER TABLE dast_auth_bundles ADD CONSTRAINT dast_auth_bundles_status_check
    CHECK (status IN ('pending_review','approved','revoked','refresh_required','expired','soft_deleted','superseded'));
```

- [ ] **Step 2: Down**

```sql
ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS superseded_by;
ALTER TABLE dast_auth_bundles DROP CONSTRAINT IF EXISTS dast_auth_bundles_status_check;
ALTER TABLE dast_auth_bundles ADD CONSTRAINT dast_auth_bundles_status_check
    CHECK (status IN ('pending_review','approved','revoked','refresh_required','expired','soft_deleted'));
```

- [ ] **Step 3: Commit**

```
git add migrations/051_dast_bundle_supersede.up.sql migrations/051_dast_bundle_supersede.down.sql
git commit -m "feat(db): dast_auth_bundles supersede column + status enum"
```

### Task D.2: Re-record business logic + handler + CLI

**Files:**
- Create: `internal/dast/bundles/re_record.go`
- Create: `internal/dast/bundles/re_record_test.go`
- Create: `internal/controlplane/re_record_handler.go`
- Create: `internal/controlplane/re_record_handler_test.go`
- Create: `internal/cli/dast_bundles.go`
- Create: `internal/cli/dast_bundles_test.go`
- Modify: `cmd/cli/dast.go` — wire `bundles` subcommand

- [ ] **Step 1: ReRecord business logic**

```go
// internal/dast/bundles/re_record.go
package bundles

func ReRecord(ctx context.Context, store Store, oldID, callerUserID, callerOrgID, reason string) (*Bundle, error) {
    src, err := store.Load(ctx, oldID, callerOrgID)
    if err != nil { return nil, err }
    // Mark source superseded.
    src.Status = "superseded"
    if _, err := store.Save(ctx, src, callerOrgID); err != nil { return nil, err }
    // Build new draft (empty actions, status=pending_review).
    nu := &Bundle{
        SchemaVersion:   src.SchemaVersion,
        CustomerID:      src.CustomerID,
        ProjectID:       src.ProjectID,
        TargetHost:      src.TargetHost,
        TargetPrincipal: src.TargetPrincipal,
        PrincipalClaim:  src.PrincipalClaim,
        Type:            src.Type,
        TTLSeconds:      src.TTLSeconds,
        CreatedByUserID: callerUserID,
        CreatedAt:       time.Now().UTC(),
        ExpiresAt:       time.Now().UTC().Add(time.Duration(src.TTLSeconds)*time.Second),
        // Status defaults to "pending_review" via store.Save(...) flow.
    }
    newID, err := store.Save(ctx, nu, callerOrgID)
    if err != nil { return nil, err }
    nu.ID = newID
    // Link old → new for audit trail.
    src.SupersededBy = newID
    _, _ = store.Save(ctx, src, callerOrgID)
    return nu, nil
}
```

`SupersededBy string` field added to `Bundle` (and `canonicalBundle`).

- [ ] **Step 2: Tests**

Postgres-backed tests assert:
- ReRecord on a missing bundle → error.
- ReRecord on a normal bundle: source flips to `superseded`, new bundle has `pending_review`, `superseded_by` link populated.
- ReRecord on already-superseded → error or idempotent (pick one — error is safer).

- [ ] **Step 3: HTTP handler**

```go
// internal/controlplane/re_record_handler.go
func ReRecordHandler(store bundles.Store) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        oldID := chiURLParam(r, "id") // adapt to actual router
        var req struct{ Reason string `json:"reason"` }
        _ = json.NewDecoder(r.Body).Decode(&req)
        userID, orgID := authFromContext(r.Context())
        nu, err := bundles.ReRecord(r.Context(), store, oldID, userID, orgID, req.Reason)
        if err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        json.NewEncoder(w).Encode(map[string]string{"new_bundle_id": nu.ID})
    }
}
```

Wire route with `RequireDASTRole(roleStore, RoleRecordingAdmin)` middleware.

- [ ] **Step 4: CLI**

```go
// internal/cli/dast_bundles.go
func RunBundlesCommand(args []string, /*deps*/) error {
    if len(args) < 1 {
        return fmt.Errorf("usage: dast bundles list|re-record ...")
    }
    switch args[0] {
    case "list":     return runBundlesList(args[1:])
    case "re-record":return runBundlesReRecord(args[1:])
    default:         return fmt.Errorf("unknown subcommand %q", args[0])
    }
}
```

`list --status refresh_required` filters; output is one line per bundle id + status. `re-record <id>` calls the API endpoint, prints the new bundle id, then optionally chains `dast record --bundle <new-id>` if the operator passes `--start-recording`.

- [ ] **Step 5: Wire dispatcher**

In `cmd/cli/dast.go`, add `case "bundles":` arm calling `cli.RunBundlesCommand`.

- [ ] **Step 6: Run + commit**

```
go build ./internal/... ./cmd/...
go test ./internal/dast/bundles/ ./internal/controlplane/ ./internal/cli/
git add internal/dast/bundles/re_record.go \
        internal/dast/bundles/re_record_test.go \
        internal/controlplane/re_record_handler.go \
        internal/controlplane/re_record_handler_test.go \
        internal/cli/dast_bundles.go \
        internal/cli/dast_bundles_test.go \
        cmd/cli/dast.go
git commit -m "feat(dast): bundle re-record API + CLI + supersede status (D.2)"
```

### Task D.3: Operations runbook

**Files:**
- Create: `docs/runbooks/dast-replay.md`

- [ ] **Step 1: Write**

Sections per spec §7.1:
1. **Triage matrix** — for each common alert (circuit open, postate mismatch, principal mismatch, captcha-mark, anomaly), provide the 3 first commands operators should run (psql query, docker logs grep, MinIO ls). Include exact SQL.
2. **Common failure modes** — root cause hypothesis tree per failure type, recovery action.
3. **Rollback playbook** — for each migration 047/048/049/050/051: down command, expected duration (small tables), data loss implications (forensic screenshots dropped, credentials dropped, recordings dropped — be explicit).
4. **Escalation path** — when to wake whom; what evidence to gather (db snapshot, MinIO ref list, audit log slice).
5. **Forensic access** — how an operator with `recording_admin` role + KMS key access retrieves a screenshot.

- [ ] **Step 2: Commit**

```
git add docs/runbooks/dast-replay.md
git commit -m "docs(runbook): DAST replay operations runbook"
```

### Task D.4: GA checklist doc

**Files:**
- Create: `docs/superpowers/specs/2026-05-06-dast-ga-checklist.md`

- [ ] **Step 1: Write**

Eight checklist items per spec §7.2 — each with explicit pass criterion AND verification command/procedure.

- [ ] **Step 2: Commit + push**

```
git add docs/superpowers/specs/2026-05-06-dast-ga-checklist.md
git commit -m "docs(spec): DAST internal GA checklist with explicit pass criteria"
git push
```

### Task D.5: Build + deploy + open PR

```
rsync -az --delete --exclude .git --exclude '*.test' --exclude '.worktrees' --exclude 'web' \
  internal migrations pkg rules scripts cmd Dockerfile go.mod go.sum customer-sdks deploy \
  okyay@77.42.34.174:/tmp/sentinelcore-src/

ssh okyay@77.42.34.174 "cp /tmp/sentinelcore-src/migrations/050_dast_forensics.up.sql /opt/sentinelcore/migrations/ && \
  cp /tmp/sentinelcore-src/migrations/051_dast_bundle_supersede.up.sql /opt/sentinelcore/migrations/ && \
  docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -f /migrations/050_dast_forensics.up.sql && \
  docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -f /migrations/051_dast_bundle_supersede.up.sql"

ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build --no-cache -t sentinelcore/controlplane:internal-ga-prd --build-arg SERVICE=controlplane . && \
  docker build --no-cache -t sentinelcore/forensics-cleanup-worker:internal-ga-prd --build-arg SERVICE=forensics-cleanup-worker . && \
  docker tag sentinelcore/controlplane:internal-ga-prd sentinelcore/controlplane:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d --force-recreate controlplane forensics-cleanup-worker"

curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\nmetrics: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz \
  https://sentinelcore.resiliencetech.com.tr/readyz \
  https://sentinelcore.resiliencetech.com.tr/metrics

gh pr create --base phase2/api-dast --head feat/dast-internal-ga-2026-05 \
  --title "feat(dast): internal GA — pen-test + observability + forensics + re-record (plan #6/6)" \
  --body "Plan #6 — closes the DAST authentication roadmap. Spec: docs/superpowers/specs/2026-05-06-dast-internal-ga-design.md."
```

PR D complete. Plan #6 done.

---

## Self-review

### Spec coverage

| Spec section | Implementing task |
|--------------|-------------------|
| §3 Pen-test harness | A.1 + A.2 |
| §4.1–4.2 Metrics package | B.2 |
| §4.3 Dashboard | B.4 |
| §4.4 Migration 050 | B.1 |
| §5 Forensics | C.1 + C.2 + C.3 |
| §6 Re-record UX | D.1 + D.2 |
| §7.1 Runbook | D.3 |
| §7.2 GA checklist | D.4 |
| §8 Migrations 050+051 | B.1 + D.1 |
| §9 Audit events | spread across C.1, C.3, D.2 (each emit-site adds the new event type) |
| §10 Rollout | D.5 |

### Type / signature consistency

- `metrics.ReplayTotal`, `metrics.CircuitState`, etc. defined in B.2; consumed in B.3 (engine) + B.4 (handler).
- `replay.Forensics` with `Capture(ctx, bundleID, actionIdx)` defined in C.1; consumed in C.2 (engine wiring).
- `CircuitStore.RecordFailure` signature changes in C.2 (adds `screenshotRef`); all call sites updated in same commit.
- `bundles.ReRecord` defined in D.2; consumed by `ReRecordHandler` (same commit).
- `Bundle.SupersededBy string` added in D.2; threaded through `canonicalBundle` for HMAC determinism.

### Open items (intentional)

- Pen-test scripts have `// TODO: insert real attack payload` placeholders inside the test bodies — by design, the actual attack mechanics are filled in during PR A execution against a real staging deployment.
- Dashboard JSON is hand-crafted; if the team prefers Grafonnet or a generator, we can swap during PR B without changing the contract.
- The `serializeEnvelope` helper in C.1 references either an existing helper or a fresh JSON marshaller — confirm at implementation time and remove the placeholder.

---

## Execution handoff

Plan #6 saved to `docs/superpowers/plans/2026-05-06-dast-internal-ga.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task with two-stage review.
**2. Inline Execution** — execute tasks in this session via executing-plans.
