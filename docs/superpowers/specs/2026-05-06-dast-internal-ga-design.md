# DAST Internal GA — Design

**Status:** Approved (brainstorming complete 2026-05-06).
**Plan track:** #6 of 6 in the DAST authentication roadmap.
**Predecessor:** `2026-05-05-dast-replay-hardening-design.md` (plan #5). Plans #1–#5 are merged or in review.
**Successor:** None within the DAST roadmap. Plan #7+ may pick up integration breadth (SIEM, multi-language SDKs, external Vault adapters).

---

## 1. Goals & non-goals

### 1.1 Goals

1. Achieve **internal General Availability** for the DAST authentication subsystem: the controlplane + replay engine + recorder operate against customer targets unattended with documented failure modes, automated forensics on failure, and a runbook the on-call operator can follow.
2. Validate the threat model from `2026-05-04-dast-auth-captcha-design.md` §2.3 against the deployed system via a black-box pen-test campaign whose pass criteria are explicit and reproducible.
3. Surface live operational metrics so customers running their own SentinelCore deployment can see replay health on their own Prometheus/Grafana stack — without us shipping any new external runtime dependency.
4. Make bundle re-record a 1-command operator workflow when the replay engine flags a bundle as `refresh_required`.

### 1.2 Non-goals

- External pen-test firm engagement (organizational decision; out of scope for code).
- Customer-facing GA artefacts: status page, public SLA, downtime communication runbook, on-call rotation rules. These are deferred to a future "external GA" track.
- Multi-replica / multi-region replay topology (current single replay worker stays).
- SIEM event forwarding, multi-language customer SDKs, external Vault adapters — explicit deferrals to plan #7+.

### 1.3 Out-of-scope follow-ups

- Distributed circuit breaker (Redis-backed). Current per-process state remains.
- Per-step screenshot retention beyond 7 days. The plan ships 7-day TTL; longer retention is a customer-config follow-up.
- Replay anomaly historical analytics (trend charts, regression detection across recordings). Dashboard ships with current-state gauges only.

---

## 2. Component architecture

```
┌──────────────────────────────────────────────────────────────┐
│ Replay Engine (existing)                                     │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐    │
│   │ Engine.Replay                                       │    │
│   │  ├─ existing pre-flight chain                       │    │
│   │  ├─ existing action walker                          │    │
│   │  ├─ NEW: metric.Inc on each branch                  │    │
│   │  └─ NEW: on failure → Forensics.Capture(actionIdx)  │    │
│   └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│   ┌─────────────────────────────────────────────────────┐    │
│   │ Forensics (NEW: internal/authbroker/replay/         │    │
│   │ forensics.go)                                       │    │
│   │  ├─ Capture(ctx, bundleID, actionIdx)               │    │
│   │  │   chromedp.CaptureScreenshot                     │    │
│   │  │   → kms.EncryptEnvelope                          │    │
│   │  │   → MinIO PUT bucket=dast-forensics              │    │
│   │  └─ Persist screenshot_refs into                    │    │
│   │      dast_replay_failures.screenshot_refs JSONB     │    │
│   └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ Controlplane (existing) — extended                           │
│                                                              │
│  /metrics endpoint (NEW)                                     │
│   └─ promhttp.Handler() exposing internal/metrics/dast.go    │
│                                                              │
│  POST /api/v1/dast/bundles/:id/re-record (NEW)               │
│   └─ recording_admin only                                    │
│   └─ copies target_host, principal_claim, ACL from old       │
│      bundle, marks old as superseded, returns new draft id   │
└──────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│ CLI (extended)                                               │
│                                                              │
│  sentinelcore dast bundles list --status refresh_required    │
│  sentinelcore dast bundles re-record <id>                    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Pen-test harness (NEW)                                       │
│                                                              │
│  tests/pentest/                                              │
│   ├─ run.sh — orchestrator, JSON report                      │
│   ├─ stride/                                                 │
│   │   ├─ spoof_bundle_integrity.go                           │
│   │   ├─ jwt_replay.go                                       │
│   │   ├─ rls_bypass.go                                       │
│   │   ├─ sql_injection_credentials_cli.go                    │
│   │   └─ csrf_circuit_reset.go                               │
│   └─ README.md — execution + interpretation                  │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│ Documentation (NEW)                                          │
│                                                              │
│  docs/runbooks/dast-replay.md                                │
│   ├─ Triage matrix (failure type → first commands)           │
│   ├─ Common failure modes + recovery                         │
│   ├─ Rollback playbook (migrations 047/048/049 down)         │
│   └─ Escalation path                                         │
│                                                              │
│  docs/superpowers/specs/2026-05-06-dast-ga-checklist.md      │
│   ├─ Pen-test campaign pass criteria                         │
│   ├─ Observability acceptance (7 days staging telemetry)     │
│   ├─ Runbook drill (response time < 30 min on 1 scenario)    │
│   └─ Rollback drill (migration down + service recovery)      │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. Pen-test harness (PR A)

### 3.1 Scope

The harness validates the same threat model that produced sec-01..sec-09 unit tests, but at black-box deployment level. Each STRIDE category gets at least one attack script that runs against the running stack (controlplane + postgres + KMS + MinIO).

| ID | Threat | STRIDE | Attack |
|----|--------|--------|--------|
| pt-01 | Spoofed bundle integrity | Tampering | Forge an HMAC for a tampered bundle JSON; submit via API; expect 400 |
| pt-02 | JWT replay across customers | Repudiation | Use customer A's JWT to fetch customer B's bundle; expect 403 (RLS) |
| pt-03 | RLS bypass via session var | Information disclosure | Connect to postgres directly with `app.customer_id` set to victim; verify policy denies cross-tenant SELECT |
| pt-04 | SQL injection on credentials CLI | Tampering | Pass `--key "x'; DROP TABLE..."` to `dast credentials add`; expect parsed-as-literal, not executed |
| pt-05 | CSRF on circuit/reset | Spoofing | Issue cross-origin POST to `/api/v1/dast/bundles/:id/circuit/reset`; expect rejection (no auth cookie / wrong origin) |

Each attack is a Go test `func TestPT_NN(t *testing.T)` with build tag `//go:build pentest` (so it doesn't run in CI by default — explicit `go test -tags pentest` to invoke).

### 3.2 Orchestrator

`tests/pentest/run.sh`:

```bash
#!/usr/bin/env bash
# Run all pentest checks against the current SENTINELCORE_HOST environment.
# Output: tests/pentest/report.json with per-test {id, status, evidence}.
set -euo pipefail
: "${SENTINELCORE_HOST:?must export}"
: "${SENTINELCORE_API_TOKEN:?must export}"
go test -tags pentest -json ./tests/pentest/stride/... > tests/pentest/raw.jsonl
jq -s '...' tests/pentest/raw.jsonl > tests/pentest/report.json
```

PASS criterion: every pt-NN test in the report has `status: PASS`. Any FAIL blocks GA.

### 3.3 Reuse

The unit-level sec-01..sec-09 tests stay where they are (`internal/dast/security_regression_*.go`); the pen-test harness is the deployed-system equivalent, not a replacement.

---

## 4. Observability layer (PR B)

### 4.1 Metrics package

`internal/metrics/dast.go`:

```go
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
    ReplayTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "dast_replay_total",
        Help: "DAST replay attempts by result",
    }, []string{"result"}) // success | failure_circuit | failure_anomaly | ...

    CircuitState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
        Name: "dast_replay_circuit_state",
        Help: "Circuit state per bundle (0=closed, 1=open)",
    }, []string{"bundle_id"})

    AnomalyTotal           = prometheus.NewCounter(...)  // dast_replay_anomaly_total
    PostStateMismatchTotal = prometheus.NewCounter(...)  // dast_replay_postate_mismatch_total
    PrincipalMismatchTotal = prometheus.NewCounter(...)  // dast_replay_principal_mismatch_total
    CredentialLoadTotal    = prometheus.NewCounterVec(...) // dast_credential_load_total{result}
)

func Register(r prometheus.Registerer) error { /* register all */ }
```

### 4.2 Wiring

- `Engine.Replay` calls the appropriate counter on each branch (success path, anomaly, postate, principal, circuit-open).
- `internal/dast/credentials.PostgresStore.Load` calls `CredentialLoadTotal.WithLabelValues("success"/"not_found"/"decrypt_error").Inc()`.
- Controlplane `cmd/controlplane/main.go` registers `/metrics` route serving `promhttp.HandlerFor(registry, ...)`. **No auth on the endpoint** — customer-side scrape is internal-only by network design (compose `expose:` not `ports:`).

### 4.3 Dashboard

`deploy/grafana/dast-replay-dashboard.json` — committed JSON. 6 panels:

1. Replay success rate (last 24h, by bundle if possible)
2. Open circuits (gauge, current value)
3. Anomaly events (rate per 5m)
4. Post-state mismatches (rate per 5m)
5. Principal mismatches (count per 1h)
6. Credential load failures (rate per 5m, broken down by reason)

Customer imports via Grafana JSON import. No external service.

### 4.4 Migration 050

```sql
-- 050: prep dast_replay_failures for screenshot_refs (used in PR C).
ALTER TABLE dast_replay_failures
    ADD COLUMN IF NOT EXISTS screenshot_refs JSONB NOT NULL DEFAULT '[]'::jsonb;
```

Ships with PR B even though its consumer is PR C, so PR C doesn't need its own migration.

---

## 5. Screenshot forensics on failure (PR C)

### 5.1 When to capture

- ONLY on replay failure (anomaly, postate mismatch, principal mismatch, action error). Not on success.
- Capture happens IN-CONTEXT: when an error short-circuits the action loop, the engine first calls `forensics.Capture(timeoutCtx, bundleID, actionIdx)` BEFORE returning the error.

### 5.2 Capture path

```go
// internal/authbroker/replay/forensics.go
package replay

func (f *Forensics) Capture(ctx context.Context, bundleID uuid.UUID, actionIdx int) (string, error) {
    var png []byte
    if err := chromedp.Run(ctx, chromedp.CaptureScreenshot(&png)); err != nil {
        return "", err  // best-effort; engine logs and continues
    }
    env, err := kms.EncryptEnvelope(ctx, f.kms, "dast.forensic", png, []byte(bundleID.String()))
    if err != nil { return "", err }
    objectKey := fmt.Sprintf("bundle/%s/%s-%d.png.enc", bundleID, time.Now().UTC().Format("20060102T150405Z"), actionIdx)
    if _, err := f.minio.PutObject(ctx, "dast-forensics", objectKey,
        wrapEnvelope(env), int64(len(png)), minio.PutObjectOptions{ContentType: "application/octet-stream"}); err != nil {
        return "", err
    }
    return objectKey, nil
}
```

### 5.3 Persistence

`replay.CircuitStore.RecordFailure` is extended to also append the new `screenshot_ref` to `dast_replay_failures.screenshot_refs` (a JSONB array). On reset, the array is cleared.

### 5.4 Retention

`cmd/forensics-cleanup-worker/main.go` — cron-style worker that runs hourly:

```sql
SELECT bundle_id, screenshot_refs
FROM dast_replay_failures
WHERE last_failure_at < NOW() - INTERVAL '7 days'
  AND jsonb_array_length(screenshot_refs) > 0;
```

For each row: delete each `screenshot_ref` from MinIO, then `UPDATE ... SET screenshot_refs = '[]'`.

### 5.5 Privacy invariants

- Successful replays MUST NOT produce screenshots. Sec test asserts this.
- Screenshot bucket is envelope-encrypted; even with object access, plaintext requires KMS unwrap.
- Screenshots can leak credentials typed via `ActionFill` (the input would render in the rasterized DOM). This is acceptable for **internal forensics only** — bucket access requires `recording_admin` role + KMS key access.

---

## 6. Re-record UX (PR D)

### 6.1 API

```
POST /api/v1/dast/bundles/:id/re-record       (recording_admin)
```

Request body: `{"reason": "circuit_open" | "postate_drift" | "manual"}`.

Effect:
1. Load source bundle.
2. Mark source bundle status = `superseded` + audit `dast.bundle.superseded`.
3. Create a new bundle row with `status = pending_review`, copying `target_host`, `principal_claim`, `acl`, `ttl_seconds`. Actions are EMPTY — operator runs the recorder against the new bundle's id.
4. Return the new bundle id.

The new bundle ID is fresh; the old one is preserved (audit trail). This is intentional vs the spec text "old ID kept" — keeping the old ID would corrupt audit history.

### 6.2 CLI

```
sentinelcore dast bundles list --status refresh_required
sentinelcore dast bundles list --status superseded
sentinelcore dast bundles re-record <old-id>
  → calls API, prints new bundle id, then auto-launches `dast record --bundle <new-id>`
```

The `re-record` shortcut chains the API call + recorder so the operator runs one command instead of two.

---

## 7. Runbook + GA checklist (PR D, docs only)

### 7.1 Runbook structure (`docs/runbooks/dast-replay.md`)

Sections:
1. **Triage matrix** — symptom → first 3 commands. Examples:
   - "Replay always fails with `circuit open`": query `dast_replay_failures.last_error`, count by bundle; identify the bad bundle; circuit/reset OR re-record.
   - "Replay returns scope violation": check bundle's TargetHost vs the action URLs in `Bundle.Actions`; usually means the customer's app moved domains.
2. **Common failure modes** — postate mismatch, principal mismatch, captcha-mark, anomaly. For each: root cause hypothesis, recovery action.
3. **Rollback playbook** — for each migration (047, 048, 049, 050): the down command, expected duration, data loss implications.
4. **Escalation path** — when to wake whom, what evidence to gather.
5. **Forensic access** — how to retrieve a screenshot from MinIO + KMS unwrap (read-only access pattern, audit logging required).

### 7.2 GA checklist (`docs/superpowers/specs/2026-05-06-dast-ga-checklist.md`)

Pass criteria for declaring DAST internally GA:

- [ ] Pen-test campaign all PASS (pt-01..05) on a fresh staging deployment.
- [ ] sec-01..sec-09 unit tests all PASS.
- [ ] Observability dashboard shows ≥ 7 days of staging telemetry; no continuous open-circuit conditions; replay success rate ≥ 95%.
- [ ] Runbook drill: 1 chosen failure scenario triaged + recovered in < 30 minutes by an operator who has never seen the system before, working only from the runbook.
- [ ] Rollback drill: migration 049 down + 048 down + 050 down applied to a staging copy; service comes back healthy.
- [ ] Forensics retention tested: failure → screenshot persisted → 7-day cleanup verified by manually advancing `last_failure_at` and running the worker.
- [ ] Credential CLI signed off: add/list/remove all functional in staging; no plaintext on disk.
- [ ] Re-record flow signed off: bundle marked refresh_required → operator invokes `dast bundles re-record <id>` → new draft created → recording captured → bundle approved → automatable replay produces fresh session.

GA = checklist 100% passed AND no open `priority:critical` issues against the DAST track.

---

## 8. Storage & migrations

- **Migration 050** (PR B): `dast_replay_failures.screenshot_refs JSONB DEFAULT '[]'`.
- **Migration 051** (PR D): `dast_auth_bundles` adds `superseded_by UUID NULL` and the `superseded` enum value to the status check constraint.

No other schema changes.

---

## 9. Audit events (additions)

| Event | When |
|-------|------|
| `dast.replay.forensic_captured` | Screenshot persisted on failure |
| `dast.replay.forensic_purged` | Cleanup worker removes a screenshot batch |
| `dast.bundle.superseded` | `re-record` flips an old bundle |
| `dast.bundle.re_recorded` | New bundle created via re-record API |
| `dast.pentest.campaign_started` | Pen-test orchestrator invocation (best-effort, audit-from-CLI) |
| `dast.pentest.campaign_completed` | Pen-test orchestrator end |

---

## 10. Rollout

1. Apply migration 050 (PR B). Customer-side: import dashboard JSON.
2. Deploy controlplane with `/metrics` endpoint. Verify scrape from a customer-side Prometheus.
3. Apply migration 051 (PR D). Deploy controlplane with re-record API + CLI.
4. Add `forensics-cleanup-worker` to the compose file with cron-style schedule.
5. Run pen-test campaign on the upgraded staging — capture report.json.
6. Run runbook drill + rollback drill.
7. Sign off GA checklist; declare internal GA.

Backward compatibility: existing bundles continue to work. New columns default to `'[]'::jsonb` and `NULL` so old code paths are unaffected.

---

## 11. Implementation plan handoff

This spec is consumed by plan #6 (`docs/superpowers/plans/2026-05-06-dast-internal-ga.md`), which decomposes the four PRs above into checklist-tracked tasks.
