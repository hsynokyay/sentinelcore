# DAST Replay Hardening + Recorder Enhancements — Design

**Status:** Approved (brainstorming complete 2026-05-05)
**Plan track:** #5 of 6 in the DAST authentication roadmap.
**Predecessor:** `2026-05-04-dast-auth-captcha-design.md` (parent spec). This document refines the deferred subsections of the parent for the plan #5 scope.
**Successor:** Plan #6 — SIEM forward, multi-language customer SDKs, pen-test, GA hardening.

---

## 1. Goals & non-goals

### 1.1 Goals

1. Make automatable replay safe enough to run unattended against a customer target.
2. Allow the recorder to capture click and fill events, so that "fresh-login replay" (Vault-backed credential injection) becomes possible.
3. Detect and contain UI drift, replay anomalies, principal mismatches, and repeated replay failures without manual intervention.
4. Keep credentials out of the recording on disk — they live only in the SentinelCore KMS-backed credential store and are fetched at replay time.

### 1.2 Non-goals

- SIEM event forwarding (plan #6).
- Multi-language customer-side SDKs for bypass token verification (plan #6).
- External Vault provider adapters (HashiCorp Vault, AWS Secrets Manager, etc.) — out of scope for this spec; SentinelCore KMS-backed credential storage is the sole MVP backend. External providers may follow in a later plan.
- Production pen-test, threat-model sign-off, GA bar (plan #6).
- Captcha-bearing flows — those remain one-shot, never automatable.

### 1.3 Out-of-scope follow-ups

- Distributed circuit breaker state across multiple replay workers — single-process state, durable in DB, is sufficient for the current single-tenant deployment.
- Per-step screenshot capture for replay forensics — useful but adds storage cost; deferred.

---

## 2. Scope summary

| Parent-spec section | Status before plan #5 | Plan #5 scope |
|---------------------|------------------------|----------------|
| §5.2 Action capture | navigate + captcha-mark only | + click + fill (selector only, never value) |
| §5.3 Credentials never literal | Designed; not implemented | KMS-backed credential store + replay-time injection |
| §6.3 Action execution / anomaly | Walker exists; no anomaly check | per-action 3× duration; aggregate 3× total |
| §6.4 Post-state assertion | Not implemented | DOM skeleton hash captured + verified |
| §6.5 Principal binding | Not implemented | JWT detect + claim extract; replay-time match |
| §6.6 Replay rate limit & circuit breaker | Rate limit only (1/min) | + circuit breaker on 3 consecutive failures, DB-backed, admin reset |

---

## 3. Component architecture

### 3.1 New / changed components

```
┌────────────────────────────────────────────────────────────────────┐
│ Recorder (chromedp)                                                │
│                                                                    │
│  capture.js (NEW)            recorder.go                           │
│  ├─ click listener           ├─ Runtime.AddScriptToEvaluateOnNew   │
│  ├─ input listener           │  Document(capture.js)               │
│  ├─ selector ranker          ├─ Runtime.AddBinding("__sentinel_   │
│  └─ post-state hasher        │  emit")                             │
│                              ├─ Runtime.bindingCalled handler      │
│                              │   → push Action onto bundle         │
│                              └─ on each action: capture            │
│                                  ExpectedPostStateHash + DurationMs│
└────────────────────────────────────────────────────────────────────┘
                            │ records
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│ Bundle store                                                       │
│  Action{Kind,URL,Selector,VaultKey?,                               │
│         ExpectedPostStateHash,DurationMs,Timestamp}                │
└────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────────────────┐
│ Credentials store (NEW package internal/dast/credentials)          │
│  Store.Save(bundle_id, vault_key, plaintext) → envelope-encrypted  │
│  Store.Load(bundle_id, vault_key) → plaintext (replay only)        │
│  Persisted in dast_credential_secrets, RLS customer-scoped         │
└────────────────────────────────────────────────────────────────────┘
                            ▲
                            │ Load
┌────────────────────────────────────────────────────────────────────┐
│ Replay engine (extended)                                           │
│                                                                    │
│  replayer.go        postate.go       principal.go                  │
│  ├─ host match      ├─ skeleton      ├─ JWT detect                 │
│  ├─ rate limit      │  hash compute  ├─ claim extract              │
│  ├─ run actions     ├─ verify        └─ scan-time match            │
│  │  ├─ ActionFill───┼──→ inject.go (NEW)                           │
│  ├─ anomaly.go      │                                              │
│  │  ├─ per-action   │                                              │
│  │  └─ aggregate    │                                              │
│  └─ circuit.go      │                                              │
│     ├─ failure++    │                                              │
│     ├─ open at 3    │                                              │
│     └─ reset (API)  │                                              │
└────────────────────────────────────────────────────────────────────┘
```

### 3.2 Trust boundaries (delta vs parent spec)

- The credential store sits behind the same envelope-encryption boundary as bundle blobs — no new trust boundary.
- `capture.js` runs in the recording browser; it is a sandboxed surface but considered untrusted for security decisions: every event it emits is re-validated server-side (selector format, action kind, timestamp monotonic, host scope).

---

## 4. Recorder changes (PR A)

### 4.1 Capture content script

`internal/authbroker/recording/capture.js` — small, vendored asset, ≤120 LoC.

```javascript
(() => {
  const STABLE_ATTRS = ['data-testid', 'data-test', 'data-cy'];
  function rankSelector(el) {
    for (const a of STABLE_ATTRS) {
      const v = el.getAttribute(a);
      if (v) return `[${a}="${cssEscape(v)}"]`;
    }
    if (el.id) return `#${cssEscape(el.id)}`;
    if (el.name) return `${el.tagName.toLowerCase()}[name="${cssEscape(el.name)}"]`;
    return cssPath(el);
  }
  function emit(kind, payload) {
    if (typeof __sentinel_emit !== 'function') return;
    __sentinel_emit(JSON.stringify({ kind, t: Date.now(), ...payload }));
  }
  document.addEventListener('click', (e) => {
    emit('click', { selector: rankSelector(e.target) });
  }, true);
  document.addEventListener('input', (e) => {
    emit('fill', { selector: rankSelector(e.target) }); // VALUE NEVER EMITTED
  }, true);
  // Post-state hash — debounced to last URL event per second
  // ... computeSkeletonHash() implementation
})();
```

**Server-side validation invariants for emitted events:**

- `kind ∈ {click, fill}`.
- `selector` matches `^[a-zA-Z0-9_\-#.\[\]="' :>+~()*\s]+$` and ≤256 chars.
- Reject any event whose origin host is outside the bundle's TargetHost.
- Reject `fill` events that include a `value` field (defense-in-depth — script never emits value, but we strip+reject if seen).

### 4.2 Recorder wiring

`recorder.go` adds:

- On context init: `chromedp.Run(ctx, page.AddScriptToEvaluateOnNewDocument(captureJS))`.
- `runtime.AddBinding("__sentinel_emit")`.
- `chromedp.ListenTarget(ctx, func(ev interface{}))` handles `*runtime.EventBindingCalled`; parses payload, validates, appends to `recordedSession.Actions`.

### 4.3 Post-state hash at capture time

After every emitted click/fill/navigate, the recorder computes:

```
expected_post_state_hash = SHA-256(url_path || canonical(skeleton))
skeleton = sorted([
  ...visible_form_selectors,
  ...visible_h1_h2_text,
  ...nav_landmarks_selectors,
])
```

Stored on `Action.ExpectedPostStateHash`. Computed server-side via a small JS evaluator injected on demand — does NOT live in `capture.js` (kept off the always-on hot path).

### 4.4 Per-action duration

`Action.DurationMs = nextActionTimestamp - thisActionTimestamp`. The last action's duration is `bundleStop - lastActionTimestamp`.

---

## 5. KMS-backed credential store (PR A)

### 5.1 Schema (migration 048)

```sql
CREATE TABLE dast_credential_secrets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_id     UUID NOT NULL REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    vault_key     TEXT NOT NULL,
    customer_id   UUID NOT NULL,
    iv            BYTEA NOT NULL,
    ciphertext    BYTEA NOT NULL,
    aead_tag      BYTEA NOT NULL,
    wrapped_dek   BYTEA NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (bundle_id, vault_key)
);
CREATE INDEX idx_dcs_bundle ON dast_credential_secrets (bundle_id);
ALTER TABLE dast_credential_secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY dcs_customer_isolation ON dast_credential_secrets
  USING (customer_id = current_setting('app.customer_id', true)::uuid);
```

### 5.2 Package contract

```go
// internal/dast/credentials/store.go
package credentials

type Store interface {
    Save(ctx context.Context, bundleID uuid.UUID, vaultKey string, plaintext []byte) error
    Load(ctx context.Context, bundleID uuid.UUID, vaultKey string) ([]byte, error)
    Delete(ctx context.Context, bundleID uuid.UUID, vaultKey string) error
    ListKeys(ctx context.Context, bundleID uuid.UUID) ([]string, error)
}
```

Implementation reuses `pkg/kms.EncryptEnvelope` / `DecryptEnvelope` with AAD `bundle_id || vault_key`. Plaintext is zeroed in memory after `Load` returns to caller via a `defer` block.

### 5.3 CLI

```
sentinelcore dast credentials add --bundle <id> --key <name>     # prompts for value, never echoed
sentinelcore dast credentials list --bundle <id>
sentinelcore dast credentials remove --bundle <id> --key <name>
```

Audit events: `dast.credential.added`, `dast.credential.loaded`, `dast.credential.removed`.

---

## 6. Replay engine extensions (PR B)

### 6.1 Anomaly detection

```go
// internal/authbroker/replay/anomaly.go
func checkAnomaly(actionDur time.Duration, recordedMs int) error {
    if actionDur > time.Duration(3*recordedMs)*time.Millisecond {
        return fmt.Errorf("anomaly: action ran %s, recorded baseline %dms", actionDur, recordedMs)
    }
    return nil
}
```

Aggregate budget: `replayDeadline = now + 3 * sum(Action.DurationMs)`. Engine wraps run in `context.WithDeadline`.

### 6.2 Post-state assertion

After each action, the engine evaluates the same skeleton-hash JS as the recorder; compares against `Action.ExpectedPostStateHash`. Mismatch ⇒ abort with `refresh_required` audit; bundle status moves to `refresh_required` so future scans skip it until re-recorded.

### 6.3 Principal binding

```go
// internal/authbroker/replay/principal.go
func ExtractPrincipal(cookies []*http.Cookie, claim string) (string, bool) {
    for _, c := range cookies {
        if !looksLikeJWT(c.Value) { continue }
        payload := decodeJWTPayload(c.Value) // base64 decode middle segment, no sig check
        if v, ok := payload[claim]; ok {
            return fmt.Sprint(v), true
        }
    }
    return "", false
}
```

- `claim` defaults to `"sub"`; configurable per bundle via `bundle.principal_claim`.
- At record approval time, principal is extracted and persisted in `bundle.target_principal`.
- At replay time, scan job's `expected_principal` is matched against `bundle.target_principal`; if either is empty, no binding (audit warning).

### 6.4 Circuit breaker

Schema (migration 049):

```sql
CREATE TABLE dast_replay_failures (
    bundle_id            UUID PRIMARY KEY REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_failure_at      TIMESTAMPTZ,
    last_error           TEXT
);
ALTER TABLE dast_auth_bundles
    ADD COLUMN principal_claim    TEXT NOT NULL DEFAULT 'sub',
    ADD COLUMN target_principal   TEXT;
```

`Action.ExpectedPostStateHash` and `Action.DurationMs` are stored inside the existing encrypted bundle blob (canonical JSON), so no relational column is needed for them.

State machine:

- Replay success ⇒ `consecutive_failures = 0`.
- Replay failure ⇒ `consecutive_failures += 1`, `last_failure_at = NOW()`.
- On `consecutive_failures >= 3` ⇒ engine refuses replay; bundle status set to `refresh_required`.
- Reset endpoint: `POST /api/dast/bundles/:id/circuit/reset` — requires `recording_admin` role (RBAC via existing `RequireDASTRole` middleware). Sets `consecutive_failures = 0`. Audit `dast.replay.circuit_reset`.

### 6.5 Engine wiring

Modified `Engine.Replay`:

```
1. nil/type/expired/no-actions guards          (existing)
2. derive targetHost                           (existing)
3. circuit.IsOpen(bundleID) → if open, abort   (NEW)
4. rateLimit.Allow                              (existing)
5. preflightHostMatch                          (existing)
6. preflightActionCountMatch                   (NEW: bundle.action_count == len(actions))
7. principal.Verify(bundle, scan.expected)     (NEW)
8. context.WithDeadline(now + 3*total_recorded)(NEW)
9. for action:
   a. run action                               (existing)
   b. checkAnomaly(elapsed, action.DurationMs) (NEW)
   c. postate.Verify(action.ExpectedHash)      (NEW)
   d. case ActionFill: credentials.Inject       (NEW, see PR C)
10. on any error: circuit.RecordFailure(bid)
11. on success:    circuit.Reset(bid)
```

---

## 7. Credential injection during replay (PR C)

`internal/authbroker/replay/inject.go`:

```go
func injectFill(ctx context.Context, store credentials.Store,
                bundleID uuid.UUID, action bundles.Action) error {
    if action.VaultKey == "" {
        return fmt.Errorf("replay: fill action %q has no vault_key", action.Selector)
    }
    plain, err := store.Load(ctx, bundleID, action.VaultKey)
    if err != nil { return fmt.Errorf("replay: credential load: %w", err) }
    defer zero(plain)
    return chromedp.Run(ctx, chromedp.SendKeys(action.Selector, string(plain), chromedp.ByQuery))
}
```

`zero(plain)` overwrites the byte slice before return.

E2E acceptance:
- Record a flow with one click + one fill.
- `sentinelcore dast credentials add --bundle X --key login_password` (prompts).
- Approve bundle as automatable.
- Trigger replay; expect: chromedp launches headless, walks navigate→fill→click, fresh session emitted.
- Verify: `dast_credential_secrets` row's plaintext never observable on disk; only the AEAD ciphertext.

---

## 8. Security regression coverage (PR D)

| ID | Threat | Test |
|----|--------|------|
| sec-05 | Forged `ExpectedPostStateHash` (mid-flight bundle tamper) | Construct bundle with mismatched hash → replay aborts with refresh_required |
| sec-06 | Principal mismatch (low-priv recording reused for admin scan) | bundle.target_principal=u1, scan.expected=u2 → engine refuses |
| sec-07 | Circuit breaker engages | 3 forced failures (e.g. invalid bundle inputs) → 4th call refused before browser launch |
| sec-08 | Forged vault_key reference | action.VaultKey points to non-existent key → injectFill returns load error, replay aborts; no browser action issued |
| sec-09 | Fill value never persisted | Recorder unit test asserts `__sentinel_emit` with kind=fill never carries `value`; server-side validator rejects if seen |

These extend `internal/dast/security_regression_replay_test.go`.

---

## 9. Migrations

- **048** `dast_credential_secrets.up.sql` — table + RLS policy.
- **048** `.down.sql` — drop table.
- **049** `dast_replay_failures.up.sql` — table + add `principal_claim` column to `dast_auth_bundles`.
- **049** `.down.sql` — drop table + drop column.

`Action.ExpectedPostStateHash` and `Action.DurationMs` live inside the existing encrypted bundle blob; no migration needed for them.

---

## 10. Audit events

| Event | When |
|-------|------|
| `dast.credential.added` | CLI add succeeds |
| `dast.credential.loaded` | Replay loads credential (info-level) |
| `dast.credential.removed` | CLI remove succeeds |
| `dast.replay.anomaly` | Per-action duration ratio breached |
| `dast.replay.postate_mismatch` | Skeleton hash differs |
| `dast.replay.principal_mismatch` | Bundle/scan principal mismatch |
| `dast.replay.circuit_open` | 3rd consecutive failure |
| `dast.replay.circuit_reset` | Admin reset |

All emitted via existing `pkg/audit.Emitter`.

---

## 11. Rollout

1. Deploy migrations 048, 049.
2. Deploy controlplane + worker images with replay-hardening tag.
3. Existing automatable bundles continue to replay. Backward compatibility:
   - `principal_claim` defaults to `sub` for all existing rows (added by migration 049).
   - `target_principal` is NULL for existing bundles, so principal binding is skipped (audit warning emitted) until the bundle is re-recorded.
   - Existing actions have no `DurationMs` or `ExpectedPostStateHash`. The anomaly check skips actions where `DurationMs == 0`, and the post-state check skips actions where `ExpectedPostStateHash` is empty. Both behaviors emit a one-line info-level audit per replay so customers know hardening is partial until re-record.
4. Customers using fill-based flows must re-record post-deploy; old bundles without click/fill capture continue to work in their existing one-shot mode.

---

## 12. Open items / explicit deferrals

- Multi-process distributed circuit state (out of scope; single replay worker today).
- Per-step screenshots for replay forensics (deferred).
- External Vault adapters (HashiCorp Vault, AWS SM, Azure KV, GCP SM) — explicit scope cut; SentinelCore KMS only for MVP.
- SIEM forwarder for `dast.replay.*` audit events — plan #6.

---

## 13. Implementation plan handoff

This spec is consumed by plan #5 (`docs/superpowers/plans/2026-05-05-dast-replay-hardening.md`), which decomposes the four PRs above into checklist-tracked steps.
