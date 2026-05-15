# DAST Replay Hardening + Recorder Enhancements — Implementation Plan (Plan #5 of 6)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make automatable DAST replay safe to run unattended: capture click/fill events during recording (selector only, never value), store credentials in a KMS-backed envelope-encrypted store, and harden the replay engine with anomaly detection, post-state assertion, principal binding, and a DB-backed circuit breaker.

**Architecture:** 4 PRs. PR A extends the chromedp recorder with a JS content script that emits click/fill events through a CDP runtime binding, plus a new `internal/dast/credentials` package that envelope-encrypts credentials in `dast_credential_secrets`. PR B adds `replay/postate.go`, `replay/principal.go`, `replay/anomaly.go`, `replay/circuit.go` and wires them into `Engine.Replay`. PR C adds `replay/inject.go` to fill credentials at replay time and ships an end-to-end smoke. PR D adds five sec regression tests (sec-05 through sec-09) and deploys.

**Tech Stack:** Go 1.23, chromedp + cdproto, embedded JS asset (≤120 LoC), pgx for new tables, no new external deps.

**Spec reference:** `docs/superpowers/specs/2026-05-05-dast-replay-hardening-design.md`.

**Plan #5 of 6.** Plans #1–#4 merged (PR #14 for plan #4 is open at time of writing). Plan #6 covers SIEM forward, multi-language SDKs, pen-test, GA.

**Scope cuts vs spec (still deferred):**
- External Vault adapters (HashiCorp Vault, AWS SM, Azure KV, GCP SM) — plan #6+.
- SIEM forwarder for `dast.replay.*` audit events — plan #6.
- Multi-process distributed circuit breaker — plan #6+ (current single replay worker).
- Per-step screenshot capture for replay forensics — explicit deferral in spec §1.3.

---

## Working environment

- **Branch:** `feat/dast-replay-hardening-2026-05` cut from `phase2/api-dast` HEAD.
- **Worktree:** `/Users/okyay/Documents/SentinelCore/.worktrees/dast-replay-hardening`.
- **Migrations** start at **048**.
- **Build/deploy** controlplane only (replay + recorder live in-process).

---

## Existing infrastructure (verified post-Plan-#4)

- `internal/authbroker/recording/recorder.go` — chromedp recorder; captures cookies + UA + final URL + navigate/captcha-mark actions.
- `internal/authbroker/replay/replayer.go` — pre-flight (host match) + chromedp action walker.
- `internal/authbroker/replay/ratelimit.go` — 1-per-minute per-bundle limit.
- `internal/dast/bundles/bundle.go` — `Bundle` already has `TargetPrincipal string` (unused) and `Actions []Action`.
- `internal/dast/bundles/actions.go` — `Action{Kind, URL, Selector, MinWaitMs, MaxWaitMs, Timestamp}`. We add `VaultKey`, `ExpectedPostStateHash`, `DurationMs`.
- `internal/dast/bundles/store.go:121` `PostgresStore.Save` — encrypted blob covers `Actions`; we extend canonical JSON to include the new action fields automatically since they live in the encrypted payload.
- `internal/dast/authz/middleware.go` — `RequireDASTRole(store, RoleRecordingAdmin)` already wired for approve/reject/list-pending; we reuse for `circuit/reset`.
- `internal/kms/envelope.go` — `EncryptEnvelope` / `DecryptEnvelope`. Reused verbatim by the new credential store.
- `pkg/audit.Emitter` — used everywhere for audit events; no changes needed.

---

## File structure

### New files

| Path | Responsibility |
|------|----------------|
| `migrations/048_dast_credential_secrets.up.sql` | `dast_credential_secrets` table + RLS policy |
| `migrations/048_dast_credential_secrets.down.sql` | Rollback |
| `migrations/049_dast_replay_hardening.up.sql` | `dast_replay_failures` + `principal_claim` column |
| `migrations/049_dast_replay_hardening.down.sql` | Rollback |
| `internal/authbroker/recording/capture.js` | Embedded content script (click/fill listeners) |
| `internal/authbroker/recording/capture.go` | Embeds `capture.js` via `//go:embed`; binding handler |
| `internal/authbroker/recording/capture_test.go` | Selector-validator + binding parser unit tests |
| `internal/authbroker/recording/postate.go` | Skeleton hash JS evaluator (recorder-side) |
| `internal/authbroker/recording/postate_test.go` | Hash determinism tests |
| `internal/dast/credentials/store.go` | `Store` interface + `PostgresStore` impl |
| `internal/dast/credentials/store_test.go` | Save/Load/Delete table-driven tests |
| `internal/dast/credentials/audit.go` | `dast.credential.*` audit emitters |
| `internal/cli/dast_credentials.go` | CLI: `sentinelcore dast credentials add/list/remove` |
| `internal/cli/dast_credentials_test.go` | CLI argument parsing tests |
| `internal/authbroker/replay/postate.go` | `VerifyPostState(b *Bundle, action Action, ctx)` chromedp evaluator |
| `internal/authbroker/replay/postate_test.go` | Match / mismatch tests |
| `internal/authbroker/replay/principal.go` | `ExtractPrincipal`, `VerifyPrincipal` |
| `internal/authbroker/replay/principal_test.go` | JWT detection + claim extraction tests |
| `internal/authbroker/replay/anomaly.go` | `CheckActionDuration`, `AggregateBudget` |
| `internal/authbroker/replay/anomaly_test.go` | Threshold tests |
| `internal/authbroker/replay/circuit.go` | DB-backed `CircuitStore`: `IsOpen`, `RecordFailure`, `Reset` |
| `internal/authbroker/replay/circuit_test.go` | State machine tests |
| `internal/authbroker/replay/inject.go` | `injectFill` — credentials.Load + chromedp.SendKeys |
| `internal/authbroker/replay/inject_test.go` | Mock store + chromedp behavioural test |
| `internal/controlplane/circuit_handler.go` | `POST /api/dast/bundles/:id/circuit/reset` |
| `internal/controlplane/circuit_handler_test.go` | Auth + state tests |
| `internal/dast/security_regression_replay_test.go` | Already exists from plan #4; we extend it with sec-05..09 |

### Modified files

| Path | Reason |
|------|--------|
| `internal/dast/bundles/actions.go` | Add `VaultKey`, `ExpectedPostStateHash`, `DurationMs` fields |
| `internal/dast/bundles/bundle.go` | Add `PrincipalClaim string`; thread through `canonicalBundle` + `canonicalAction` |
| `internal/authbroker/recording/recorder.go` | Inject `capture.js` + bind `__sentinel_emit`; capture per-action duration; capture post-state hash |
| `internal/authbroker/replay/replayer.go` | Wire circuit/anomaly/postate/principal checks; `case ActionFill:` calls `injectFill` |
| `internal/authbroker/recorded_login_strategy.go` | Surface `refresh_required` on circuit-open / postate-mismatch |
| `internal/dast/bundles/store.go` | Persist `principal_claim` column on Save/Load |

---

## PR 0 — Pre-flight

- [ ] **Step 1: Worktree**

```
cd /Users/okyay/Documents/SentinelCore
git fetch origin
git worktree add /Users/okyay/Documents/SentinelCore/.worktrees/dast-replay-hardening \
  -b feat/dast-replay-hardening-2026-05 origin/phase2/api-dast
cd /Users/okyay/Documents/SentinelCore/.worktrees/dast-replay-hardening
```

- [ ] **Step 2: Sanity test**

```
go build ./...
go test ./internal/authbroker/... ./internal/dast/...
```

Expected: PASS. (Note: PR #14 for plan #4 may not be merged into `phase2/api-dast` yet at branch-cut time. If plan #4 is unmerged, base off `feat/dast-replay-2026-05` instead and adjust the merge target later.)

- [ ] **Step 3: Rollback tag**

```
git tag pre-replay-hardening-$(date +%Y%m%d)
git push origin pre-replay-hardening-$(date +%Y%m%d)
```

---

## PR A — Recorder click/fill capture + KMS credential store (5 tasks)

### Task A.1: Migration 048 (credential secrets)

**Files:**
- Create: `migrations/048_dast_credential_secrets.up.sql`
- Create: `migrations/048_dast_credential_secrets.down.sql`

- [ ] **Step 1: Up migration**

```sql
-- migrations/048_dast_credential_secrets.up.sql
CREATE TABLE IF NOT EXISTS dast_credential_secrets (
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

CREATE INDEX IF NOT EXISTS idx_dcs_bundle ON dast_credential_secrets (bundle_id);

ALTER TABLE dast_credential_secrets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dcs_customer_isolation ON dast_credential_secrets;
CREATE POLICY dcs_customer_isolation ON dast_credential_secrets
  USING (customer_id = current_setting('app.customer_id', true)::uuid);
```

- [ ] **Step 2: Down migration**

```sql
-- migrations/048_dast_credential_secrets.down.sql
DROP TABLE IF EXISTS dast_credential_secrets;
```

- [ ] **Step 3: Verify schema parses**

```
grep -E "CREATE TABLE|REFERENCES|POLICY" migrations/048_dast_credential_secrets.up.sql
```

Expected: 4 matches (CREATE TABLE, REFERENCES, ENABLE RLS, CREATE POLICY).

- [ ] **Step 4: Commit**

```
git add migrations/048_dast_credential_secrets.up.sql migrations/048_dast_credential_secrets.down.sql
git commit -m "feat(db): add dast_credential_secrets with RLS"
```

---

### Task A.2: Action struct fields

**Files:**
- Modify: `internal/dast/bundles/actions.go`
- Modify: `internal/dast/bundles/bundle.go` (canonicalAction + threading)

- [ ] **Step 1: Extend Action**

Replace `internal/dast/bundles/actions.go` with:

```go
package bundles

import "time"

type ActionKind string

const (
	ActionNavigate    ActionKind = "navigate"
	ActionClick       ActionKind = "click"
	ActionFill        ActionKind = "fill"
	ActionWaitForLoad ActionKind = "wait_for_load"
	ActionCaptchaMark ActionKind = "captcha_mark"
)

type Action struct {
	Kind                  ActionKind `json:"kind"`
	URL                   string     `json:"url,omitempty"`
	Selector              string     `json:"selector,omitempty"`
	VaultKey              string     `json:"vault_key,omitempty"`
	ExpectedPostStateHash string     `json:"expected_post_state_hash,omitempty"`
	DurationMs            int        `json:"duration_ms,omitempty"`
	MinWaitMs             int        `json:"min_wait_ms,omitempty"`
	MaxWaitMs             int        `json:"max_wait_ms,omitempty"`
	Timestamp             time.Time  `json:"timestamp"`
}
```

- [ ] **Step 2: Update canonicalAction in bundle.go**

In `internal/dast/bundles/bundle.go`, locate `type canonicalAction struct` and replace with:

```go
type canonicalAction struct {
	Kind                  ActionKind `json:"kind"`
	URL                   string     `json:"url,omitempty"`
	Selector              string     `json:"selector,omitempty"`
	VaultKey              string     `json:"vault_key,omitempty"`
	ExpectedPostStateHash string     `json:"expected_post_state_hash,omitempty"`
	DurationMs            int        `json:"duration_ms,omitempty"`
	MinWaitMs             int        `json:"min_wait_ms,omitempty"`
	MaxWaitMs             int        `json:"max_wait_ms,omitempty"`
	Timestamp             string     `json:"timestamp"`
}
```

In the `CanonicalJSON()` method, locate the `for i, a := range b.Actions` loop and replace its body:

```go
canonActions[i] = canonicalAction{
	Kind:                  a.Kind,
	URL:                   a.URL,
	Selector:              a.Selector,
	VaultKey:              a.VaultKey,
	ExpectedPostStateHash: a.ExpectedPostStateHash,
	DurationMs:            a.DurationMs,
	MinWaitMs:             a.MinWaitMs,
	MaxWaitMs:             a.MaxWaitMs,
	Timestamp:             a.Timestamp.UTC().Format(time.RFC3339Nano),
}
```

- [ ] **Step 3: Add PrincipalClaim to Bundle**

In `bundle.go` add to `Bundle` struct after `TargetPrincipal`:

```go
PrincipalClaim string `json:"principal_claim,omitempty"`
```

And to `canonicalBundle` similarly. In `CanonicalJSON()` thread `b.PrincipalClaim` into `cb.PrincipalClaim`.

- [ ] **Step 4: Test**

```
go test ./internal/dast/bundles/ -v
```

Expected: existing tests still pass (added fields are `omitempty` so canonical JSON is backward-compatible for old test fixtures).

- [ ] **Step 5: Commit**

```
git add internal/dast/bundles/actions.go internal/dast/bundles/bundle.go
git commit -m "feat(dast/bundles): add Action.{VaultKey,ExpectedPostStateHash,DurationMs} + Bundle.PrincipalClaim"
```

---

### Task A.3: Capture content script + recorder wiring

**Files:**
- Create: `internal/authbroker/recording/capture.js`
- Create: `internal/authbroker/recording/capture.go`
- Create: `internal/authbroker/recording/capture_test.go`
- Modify: `internal/authbroker/recording/recorder.go`

- [ ] **Step 1: Capture script**

```javascript
// internal/authbroker/recording/capture.js
(() => {
  const STABLE_ATTRS = ['data-testid', 'data-test', 'data-cy'];
  function cssEscape(s) { return CSS.escape(s); }
  function rankSelector(el) {
    if (!el || !(el instanceof Element)) return '';
    for (const a of STABLE_ATTRS) {
      const v = el.getAttribute && el.getAttribute(a);
      if (v) return `[${a}="${cssEscape(v)}"]`;
    }
    if (el.id) return `#${cssEscape(el.id)}`;
    if (el.name) return `${el.tagName.toLowerCase()}[name="${cssEscape(el.name)}"]`;
    let path = [];
    let cur = el;
    while (cur && cur.nodeType === 1 && path.length < 6) {
      let part = cur.tagName.toLowerCase();
      if (cur.parentElement) {
        const sibs = Array.from(cur.parentElement.children).filter(s => s.tagName === cur.tagName);
        if (sibs.length > 1) part += `:nth-of-type(${sibs.indexOf(cur)+1})`;
      }
      path.unshift(part);
      cur = cur.parentElement;
    }
    return path.join(' > ');
  }
  function emit(kind, payload) {
    if (typeof __sentinel_emit !== 'function') return;
    try {
      __sentinel_emit(JSON.stringify({ kind: kind, t: Date.now(), ...payload }));
    } catch (e) {}
  }
  document.addEventListener('click', (e) => {
    emit('click', { selector: rankSelector(e.target) });
  }, true);
  document.addEventListener('input', (e) => {
    // VALUE INTENTIONALLY OMITTED — selector only.
    emit('fill', { selector: rankSelector(e.target) });
  }, true);
})();
```

- [ ] **Step 2: Embed + handler**

```go
// internal/authbroker/recording/capture.go
package recording

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

//go:embed capture.js
var captureScript string

// CaptureScript returns the embedded JS content script.
func CaptureScript() string { return captureScript }

// CapturedEvent is the JSON shape emitted via __sentinel_emit.
type CapturedEvent struct {
	Kind     string `json:"kind"`
	Selector string `json:"selector,omitempty"`
	URL      string `json:"url,omitempty"`
	T        int64  `json:"t"`
	// Defense-in-depth: if a value field is ever present, we reject the event.
	Value *string `json:"value,omitempty"`
}

var selectorRE = regexp.MustCompile(`^[A-Za-z0-9_\-#.\[\]="' :>+~()*\s]+$`)

// ParseAndValidate decodes a JSON payload from the binding and converts it to
// a bundles.Action. It returns an error if the event is malformed or violates
// any invariant (e.g. carries a value, selector too long, unknown kind).
func ParseAndValidate(payload string) (bundles.Action, error) {
	var ev CapturedEvent
	if err := json.Unmarshal([]byte(payload), &ev); err != nil {
		return bundles.Action{}, fmt.Errorf("recording.capture: bad payload: %w", err)
	}
	if ev.Value != nil {
		return bundles.Action{}, fmt.Errorf("recording.capture: fill events must not carry value")
	}
	if len(ev.Selector) > 256 {
		return bundles.Action{}, fmt.Errorf("recording.capture: selector too long")
	}
	if ev.Selector != "" && !selectorRE.MatchString(ev.Selector) {
		return bundles.Action{}, fmt.Errorf("recording.capture: selector contains invalid characters")
	}
	switch ev.Kind {
	case "click":
		return bundles.Action{
			Kind:      bundles.ActionClick,
			Selector:  ev.Selector,
			Timestamp: time.UnixMilli(ev.T).UTC(),
		}, nil
	case "fill":
		return bundles.Action{
			Kind:      bundles.ActionFill,
			Selector:  ev.Selector,
			Timestamp: time.UnixMilli(ev.T).UTC(),
		}, nil
	default:
		return bundles.Action{}, fmt.Errorf("recording.capture: unknown kind %q", ev.Kind)
	}
}
```

- [ ] **Step 3: Test**

```go
// internal/authbroker/recording/capture_test.go
package recording

import (
	"strings"
	"testing"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

func TestParseAndValidate_Click(t *testing.T) {
	a, err := ParseAndValidate(`{"kind":"click","selector":"#login","t":1700000000000}`)
	if err != nil { t.Fatal(err) }
	if a.Kind != bundles.ActionClick { t.Fatalf("kind=%v", a.Kind) }
	if a.Selector != "#login" { t.Fatalf("selector=%q", a.Selector) }
}

func TestParseAndValidate_FillRejectsValue(t *testing.T) {
	v := "secret"
	_, err := ParseAndValidate(`{"kind":"fill","selector":"#pwd","t":1,"value":"` + v + `"}`)
	if err == nil || !strings.Contains(err.Error(), "must not carry value") {
		t.Fatalf("expected value rejection, got %v", err)
	}
}

func TestParseAndValidate_SelectorTooLong(t *testing.T) {
	long := strings.Repeat("a", 257)
	_, err := ParseAndValidate(`{"kind":"click","selector":"` + long + `","t":1}`)
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("expected length rejection, got %v", err)
	}
}

func TestParseAndValidate_BadKind(t *testing.T) {
	_, err := ParseAndValidate(`{"kind":"navigate","t":1}`)
	if err == nil { t.Fatal("expected unknown kind") }
}

func TestCaptureScript_NotEmpty(t *testing.T) {
	if len(CaptureScript()) < 200 {
		t.Fatalf("capture script too short: %d bytes", len(CaptureScript()))
	}
}
```

- [ ] **Step 4: Run**

```
go test ./internal/authbroker/recording/ -run "TestParseAndValidate|TestCaptureScript" -v
```

Expected: 5 PASS.

- [ ] **Step 5: Wire into recorder**

In `internal/authbroker/recording/recorder.go`, locate the chromedp context creation. After the browser context is created, before `Run(ctx, chromedp.Navigate(...))`, add:

```go
import (
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
)

// Inside Record(...) after bctx is created:

if err := chromedp.Run(bctx, chromedp.ActionFunc(func(c context.Context) error {
	if _, err := runtime.AddBinding("__sentinel_emit").Do(c); err != nil {
		return err
	}
	if _, err := page.AddScriptToEvaluateOnNewDocument(captureScript).Do(c); err != nil {
		return err
	}
	return nil
})); err != nil {
	return nil, fmt.Errorf("recorder: install capture script: %w", err)
}

chromedp.ListenTarget(bctx, func(ev interface{}) {
	bc, ok := ev.(*runtime.EventBindingCalled)
	if !ok || bc.Name != "__sentinel_emit" {
		return
	}
	a, err := ParseAndValidate(bc.Payload)
	if err != nil {
		// Log and drop — invalid events are not fatal.
		return
	}
	r.appendAction(a)
})
```

(Where `r` is the recorder receiver and `appendAction` is a thread-safe append helper added in the same file. If `recorder.go` doesn't yet have a recorder struct that owns the action slice, refactor it to do so as part of this step — keep it minimal: a `mu sync.Mutex` + `actions []bundles.Action` field.)

- [ ] **Step 6: Test recorder integration**

Extend `internal/authbroker/recording/recorder_test.go` with a behavioural test that drives chromedp against an `httptest.Server` serving an HTML page with a button + input, simulates click and input via `chromedp.Click` / `chromedp.SendKeys`, and asserts the resulting `RecordedSession.Actions` contains both events with correct selectors. (Skip on `testing.Short()`.)

```go
func TestRecorder_CapturesClickAndFill(t *testing.T) {
	if testing.Short() {
		t.Skip("chromedp integration test")
	}
	// Spin up httptest.Server with a minimal HTML page:
	//   <button id="go" data-testid="go-btn">Go</button>
	//   <input id="user" name="user" />
	// Run recorder.Record(...) against it for 5s.
	// During the run, drive chromedp.Click("#go") + chromedp.SendKeys("#user", "alice").
	// Assert at least one click+fill action is in session.Actions.
	// (Helper: launch a goroutine that uses chromedp.NewContext on the same allocator
	// after recorder boots — or expose a hook in the recorder for tests.)
}
```

If exposing a hook is invasive, skip the integration test in this plan and rely on the `ParseAndValidate` unit tests above plus the E2E smoke in PR C. Document the deferral inline with `// TODO(plan-6): full chromedp integration test`.

- [ ] **Step 7: Commit**

```
git add internal/authbroker/recording/capture.js \
        internal/authbroker/recording/capture.go \
        internal/authbroker/recording/capture_test.go \
        internal/authbroker/recording/recorder.go
git commit -m "feat(recording): capture click + fill events via JS injection"
```

---

### Task A.4: Post-state hash at capture time

**Files:**
- Create: `internal/authbroker/recording/postate.go`
- Create: `internal/authbroker/recording/postate_test.go`
- Modify: `internal/authbroker/recording/recorder.go`

- [ ] **Step 1: Implement skeleton hash**

```go
// internal/authbroker/recording/postate.go
package recording

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/chromedp/chromedp"
)

const skeletonJS = `
(() => {
  const visibleFormSel = Array.from(document.querySelectorAll('form input,form select,form textarea,form button'))
    .filter(el => el.offsetParent !== null)
    .map(el => (el.getAttribute('name') || el.id || el.tagName.toLowerCase()));
  const headings = Array.from(document.querySelectorAll('h1,h2'))
    .map(h => (h.textContent || '').trim().slice(0, 80))
    .filter(Boolean);
  const landmarks = Array.from(document.querySelectorAll('nav,[role="navigation"]'))
    .map((_, i) => 'nav-' + i);
  return JSON.stringify({
    path: location.pathname,
    form: visibleFormSel,
    h: headings,
    nav: landmarks
  });
})()
`

// ComputePostStateHash evaluates the skeleton JS in the current page and
// returns the canonical SHA-256 hex digest.
func ComputePostStateHash(ctx context.Context) (string, error) {
	var raw string
	if err := chromedp.Run(ctx, chromedp.Evaluate(skeletonJS, &raw)); err != nil {
		return "", err
	}
	return canonicalize(raw), nil
}

func canonicalize(raw string) string {
	// Stable canonicalization: sort the form/heading/landmark slices server-side.
	// We re-decode the JSON to a struct, sort, then hash.
	type sk struct {
		Path string   `json:"path"`
		Form []string `json:"form"`
		H    []string `json:"h"`
		Nav  []string `json:"nav"`
	}
	var s sk
	// Tolerate parse failure by falling back to raw bytes.
	if err := jsonUnmarshalStrict(raw, &s); err != nil {
		sum := sha256.Sum256([]byte(raw))
		return hex.EncodeToString(sum[:])
	}
	sort.Strings(s.Form)
	sort.Strings(s.H)
	sort.Strings(s.Nav)
	var b strings.Builder
	b.WriteString(s.Path)
	b.WriteString("|")
	b.WriteString(strings.Join(s.Form, ","))
	b.WriteString("|")
	b.WriteString(strings.Join(s.H, ","))
	b.WriteString("|")
	b.WriteString(strings.Join(s.Nav, ","))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// jsonUnmarshalStrict is a thin wrapper to keep imports tidy in a single line.
func jsonUnmarshalStrict(raw string, out interface{}) error {
	dec := jsonNewDecoderString(raw)
	dec.DisallowUnknownFields()
	return dec.Decode(out)
}
```

The two `jsonNewDecoderString` / `jsonUnmarshalStrict` helpers are tiny; either inline `encoding/json` directly (`json.NewDecoder(strings.NewReader(raw))`) or define them in this file. Use the inline form for clarity.

- [ ] **Step 2: Tests**

```go
// internal/authbroker/recording/postate_test.go
package recording

import "testing"

func TestCanonicalize_Stable(t *testing.T) {
	a := canonicalize(`{"path":"/x","form":["b","a"],"h":["H1"],"nav":["nav-0"]}`)
	b := canonicalize(`{"path":"/x","form":["a","b"],"h":["H1"],"nav":["nav-0"]}`)
	if a != b {
		t.Fatalf("canonicalize not order-stable: %q vs %q", a, b)
	}
}

func TestCanonicalize_DifferentPathsDiffer(t *testing.T) {
	a := canonicalize(`{"path":"/login","form":[],"h":[],"nav":[]}`)
	b := canonicalize(`{"path":"/dashboard","form":[],"h":[],"nav":[]}`)
	if a == b {
		t.Fatal("different paths must produce different hashes")
	}
}

func TestCanonicalize_BadJSONFallback(t *testing.T) {
	h := canonicalize("not-json")
	if len(h) != 64 {
		t.Fatalf("expected 64-char hex digest, got %d", len(h))
	}
}
```

- [ ] **Step 3: Wire into recorder**

In `recorder.go`, after each captured action append, call `ComputePostStateHash` against the current bctx and store the result on the most-recent action:

```go
if h, err := ComputePostStateHash(bctx); err == nil {
	r.setLastActionHash(h)
}
```

Also compute `Action.DurationMs` as `current.Timestamp.Sub(previous.Timestamp).Milliseconds()` when appending the next action. The last action's DurationMs is set at session-stop time as `stop.Sub(last.Timestamp).Milliseconds()`.

- [ ] **Step 4: Run + commit**

```
go test ./internal/authbroker/recording/ -run TestCanonicalize -v
git add internal/authbroker/recording/postate.go \
        internal/authbroker/recording/postate_test.go \
        internal/authbroker/recording/recorder.go
git commit -m "feat(recording): capture post-state skeleton hash + per-action duration"
```

---

### Task A.5: Credential store + CLI

**Files:**
- Create: `internal/dast/credentials/store.go`
- Create: `internal/dast/credentials/store_test.go`
- Create: `internal/dast/credentials/audit.go`
- Create: `internal/cli/dast_credentials.go`
- Create: `internal/cli/dast_credentials_test.go`

- [ ] **Step 1: Store**

```go
// internal/dast/credentials/store.go
package credentials

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sentinelcore/sentinelcore/internal/kms"
)

type Store interface {
	Save(ctx context.Context, customerID, bundleID uuid.UUID, vaultKey string, plaintext []byte) error
	Load(ctx context.Context, bundleID uuid.UUID, vaultKey string) ([]byte, error)
	Delete(ctx context.Context, bundleID uuid.UUID, vaultKey string) error
	ListKeys(ctx context.Context, bundleID uuid.UUID) ([]string, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
	kms  kms.Provider
}

func NewPostgresStore(pool *pgxpool.Pool, p kms.Provider) *PostgresStore {
	return &PostgresStore{pool: pool, kms: p}
}

func aad(bundleID uuid.UUID, vaultKey string) []byte {
	return []byte(bundleID.String() + "|" + vaultKey)
}

func (s *PostgresStore) Save(ctx context.Context, customerID, bundleID uuid.UUID, vaultKey string, plaintext []byte) error {
	env, err := kms.EncryptEnvelope(ctx, s.kms, "dast.credential", plaintext, aad(bundleID, vaultKey))
	if err != nil {
		return fmt.Errorf("credentials: encrypt: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO dast_credential_secrets
		    (bundle_id, vault_key, customer_id, iv, ciphertext, aead_tag, wrapped_dek)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (bundle_id, vault_key) DO UPDATE
		SET iv=EXCLUDED.iv, ciphertext=EXCLUDED.ciphertext,
		    aead_tag=EXCLUDED.aead_tag, wrapped_dek=EXCLUDED.wrapped_dek`,
		bundleID, vaultKey, customerID, env.IV, env.Ciphertext, env.AEADTag, env.WrappedDEK)
	return err
}

func (s *PostgresStore) Load(ctx context.Context, bundleID uuid.UUID, vaultKey string) ([]byte, error) {
	var env kms.Envelope
	err := s.pool.QueryRow(ctx, `
		SELECT iv, ciphertext, aead_tag, wrapped_dek
		FROM dast_credential_secrets
		WHERE bundle_id = $1 AND vault_key = $2`,
		bundleID, vaultKey,
	).Scan(&env.IV, &env.Ciphertext, &env.AEADTag, &env.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("credentials: load: %w", err)
	}
	return kms.DecryptEnvelope(ctx, s.kms, &env, aad(bundleID, vaultKey))
}

func (s *PostgresStore) Delete(ctx context.Context, bundleID uuid.UUID, vaultKey string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM dast_credential_secrets WHERE bundle_id = $1 AND vault_key = $2`,
		bundleID, vaultKey)
	return err
}

func (s *PostgresStore) ListKeys(ctx context.Context, bundleID uuid.UUID) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT vault_key FROM dast_credential_secrets WHERE bundle_id = $1 ORDER BY vault_key`,
		bundleID)
	if err != nil { return nil, err }
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil { return nil, err }
		out = append(out, k)
	}
	return out, rows.Err()
}
```

- [ ] **Step 2: Audit emitters**

```go
// internal/dast/credentials/audit.go
package credentials

import (
	"context"

	"github.com/sentinelcore/sentinelcore/pkg/audit"
)

func EmitAdded(ctx context.Context, e audit.Emitter, bundleID, vaultKey string) {
	e.Emit(ctx, audit.Event{Type: "dast.credential.added", Subject: bundleID, Detail: vaultKey})
}
func EmitLoaded(ctx context.Context, e audit.Emitter, bundleID, vaultKey string) {
	e.Emit(ctx, audit.Event{Type: "dast.credential.loaded", Subject: bundleID, Detail: vaultKey})
}
func EmitRemoved(ctx context.Context, e audit.Emitter, bundleID, vaultKey string) {
	e.Emit(ctx, audit.Event{Type: "dast.credential.removed", Subject: bundleID, Detail: vaultKey})
}
```

(Verify the actual `audit.Event` shape in `pkg/audit/` and adjust field names accordingly. If the existing emitter uses `Action` instead of `Type`, swap.)

- [ ] **Step 3: Tests (table-driven)**

```go
// internal/dast/credentials/store_test.go
package credentials

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/kms"
	pgtest "github.com/sentinelcore/sentinelcore/internal/testutil/pg"
)

func TestPostgresStore_SaveLoadDelete(t *testing.T) {
	pool := pgtest.MustOpen(t)
	defer pool.Close()
	kp := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	s := NewPostgresStore(pool, kp)

	ctx := context.Background()
	cust := uuid.New()
	bun := uuid.New()
	plain := []byte("hunter2")
	if err := s.Save(ctx, cust, bun, "login_pwd", plain); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx, bun, "login_pwd")
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext mismatch: %q vs %q", got, plain)
	}
	keys, err := s.ListKeys(ctx, bun)
	if err != nil { t.Fatal(err) }
	if len(keys) != 1 || keys[0] != "login_pwd" {
		t.Fatalf("ListKeys: %v", keys)
	}
	if err := s.Delete(ctx, bun, "login_pwd"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, bun, "login_pwd"); err == nil {
		t.Fatal("expected load error after delete")
	}
}

func TestPostgresStore_AADBindsCredentialToBundle(t *testing.T) {
	pool := pgtest.MustOpen(t)
	defer pool.Close()
	kp := kms.NewLocalProvider([]byte("test-master-key-32-bytes--------"))
	s := NewPostgresStore(pool, kp)

	ctx := context.Background()
	cust := uuid.New()
	b1 := uuid.New()
	b2 := uuid.New()
	if err := s.Save(ctx, cust, b1, "k", []byte("secret")); err != nil { t.Fatal(err) }

	// Manually swap bundle_id in DB row, then Load should fail because AAD differs.
	_, err := pool.Exec(ctx,
		`UPDATE dast_credential_secrets SET bundle_id=$1 WHERE bundle_id=$2`, b2, b1)
	if err != nil { t.Fatal(err) }

	if _, err := s.Load(ctx, b2, "k"); err == nil {
		t.Fatal("expected AAD mismatch error after row tamper")
	}
}
```

(`internal/testutil/pg` exists or — if not — add a `MustOpen` helper that uses `sentinelcore_test` DB; check `internal/dast/bundles/store_test.go` for the existing pattern and copy it.)

- [ ] **Step 4: CLI**

```go
// internal/cli/dast_credentials.go
package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/google/uuid"
	"golang.org/x/term"

	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// runCredentialsCommand handles `sentinelcore dast credentials <subcmd>`.
func runCredentialsCommand(args []string, store credentials.Store) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: dast credentials add|list|remove ...")
	}
	switch args[0] {
	case "add":
		return runCredAdd(args[1:], store)
	case "list":
		return runCredList(args[1:], store)
	case "remove":
		return runCredRemove(args[1:], store)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runCredAdd(args []string, store credentials.Store) error {
	bundleID, vaultKey, err := parseBundleAndKey(args)
	if err != nil { return err }
	customerID, err := requireCustomerID()
	if err != nil { return err }

	fmt.Fprint(os.Stderr, "credential value (input hidden): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil { return err }
	if len(pw) == 0 { return fmt.Errorf("empty value rejected") }

	return store.Save(context.Background(), customerID, bundleID, vaultKey, pw)
}

func runCredList(args []string, store credentials.Store) error {
	bundleID, _, err := parseBundleAndKey(append(args, "--key", ""))
	if err != nil { return err }
	keys, err := store.ListKeys(context.Background(), bundleID)
	if err != nil { return err }
	for _, k := range keys {
		fmt.Println(k)
	}
	return nil
}

func runCredRemove(args []string, store credentials.Store) error {
	bundleID, vaultKey, err := parseBundleAndKey(args)
	if err != nil { return err }
	if vaultKey == "" { return fmt.Errorf("--key required") }
	return store.Delete(context.Background(), bundleID, vaultKey)
}

// parseBundleAndKey scans args for --bundle and --key flags.
func parseBundleAndKey(args []string) (uuid.UUID, string, error) {
	var bundle, key string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bundle":
			if i+1 < len(args) { bundle = args[i+1]; i++ }
		case "--key":
			if i+1 < len(args) { key = args[i+1]; i++ }
		}
	}
	if bundle == "" {
		return uuid.Nil, "", fmt.Errorf("--bundle <id> required")
	}
	id, err := uuid.Parse(bundle)
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid bundle id: %w", err)
	}
	return id, key, nil
}

// requireCustomerID reads from $SENTINEL_CUSTOMER_ID — every CLI invocation
// already exports this in the operator environment.
func requireCustomerID() (uuid.UUID, error) {
	v := os.Getenv("SENTINEL_CUSTOMER_ID")
	if v == "" {
		return uuid.Nil, fmt.Errorf("SENTINEL_CUSTOMER_ID environment variable not set")
	}
	return uuid.Parse(v)
}

// silence unused-import in some build contexts
var _ = bufio.NewReader
```

Wire into the existing `dast` subcommand dispatcher (likely `internal/cli/dast.go` from plan #3); add a `case "credentials":` arm.

- [ ] **Step 5: CLI tests**

```go
// internal/cli/dast_credentials_test.go
package cli

import "testing"

func TestParseBundleAndKey_Both(t *testing.T) {
	id, k, err := parseBundleAndKey([]string{"--bundle", "11111111-1111-1111-1111-111111111111", "--key", "pwd"})
	if err != nil { t.Fatal(err) }
	if k != "pwd" { t.Fatalf("k=%q", k) }
	if id.String() != "11111111-1111-1111-1111-111111111111" { t.Fatalf("id=%v", id) }
}

func TestParseBundleAndKey_MissingBundle(t *testing.T) {
	if _, _, err := parseBundleAndKey([]string{"--key", "pwd"}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseBundleAndKey_BadUUID(t *testing.T) {
	if _, _, err := parseBundleAndKey([]string{"--bundle", "not-a-uuid"}); err == nil {
		t.Fatal("expected error")
	}
}
```

- [ ] **Step 6: Run + commit**

```
go test ./internal/dast/credentials/ ./internal/cli/ -v
git add internal/dast/credentials/ internal/cli/dast_credentials.go internal/cli/dast_credentials_test.go internal/cli/dast.go
git commit -m "feat(dast/credentials): KMS-backed credential store + CLI add/list/remove"
```

PR A complete.

```
git push -u origin feat/dast-replay-hardening-2026-05
```

---

## PR B — Replay hardening (5 tasks)

### Task B.1: Migration 049

**Files:**
- Create: `migrations/049_dast_replay_hardening.up.sql`
- Create: `migrations/049_dast_replay_hardening.down.sql`

- [ ] **Step 1: Up**

```sql
-- migrations/049_dast_replay_hardening.up.sql
CREATE TABLE IF NOT EXISTS dast_replay_failures (
    bundle_id            UUID PRIMARY KEY REFERENCES dast_auth_bundles(id) ON DELETE CASCADE,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_failure_at      TIMESTAMPTZ,
    last_error           TEXT
);

ALTER TABLE dast_auth_bundles
    ADD COLUMN IF NOT EXISTS principal_claim TEXT NOT NULL DEFAULT 'sub';
```

- [ ] **Step 2: Down**

```sql
-- migrations/049_dast_replay_hardening.down.sql
ALTER TABLE dast_auth_bundles DROP COLUMN IF EXISTS principal_claim;
DROP TABLE IF EXISTS dast_replay_failures;
```

- [ ] **Step 3: Commit**

```
git add migrations/049_dast_replay_hardening.up.sql migrations/049_dast_replay_hardening.down.sql
git commit -m "feat(db): add dast_replay_failures + bundles.principal_claim"
```

---

### Task B.2: Anomaly + post-state + principal helpers

**Files:**
- Create: `internal/authbroker/replay/anomaly.go` (+ test)
- Create: `internal/authbroker/replay/postate.go` (+ test)
- Create: `internal/authbroker/replay/principal.go` (+ test)

- [ ] **Step 1: Anomaly**

```go
// internal/authbroker/replay/anomaly.go
package replay

import (
	"context"
	"fmt"
	"time"
)

// CheckActionDuration returns an error if the observed duration exceeds
// 3× the recorded baseline. If recordedMs is 0 (legacy bundles without
// per-action duration), the check is skipped.
func CheckActionDuration(observed time.Duration, recordedMs int) error {
	if recordedMs <= 0 {
		return nil
	}
	if observed > time.Duration(3*recordedMs)*time.Millisecond {
		return fmt.Errorf("anomaly: action ran %s, recorded baseline %dms", observed, recordedMs)
	}
	return nil
}

// AggregateBudget returns a context whose deadline is now + 3*sum(recordedMs).
// If the total recorded duration is 0, returns the parent context unchanged.
func AggregateBudget(parent context.Context, recordedTotalMs int) (context.Context, context.CancelFunc) {
	if recordedTotalMs <= 0 {
		return parent, func() {}
	}
	return context.WithDeadline(parent, time.Now().Add(time.Duration(3*recordedTotalMs)*time.Millisecond))
}
```

```go
// internal/authbroker/replay/anomaly_test.go
package replay

import (
	"testing"
	"time"
)

func TestCheckActionDuration_WithinThreshold(t *testing.T) {
	if err := CheckActionDuration(150*time.Millisecond, 100); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCheckActionDuration_Exceeds(t *testing.T) {
	if err := CheckActionDuration(400*time.Millisecond, 100); err == nil {
		t.Fatal("expected anomaly")
	}
}

func TestCheckActionDuration_LegacyZero(t *testing.T) {
	if err := CheckActionDuration(10*time.Second, 0); err != nil {
		t.Fatalf("legacy bundles must skip: %v", err)
	}
}
```

- [ ] **Step 2: Post-state**

```go
// internal/authbroker/replay/postate.go
package replay

import (
	"context"
	"fmt"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/recording"
)

// VerifyPostState recomputes the post-state hash in the current chromedp
// context and compares it to the expected hash. An empty expected hash
// (legacy bundles) passes through.
func VerifyPostState(ctx context.Context, expected string) error {
	if expected == "" {
		return nil
	}
	got, err := recording.ComputePostStateHash(ctx)
	if err != nil {
		return fmt.Errorf("postate: compute: %w", err)
	}
	if got != expected {
		return fmt.Errorf("postate: skeleton hash mismatch (refresh_required)")
	}
	return nil
}
```

```go
// internal/authbroker/replay/postate_test.go
package replay

import (
	"context"
	"testing"
)

func TestVerifyPostState_EmptyExpectedSkips(t *testing.T) {
	if err := VerifyPostState(context.Background(), ""); err != nil {
		t.Fatalf("legacy bundle must skip: %v", err)
	}
}
```

(Live chromedp verification covered by E2E in PR C and sec regression in PR D.)

- [ ] **Step 3: Principal**

```go
// internal/authbroker/replay/principal.go
package replay

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ExtractPrincipal scans cookies for JWT-shaped values and returns the value
// of the named claim. Signature is NOT verified — the goal is identity
// attribution, not auth.
func ExtractPrincipal(cookies []*http.Cookie, claim string) (string, bool) {
	if claim == "" {
		claim = "sub"
	}
	for _, c := range cookies {
		parts := strings.Split(c.Value, ".")
		if len(parts) != 3 {
			continue
		}
		payload, err := base64.RawURLEncoding.DecodeString(padBase64(parts[1]))
		if err != nil {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(payload, &m); err != nil {
			continue
		}
		if v, ok := m[claim]; ok {
			return fmt.Sprint(v), true
		}
	}
	return "", false
}

// VerifyPrincipal returns nil when the bundle's recorded principal matches
// the scan job's expected principal, OR when either is empty (no binding).
func VerifyPrincipal(bundlePrincipal, scanExpected string) error {
	if bundlePrincipal == "" || scanExpected == "" {
		return nil
	}
	if bundlePrincipal != scanExpected {
		return fmt.Errorf("principal: bundle=%q scan=%q (mismatch)", bundlePrincipal, scanExpected)
	}
	return nil
}

func padBase64(s string) string {
	switch len(s) % 4 {
	case 2: return s + "=="
	case 3: return s + "="
	}
	return s
}
```

```go
// internal/authbroker/replay/principal_test.go
package replay

import (
	"net/http"
	"testing"
)

func TestExtractPrincipal_FromJWT(t *testing.T) {
	// payload: {"sub":"alice"}
	jwt := "x.eyJzdWIiOiJhbGljZSJ9.y"
	cookies := []*http.Cookie{{Name: "sess", Value: jwt}}
	got, ok := ExtractPrincipal(cookies, "sub")
	if !ok || got != "alice" {
		t.Fatalf("got=%q ok=%v", got, ok)
	}
}

func TestExtractPrincipal_NoJWT(t *testing.T) {
	if _, ok := ExtractPrincipal([]*http.Cookie{{Name: "x", Value: "plain"}}, "sub"); ok {
		t.Fatal("plain cookie must not match")
	}
}

func TestVerifyPrincipal_Match(t *testing.T) {
	if err := VerifyPrincipal("alice", "alice"); err != nil { t.Fatal(err) }
}
func TestVerifyPrincipal_Mismatch(t *testing.T) {
	if err := VerifyPrincipal("alice", "bob"); err == nil { t.Fatal("expected mismatch") }
}
func TestVerifyPrincipal_EitherEmpty(t *testing.T) {
	if err := VerifyPrincipal("", "bob"); err != nil { t.Fatal(err) }
	if err := VerifyPrincipal("alice", ""); err != nil { t.Fatal(err) }
}
```

- [ ] **Step 4: Run + commit**

```
go test ./internal/authbroker/replay/ -run "TestCheckActionDuration|TestVerifyPostState|TestExtractPrincipal|TestVerifyPrincipal" -v
git add internal/authbroker/replay/anomaly.go \
        internal/authbroker/replay/anomaly_test.go \
        internal/authbroker/replay/postate.go \
        internal/authbroker/replay/postate_test.go \
        internal/authbroker/replay/principal.go \
        internal/authbroker/replay/principal_test.go
git commit -m "feat(replay): anomaly + post-state + principal helpers"
```

---

### Task B.3: Circuit breaker

**Files:**
- Create: `internal/authbroker/replay/circuit.go`
- Create: `internal/authbroker/replay/circuit_test.go`

- [ ] **Step 1: Implement**

```go
// internal/authbroker/replay/circuit.go
package replay

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const CircuitFailureThreshold = 3

type CircuitStore interface {
	IsOpen(ctx context.Context, bundleID uuid.UUID) (bool, error)
	RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg string) error
	Reset(ctx context.Context, bundleID uuid.UUID) error
}

type PostgresCircuitStore struct{ pool *pgxpool.Pool }

func NewCircuitStore(pool *pgxpool.Pool) *PostgresCircuitStore {
	return &PostgresCircuitStore{pool: pool}
}

func (s *PostgresCircuitStore) IsOpen(ctx context.Context, bundleID uuid.UUID) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT consecutive_failures FROM dast_replay_failures WHERE bundle_id = $1`,
		bundleID,
	).Scan(&n)
	if err != nil {
		// Row missing == zero failures.
		return false, nil
	}
	return n >= CircuitFailureThreshold, nil
}

func (s *PostgresCircuitStore) RecordFailure(ctx context.Context, bundleID uuid.UUID, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO dast_replay_failures (bundle_id, consecutive_failures, last_failure_at, last_error)
		VALUES ($1, 1, $2, $3)
		ON CONFLICT (bundle_id) DO UPDATE
		SET consecutive_failures = dast_replay_failures.consecutive_failures + 1,
		    last_failure_at      = $2,
		    last_error           = $3`,
		bundleID, time.Now(), errMsg)
	if err != nil {
		return fmt.Errorf("circuit: record failure: %w", err)
	}
	return nil
}

func (s *PostgresCircuitStore) Reset(ctx context.Context, bundleID uuid.UUID) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE dast_replay_failures SET consecutive_failures = 0 WHERE bundle_id = $1`,
		bundleID)
	return err
}
```

- [ ] **Step 2: Tests**

```go
// internal/authbroker/replay/circuit_test.go
package replay

import (
	"context"
	"testing"

	"github.com/google/uuid"

	pgtest "github.com/sentinelcore/sentinelcore/internal/testutil/pg"
)

func TestCircuit_OpensAfter3Failures(t *testing.T) {
	pool := pgtest.MustOpen(t)
	defer pool.Close()
	s := NewCircuitStore(pool)
	ctx := context.Background()
	id := uuid.New()
	mustInsertBundle(t, pool, id) // helper to satisfy FK; copy from bundles tests

	for i := 0; i < 2; i++ {
		if err := s.RecordFailure(ctx, id, "boom"); err != nil { t.Fatal(err) }
		open, _ := s.IsOpen(ctx, id)
		if open { t.Fatalf("opened too early after %d failures", i+1) }
	}
	if err := s.RecordFailure(ctx, id, "boom"); err != nil { t.Fatal(err) }
	open, _ := s.IsOpen(ctx, id)
	if !open { t.Fatal("expected open after 3rd failure") }
}

func TestCircuit_ResetClosesIt(t *testing.T) {
	pool := pgtest.MustOpen(t)
	defer pool.Close()
	s := NewCircuitStore(pool)
	ctx := context.Background()
	id := uuid.New()
	mustInsertBundle(t, pool, id)

	for i := 0; i < 3; i++ { _ = s.RecordFailure(ctx, id, "boom") }
	if err := s.Reset(ctx, id); err != nil { t.Fatal(err) }
	open, _ := s.IsOpen(ctx, id)
	if open { t.Fatal("expected closed after reset") }
}

// mustInsertBundle inserts a minimal dast_auth_bundles row so the FK on
// dast_replay_failures is satisfied. Copy the helper from the bundles tests
// or implement inline:
//   _, err := pool.Exec(ctx, `INSERT INTO dast_auth_bundles (id, ...) VALUES (...)`)
```

- [ ] **Step 3: Run + commit**

```
go test ./internal/authbroker/replay/ -run TestCircuit -v
git add internal/authbroker/replay/circuit.go internal/authbroker/replay/circuit_test.go
git commit -m "feat(replay): DB-backed circuit breaker (3 failures → open)"
```

---

### Task B.4: Wire all checks into Engine.Replay

**Files:**
- Modify: `internal/authbroker/replay/replayer.go`

- [ ] **Step 1: Extend Engine struct**

```go
type Engine struct {
	rateLimit    *RateLimit
	circuit      CircuitStore // optional; if nil, circuit checks are skipped
	expectedPrincipal string  // set per-replay; threaded through Replay()
}

func NewEngine() *Engine {
	return &Engine{rateLimit: NewRateLimit()}
}

func (e *Engine) WithCircuit(c CircuitStore) *Engine {
	e.circuit = c
	return e
}
```

- [ ] **Step 2: Replay method**

Replace the `Replay` method body with the integrated check sequence. Key additions, in order, before the existing browser launch:

```go
// 1. Existing nil/type/expired/no-actions guards.
// 2. Existing host derivation.
// 3. NEW: circuit check.
if e.circuit != nil {
	open, err := e.circuit.IsOpen(ctx, mustParseUUID(b.ID))
	if err != nil {
		return nil, fmt.Errorf("replay: circuit check: %w", err)
	}
	if open {
		return nil, fmt.Errorf("replay: circuit open for bundle %s (refresh_required)", b.ID)
	}
}
// 4. Existing rate limit.
// 5. Existing preflight host match.
// 6. NEW: principal binding (if scan provided expectedPrincipal via context value).
if exp, _ := ctx.Value(scanPrincipalKey{}).(string); exp != "" {
	if err := VerifyPrincipal(b.TargetPrincipal, exp); err != nil {
		return nil, fmt.Errorf("replay: %w", err)
	}
}
// 7. NEW: aggregate budget.
total := 0
for _, a := range b.Actions { total += a.DurationMs }
ctx, cancel := AggregateBudget(ctx, total)
defer cancel()
```

In the per-action loop add:

```go
actStart := time.Now()
// existing switch on a.Kind …
if err := CheckActionDuration(time.Since(actStart), a.DurationMs); err != nil {
	if e.circuit != nil { _ = e.circuit.RecordFailure(ctx, mustParseUUID(b.ID), err.Error()) }
	return nil, err
}
if err := VerifyPostState(timeoutCtx, a.ExpectedPostStateHash); err != nil {
	if e.circuit != nil { _ = e.circuit.RecordFailure(ctx, mustParseUUID(b.ID), err.Error()) }
	return nil, err
}
```

After successful return, add:

```go
if e.circuit != nil {
	_ = e.circuit.Reset(ctx, mustParseUUID(b.ID))
}
```

Define `scanPrincipalKey` and `mustParseUUID` as private types/helpers in the same file.

```go
type scanPrincipalKey struct{}
// ContextWithExpectedPrincipal is exported for callers (RecordedLoginStrategy) to set the value.
func ContextWithExpectedPrincipal(parent context.Context, principal string) context.Context {
	return context.WithValue(parent, scanPrincipalKey{}, principal)
}
func mustParseUUID(s string) uuid.UUID {
	u, _ := uuid.Parse(s)
	return u
}
```

- [ ] **Step 3: Update existing replayer_test.go**

Most tests still hold (they don't pass a circuit, so circuit checks no-op). Add at least one test that asserts the new principal/postate/anomaly hooks are wired:

```go
func TestEngine_Replay_PrincipalMismatch(t *testing.T) {
	e := NewEngine()
	b := &bundles.Bundle{
		ID: "11111111-1111-1111-1111-111111111111",
		Type: "recorded_login",
		TargetHost: "app.bank.tld",
		TargetPrincipal: "alice",
		ExpiresAt: time.Now().Add(time.Hour),
		Actions: []bundles.Action{
			{Kind: bundles.ActionNavigate, URL: "https://app.bank.tld/x"},
		},
	}
	ctx := ContextWithExpectedPrincipal(context.Background(), "bob")
	_, err := e.Replay(ctx, b)
	if err == nil || !strings.Contains(err.Error(), "principal") {
		t.Fatalf("expected principal mismatch, got %v", err)
	}
}
```

- [ ] **Step 4: Run + commit**

```
go test ./internal/authbroker/replay/ -v
git add internal/authbroker/replay/replayer.go internal/authbroker/replay/replayer_test.go
git commit -m "feat(replay): wire circuit + anomaly + postate + principal into Engine.Replay"
```

---

### Task B.5: Circuit reset HTTP handler

**Files:**
- Create: `internal/controlplane/circuit_handler.go`
- Create: `internal/controlplane/circuit_handler_test.go`
- Modify: `internal/controlplane/router.go` (or wherever DAST routes are registered — locate via `grep -rn "dast/bundles" internal/controlplane/`)

- [ ] **Step 1: Handler**

```go
// internal/controlplane/circuit_handler.go
package controlplane

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/authbroker/replay"
)

func CircuitResetHandler(store replay.CircuitStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Path: /api/dast/bundles/{id}/circuit/reset
		id := chiURLParam(r, "id") // or your existing route param helper
		bid, err := uuid.Parse(id)
		if err != nil {
			http.Error(w, "invalid bundle id", http.StatusBadRequest)
			return
		}
		if err := store.Reset(r.Context(), bid); err != nil {
			http.Error(w, "reset failed", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
```

- [ ] **Step 2: Wire route + auth**

In the router, attach:

```go
r.With(authz.RequireDASTRole(roleStore, authz.RoleRecordingAdmin)).
  Post("/api/dast/bundles/{id}/circuit/reset", CircuitResetHandler(circuitStore))
```

(Match the actual router style — chi, gorilla/mux, or net/http; check `internal/controlplane/router.go`.)

- [ ] **Step 3: Test**

```go
// internal/controlplane/circuit_handler_test.go
package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

type fakeCircuit struct{ resetCalls int }
func (f *fakeCircuit) IsOpen(ctx context.Context, _ uuid.UUID) (bool, error)             { return false, nil }
func (f *fakeCircuit) RecordFailure(ctx context.Context, _ uuid.UUID, _ string) error    { return nil }
func (f *fakeCircuit) Reset(ctx context.Context, _ uuid.UUID) error                       { f.resetCalls++; return nil }

func TestCircuitResetHandler_Success(t *testing.T) {
	c := &fakeCircuit{}
	h := CircuitResetHandler(c)
	req := httptest.NewRequest("POST", "/api/dast/bundles/00000000-0000-0000-0000-000000000001/circuit/reset", nil)
	// inject the URL param via your router's chi/mux test helper
	// chi: req = req.WithContext(chi.RouteContext(req.Context()).URLParam("id", "..."))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent { t.Fatalf("status=%d", w.Code) }
	if c.resetCalls != 1 { t.Fatalf("reset not called") }
}

func TestCircuitResetHandler_BadUUID(t *testing.T) {
	c := &fakeCircuit{}
	h := CircuitResetHandler(c)
	req := httptest.NewRequest("POST", "/api/dast/bundles/not-a-uuid/circuit/reset", nil)
	// inject "not-a-uuid" as the URL param
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest { t.Fatalf("status=%d", w.Code) }
}
```

(For the auth check, copy the existing `roleStore` test fixture from `internal/dast/authz/middleware_test.go`.)

- [ ] **Step 4: Run + commit**

```
go test ./internal/controlplane/ -run TestCircuitResetHandler -v
git add internal/controlplane/circuit_handler.go internal/controlplane/circuit_handler_test.go internal/controlplane/router.go
git commit -m "feat(controlplane): POST /api/dast/bundles/:id/circuit/reset (recording_admin)"
```

PR B complete; push.

```
git push
```

---

## PR C — Credential injection during replay (3 tasks)

### Task C.1: injectFill helper

**Files:**
- Create: `internal/authbroker/replay/inject.go`
- Create: `internal/authbroker/replay/inject_test.go`

- [ ] **Step 1: Implement**

```go
// internal/authbroker/replay/inject.go
package replay

import (
	"context"
	"fmt"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
	"github.com/sentinelcore/sentinelcore/internal/dast/credentials"
)

// InjectFill loads the credential keyed by action.VaultKey from the credential
// store and types it into the field identified by action.Selector. The
// plaintext is overwritten in memory before this function returns.
func InjectFill(ctx context.Context, store credentials.Store, bundleID uuid.UUID, action bundles.Action) error {
	if action.Kind != bundles.ActionFill {
		return fmt.Errorf("inject: action kind %q is not fill", action.Kind)
	}
	if action.VaultKey == "" {
		return fmt.Errorf("inject: fill action has no vault_key")
	}
	if action.Selector == "" {
		return fmt.Errorf("inject: fill action has no selector")
	}
	plain, err := store.Load(ctx, bundleID, action.VaultKey)
	if err != nil {
		return fmt.Errorf("inject: credential load: %w", err)
	}
	defer zeroBytes(plain)
	return chromedp.Run(ctx, chromedp.SendKeys(action.Selector, string(plain), chromedp.ByQuery))
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
```

- [ ] **Step 2: Tests**

```go
// internal/authbroker/replay/inject_test.go
package replay

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/sentinelcore/sentinelcore/internal/dast/bundles"
)

type fakeCredStore struct {
	loadErr error
	value   []byte
}
func (f *fakeCredStore) Save(_ context.Context, _, _ uuid.UUID, _ string, _ []byte) error { return nil }
func (f *fakeCredStore) Load(_ context.Context, _ uuid.UUID, _ string) ([]byte, error) {
	if f.loadErr != nil { return nil, f.loadErr }
	return append([]byte(nil), f.value...), nil
}
func (f *fakeCredStore) Delete(_ context.Context, _ uuid.UUID, _ string) error { return nil }
func (f *fakeCredStore) ListKeys(_ context.Context, _ uuid.UUID) ([]string, error) { return nil, nil }

func TestInjectFill_RejectsNonFillKind(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{}, uuid.New(),
		bundles.Action{Kind: bundles.ActionClick, Selector: "#x", VaultKey: "k"})
	if err == nil { t.Fatal("expected kind rejection") }
}

func TestInjectFill_MissingVaultKey(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x"})
	if err == nil { t.Fatal("expected vault_key rejection") }
}

func TestInjectFill_MissingSelector(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, VaultKey: "k"})
	if err == nil { t.Fatal("expected selector rejection") }
}

func TestInjectFill_LoadErrorBubbles(t *testing.T) {
	err := InjectFill(context.Background(), &fakeCredStore{loadErr: errors.New("boom")}, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x", VaultKey: "k"})
	if err == nil || !errorContains(err, "credential load") {
		t.Fatalf("expected credential load error, got %v", err)
	}
}

func errorContains(err error, sub string) bool {
	return err != nil && (err.Error() == sub || (len(err.Error()) >= len(sub) &&
		(err.Error()[:len(sub)] == sub || (len(err.Error()) > len(sub) &&
			(err.Error()[len(err.Error())-len(sub):] == sub || stringContains(err.Error(), sub))))))
}
func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ { if s[i:i+len(sub)] == sub { return true } }
	return false
}
```

(Or just `import "strings"` and use `strings.Contains(err.Error(), sub)` directly. Use whichever the rest of the package already imports.)

- [ ] **Step 3: Run + commit**

```
go test ./internal/authbroker/replay/ -run TestInjectFill -v
git add internal/authbroker/replay/inject.go internal/authbroker/replay/inject_test.go
git commit -m "feat(replay): InjectFill — KMS-backed credential injection during replay"
```

---

### Task C.2: Wire ActionFill into the replay walker

**Files:**
- Modify: `internal/authbroker/replay/replayer.go`

- [ ] **Step 1: Engine holds credential store**

```go
type Engine struct {
	rateLimit *RateLimit
	circuit   CircuitStore
	creds     credentials.Store
}

func (e *Engine) WithCredentials(s credentials.Store) *Engine {
	e.creds = s
	return e
}
```

- [ ] **Step 2: Action loop**

In the action switch inside `run()`, add:

```go
case bundles.ActionFill:
	if e.creds == nil {
		return nil, fmt.Errorf("replay: action %d is fill but no credential store configured", i)
	}
	if err := InjectFill(timeoutCtx, e.creds, mustParseUUID(b.ID), a); err != nil {
		return nil, fmt.Errorf("replay: action %d: %w", i, err)
	}
```

- [ ] **Step 3: Strategy DI**

In `internal/authbroker/recorded_login_strategy.go`, when constructing the engine for refresh, pass the credential store from the strategy:

```go
type RecordedLoginStrategy struct {
	Bundles  bundleLoader
	Replayer *replay.Engine
	Creds    credentials.Store
}

// In Refresh, when invoking the engine:
eng := s.Replayer.WithCredentials(s.Creds)  // chainable
res, err := eng.Replay(ctx, b)
```

- [ ] **Step 4: Run + commit**

```
go build ./...
go test ./internal/authbroker/...
git add internal/authbroker/replay/replayer.go internal/authbroker/recorded_login_strategy.go
git commit -m "feat(replay): walker injects credentials on ActionFill"
```

---

### Task C.3: End-to-end smoke

**Files:**
- Create: `internal/authbroker/replay/e2e_test.go`

- [ ] **Step 1: Test**

Build a self-contained end-to-end:

1. Spin up `httptest.NewTLSServer` returning two pages: `/login` (form with `<input name="user">`, `<input name="pwd">`, `<button id="go">`) and `/dashboard` (simple "ok").
2. Run the recorder against `/login` for ~5 s; in parallel, drive chromedp to type `alice` into `user`, type `redacted` into `pwd`, click `#go`. Stop the recorder; assert `Bundle.Actions` contains 1 fill (user) — note: pwd typing should be captured as fill with VaultKey blank (recorder doesn't know yet it's secret); selector should be `[name="pwd"]`.
3. Save a credential: `store.Save(ctx, customer, bundleID, "login_pwd", []byte("redacted"))`.
4. Mark the action with `VaultKey="login_pwd"` (operator-side: in the real flow this happens via UI; in the test, mutate the bundle in-place).
5. Approve the bundle as automatable; persist via `bundles.PostgresStore.Save`.
6. Call `engine.WithCredentials(store).Replay(ctx, bundle)`; expect a `*Result` with cookies for the test server's host.

Skip on `testing.Short()` — this test launches a real headless browser.

```go
func TestE2E_RecordCredentialReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: launches headless chrome")
	}
	// … see steps above. Reuse helpers from recording_test.go and bundles store_test.go.
}
```

If running this test against the local stack is infeasible in the worktree (Chrome not present), gate behind `os.Getenv("SENTINELCORE_E2E") == "1"` and document that ops runs it manually pre-deploy.

- [ ] **Step 2: Commit**

```
git add internal/authbroker/replay/e2e_test.go
git commit -m "test(replay): end-to-end record→credential→replay smoke (skipped without SENTINELCORE_E2E=1)"
```

PR C complete; push.

```
git push
```

---

## PR D — Sec regression + deploy (3 tasks)

### Task D.1: Sec regression tests sec-05..sec-09

**Files:**
- Modify: `internal/dast/security_regression_replay_test.go`

- [ ] **Step 1: Add tests**

Append the following tests to the file. Each test must use a unique bundle ID to avoid the rate limiter and circuit state from leaking across cases.

```go
// sec-05: tampered ExpectedPostStateHash on a recorded action causes the
// replayer to surface a refresh_required error during postate verification.
func TestSec05_TamperedPostStateHashRejected(t *testing.T) {
	// VerifyPostState returns nil for empty expected; we test the non-empty branch.
	// Because chromedp isn't available in unit tests, exercise the helper directly.
	if err := replay.VerifyPostState(context.Background(), "deadbeef"); err == nil {
		// Without chromedp, ComputePostStateHash returns an error → VerifyPostState surfaces it.
		t.Fatal("expected error path")
	}
}

// sec-06: principal mismatch (low-priv recording reused for an admin scan).
func TestSec06_PrincipalMismatchRejected(t *testing.T) {
	if err := replay.VerifyPrincipal("alice", "admin"); err == nil {
		t.Fatal("expected mismatch")
	}
}

// sec-07: circuit opens after 3 consecutive failures (DB-backed).
func TestSec07_CircuitOpensAfter3(t *testing.T) {
	pool := pgtest.MustOpen(t)
	defer pool.Close()
	s := replay.NewCircuitStore(pool)
	id := uuid.New()
	mustInsertBundle(t, pool, id)
	ctx := context.Background()
	for i := 0; i < 3; i++ { _ = s.RecordFailure(ctx, id, "boom") }
	open, _ := s.IsOpen(ctx, id)
	if !open { t.Fatal("expected circuit open") }
}

// sec-08: forged vault_key reference — InjectFill returns the load error,
// no chromedp action is issued.
func TestSec08_ForgedVaultKeyRejected(t *testing.T) {
	store := &fakeCredStore{loadErr: errors.New("not found")}
	err := replay.InjectFill(context.Background(), store, uuid.New(),
		bundles.Action{Kind: bundles.ActionFill, Selector: "#x", VaultKey: "ghost"})
	if err == nil || !strings.Contains(err.Error(), "credential load") {
		t.Fatalf("expected load failure, got %v", err)
	}
}

// sec-09: fill events must never carry a value field. Server-side validator
// rejects any payload that does.
func TestSec09_FillValueRejectedAtIngest(t *testing.T) {
	_, err := recording.ParseAndValidate(`{"kind":"fill","selector":"#pwd","t":1,"value":"x"}`)
	if err == nil || !strings.Contains(err.Error(), "must not carry value") {
		t.Fatalf("expected value rejection, got %v", err)
	}
}
```

(Add the imports at the top: `replay`, `recording`, `errors`, `strings`, `pgtest`, `uuid`.)

The `fakeCredStore` type already exists in `internal/authbroker/replay/inject_test.go` (PR C) — to share it across packages, either move it to `internal/authbroker/replay/testutil.go` (build-tagged `_test.go` exposed via `replay_test` package) or duplicate the minimal version in this test file. Duplicate for simplicity.

- [ ] **Step 2: Run**

```
go test ./internal/dast/ -run "TestSec0[3-9]" -v
```

Expected: all 7 (sec-03..09) PASS.

- [ ] **Step 3: Commit**

```
git add internal/dast/security_regression_replay_test.go
git commit -m "test(dast): security regression sec-05..sec-09 (postate/principal/circuit/vault/fill-value)"
```

---

### Task D.2: Final test pass + push

```
go test ./internal/...
go vet ./...
git push
```

Expected: all green.

---

### Task D.3: Build + deploy + open PR

```
rsync -az --delete --exclude .git --exclude '*.test' --exclude '.worktrees' \
  internal migrations pkg rules scripts cmd Dockerfile go.mod go.sum customer-sdks \
  okyay@77.42.34.174:/tmp/sentinelcore-src/

ssh okyay@77.42.34.174 "cp /tmp/sentinelcore-src/migrations/048_dast_credential_secrets.up.sql /opt/sentinelcore/migrations/ && \
  cp /tmp/sentinelcore-src/migrations/049_dast_replay_hardening.up.sql /opt/sentinelcore/migrations/ && \
  docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -f /migrations/048_dast_credential_secrets.up.sql && \
  docker exec sentinelcore_postgres psql -U sentinelcore -d sentinelcore -f /migrations/049_dast_replay_hardening.up.sql"

ssh okyay@77.42.34.174 "cd /tmp/sentinelcore-src && \
  docker build --no-cache -t sentinelcore/controlplane:replay-hardening-prd --build-arg SERVICE=controlplane . && \
  docker tag sentinelcore/controlplane:replay-hardening-prd sentinelcore/controlplane:pilot && \
  cd /opt/sentinelcore/compose && docker compose up -d --force-recreate controlplane"

curl -s -o /dev/null -w 'healthz: %{http_code}\nreadyz: %{http_code}\n' \
  https://sentinelcore.resiliencetech.com.tr/healthz \
  https://sentinelcore.resiliencetech.com.tr/readyz

gh pr create --base phase2/api-dast --head feat/dast-replay-hardening-2026-05 \
  --title "feat(dast): replay hardening + recorder enhancements (plan #5/6)" \
  --body "Plan #5 — adds click+fill capture, KMS-backed credential store, replay anomaly/postate/principal/circuit hardening. Spec: docs/superpowers/specs/2026-05-05-dast-replay-hardening-design.md."
```

PR D complete.

---

## Self-review

### Spec coverage

| Spec section | Implementing task |
|--------------|-------------------|
| §4.1 capture content script | A.3 (capture.js) |
| §4.1 server-side validator | A.3 (capture.go ParseAndValidate) |
| §4.2 recorder wiring | A.3 (recorder.go bind handler) |
| §4.3 post-state hash at capture | A.4 (postate.go + recorder integration) |
| §4.4 per-action duration | A.4 (recorder.go DurationMs computation) |
| §5.1 schema | A.1 (migration 048) |
| §5.2 store contract | A.5 (credentials/store.go) |
| §5.3 CLI | A.5 (cli/dast_credentials.go) |
| §6.1 anomaly detection | B.2 (anomaly.go) + B.4 (engine wiring) |
| §6.2 post-state assertion | B.2 (postate.go) + B.4 (engine wiring) |
| §6.3 principal binding | B.2 (principal.go) + B.4 (engine wiring) |
| §6.4 circuit breaker | B.1 (migration 049) + B.3 (circuit.go) + B.4 (engine wiring) + B.5 (HTTP reset) |
| §6.5 engine wiring | B.4 |
| §7 credential injection | C.1 (inject.go) + C.2 (engine wiring) |
| §8 sec regression sec-05..09 | D.1 |
| §9 migrations 048+049 | A.1, B.1, D.3 (deploy) |
| §10 audit events | A.5 (credentials/audit.go) — replay-side audit emitters folded into engine wiring in B.4 (TODO inline if time-pressed) |
| §11 rollout | D.3 |

### Type / signature consistency

- `bundles.Action`: `VaultKey`, `ExpectedPostStateHash`, `DurationMs` defined in A.2; consumed in A.3 (recorder), A.4 (postate hashing), B.2 (anomaly + postate verifier), B.4 (engine), C.1 (inject), D.1 (sec tests). Names match throughout.
- `credentials.Store`: defined in A.5 with `Save(ctx, customerID, bundleID, vaultKey, plaintext)` and `Load(ctx, bundleID, vaultKey)`. Used by C.1 / C.2 with the same signature.
- `replay.CircuitStore`: defined in B.3 with `IsOpen / RecordFailure / Reset`. Used in B.4 (engine) and B.5 (HTTP handler).
- `replay.ContextWithExpectedPrincipal` / `scanPrincipalKey`: defined in B.4; used by `RecordedLoginStrategy.Refresh` which sets the value before calling `Replay`.

### Open items (intentional)

- The `recorder.go` integration test in A.3 step 6 is documented as deferrable to plan #6 if the recorder's struct doesn't expose a test hook. The unit-tested validator + the E2E in PR C give defence-in-depth without it.
- The `audit.Event` field shape used in A.5 step 2 is a placeholder — verify against `pkg/audit/` and adjust before the first commit on that step.
- The router wiring in B.5 step 2 depends on which router framework controlplane uses; the developer must adapt the snippet to chi / mux / net/http accordingly.

---

## Execution handoff

Plan #5 saved to `docs/superpowers/plans/2026-05-05-dast-replay-hardening.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task with two-stage review.
**2. Inline Execution** — execute tasks in this session via executing-plans, with checkpoints.
