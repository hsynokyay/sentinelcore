# Auth / Authz / Session SAST Rules — Design Spec

**Status:** Design complete, awaiting implementation plan
**Owner:** Huseyin
**Target:** `internal/sast/` — add 36 new SAST rules covering authentication, authorization, session, JWT, cookie, and CSRF concerns. One small engine extension (`arg_text_contains_any` / `arg_text_missing_any`) supports object-key-presence matching for cookie-attribute rules.
**Date:** 2026-05-02
**Predecessor:** `2026-05-01-sast-rule-expansion-design.md` (PR #7 merged 2026-05-02)

---

## 1. Goals & non-goals

### Goals

- Expand SAST coverage from 64 rules to 100 rules by filling the largest remaining vulnerability-class gap: **auth/authz/session/cookie/JWT/CSRF**.
- Add a minimal engine matcher (`arg_text_contains_any`, `arg_text_missing_any`) so that rules can assert "this options object includes/omits a specific key" without a full AST keyword-argument walk.
- Each new rule ships with a positive + negative fixture, verified by the existing fixture-driven worker test loop.
- Maintain language coverage parity across Python, JavaScript, Java, C#.

### Non-goals

- **No framework-aware authorization detection.** "Missing `@PreAuthorize` on Spring controller" / "Missing auth middleware on Express route" require controller-graph analysis; deferred to a future Faz 8.5.
- **No business-logic rules.** IDOR, role-bypass, broken access control are out of scope — these are largely undetectable statically and belong in DAST/manual-review territory.
- **No new languages.** Go, Ruby, PHP are out of scope for this phase.
- **No DB migration.** `findings.rule_id` is `TEXT` and `vuln_class` is opaque — new vuln classes are accepted without schema changes.

---

## 2. Background & current state

After PR #7 merged on 2026-05-02, SAST has 64 structured rules across 4 languages covering 13 vulnerability classes (cmd, crypto, deser, eval, log, path, redirect, secret, sql, ssrf, xss, xxe, ssti, nosql, mass-assignment, prototype-pollution, http-header). Auth-adjacent gaps remain:

| Gap | Languages affected | Static-detectable? |
|-----|-------------------|--------------------|
| Cookie missing Secure / HttpOnly / SameSite | All 4 | Yes (with engine extension) |
| JWT `verify=False` / unsigned `decode` | All 4 | Yes (`ast_call`) |
| JWT `alg=none` accepted | All 4 | Yes (`ast_call`) |
| Hardcoded JWT/session secret | All 4 | Yes (extends existing SECRET pattern) |
| Predictable session ID (Math.random / java.util.Random) | JS, Java, C# | Yes (`ast_call`) |
| Missing session regeneration on auth | Py, Java | Partially — pattern: write-to-session followed by no rotation call |
| Authorization header injection (taint) | All 4 | Yes (taint, sub-class of `http_header_injection`) |
| CSRF token compared with `==` (not constant-time) | JS, Py, Java | Yes (`ast_call` — sink absence pattern) |
| Missing `@PreAuthorize` / auth middleware | All 4 | **No** — needs framework-aware analysis (deferred) |
| Broken access control / IDOR | All | **No** — deferred (DAST territory) |

This spec covers everything in the "Yes" rows.

---

## 3. New vuln_class values

These strings are added to the engine's vocabulary. The engine treats `vuln_class` opaquely, so adding new values requires no engine code changes (only sink declarations in framework-model JSONs and rule-file `detection.vuln_class` references).

| vuln_class | Used by |
|---|---|
| `cookie_misconfig` | All 12 cookie rules |
| `jwt_unverified` | JWT verify=False / unsigned decode (4 rules) |
| `jwt_weak_alg` | JWT alg=none (4 rules) |
| `weak_session_id` | Predictable session ID (3 rules) |
| `session_no_rotate` | Missing session regeneration (2 rules) |
| `auth_header_injection` | 4 taint rules — narrower than existing `http_header_injection` |
| `csrf_weak_compare` | 3 rules |

Hardcoded JWT/session secret reuses the existing `secret` class; the rule file just narrows the variable-name regex.

---

## 4. Engine extension — `arg_text_contains_any` / `arg_text_missing_any`

### 4.1 Why

Cookie-attribute rules need to fire when an options-object argument either:
- contains a substring like `"httpOnly: false"` (explicit anti-pattern), or
- **omits** a substring like `"httpOnly"` entirely (implicit insecure default).

The existing `arg_matches_any` only inspects string-literal arguments — it can't see object expressions. Adding a full AST keyword-argument walker is engine refactor territory; instead, we add a minimal text-of-arg helper that returns the original source-text span of the call argument.

### 4.2 Schema additions

In `internal/sast/rules/schema.go`, extend `CallPattern`:

```go
type CallPattern struct {
    ReceiverFQN          string   `json:"receiver_fqn,omitempty"`
    Callee               string   `json:"callee,omitempty"`
    CalleeFQN            string   `json:"callee_fqn,omitempty"`
    ArgIndex             *int     `json:"arg_index,omitempty"`
    ArgMatchesAny        []string `json:"arg_matches_any,omitempty"`
    ArgTextContainsAny   []string `json:"arg_text_contains_any,omitempty"` // NEW
    ArgTextMissingAny    []string `json:"arg_text_missing_any,omitempty"`  // NEW
    MessageTemplate      string   `json:"message_template,omitempty"`
}
```

Semantics:
- `ArgTextContainsAny` — fires when the source text of the argument at `ArgIndex` contains **any** listed substring (case-sensitive). If `ArgIndex` is nil, all args are joined.
- `ArgTextMissingAny` — fires when the source text of the argument at `ArgIndex` is missing **any** listed substring. (i.e. at least one substring not present.)

### 4.3 IR changes

The IR currently stores call instructions with a list of operand IDs. We add an optional `ArgSourceText []string` field on the Call instruction, populated by the AST adapter when each call site is lowered. For arguments that aren't simple literals, the text is the verbatim slice of source between the start and end positions of the argument node.

For Java/C# AST adapters this is straightforward. For Python, the `ast` module exposes `lineno` / `col_offset` / `end_lineno` / `end_col_offset`; we slice the source buffer. For JS/TS via the existing tree-sitter integration, we already have node ranges.

### 4.4 Tests

- `engine/cmd_path_test.go` (or new `engine/arg_text_test.go`): unit-test the matcher with synthetic Call instructions and assert match/no-match for both new options.
- Existing rule tests are unchanged; new rules in PRs B+ exercise the matcher end-to-end.

---

## 5. Rule inventory — 36 rules

Subtotals: 12 cookie + 12 JWT + 5 session + 4 auth-header + 3 CSRF = 36.

Naming: `SC-<LANG>-<CLASS>-NNN`. Languages: `PY`, `JS`, `JAVA`, `CSHARP`. CWE/OWASP per row.

### 5.1 Cookie attribute rules (12)

CWE-1004 (HttpOnly), CWE-614 (Secure), CWE-1275 (SameSite). OWASP A05:2021.

| Rule ID | Detection | Sink target |
|---|---|---|
| `SC-PY-COOKIE-001` Missing Secure | `ast_call` + `arg_text_missing_any: ["secure", "Secure"]` | Flask `Response.set_cookie`, Django `HttpResponse.set_cookie` |
| `SC-PY-COOKIE-002` Missing HttpOnly | same with `httponly` / `HttpOnly` | same |
| `SC-PY-COOKIE-003` Missing SameSite | same with `samesite` / `SameSite` | same |
| `SC-JS-COOKIE-001/002/003` | `ast_call` + arg-text checks | Express `res.cookie`, `cookie-session`, `express-session.session({...cookie:{}})`, `set-cookie-parser` |
| `SC-JAVA-COOKIE-001/002/003` | `ast_call` (no text matcher needed — separate setter calls) | Servlet `Cookie.setSecure(false)` / not-called pattern; Spring `ResponseCookie.builder().secure(false)` |
| `SC-CSHARP-COOKIE-001/002/003` | `ast_call` + arg-text checks on `CookieOptions` initializer | ASP.NET `Response.Cookies.Append(name, value, new CookieOptions{...})` |

Java differs from JS/Py/C# because `Cookie` configuration is a series of setter calls, not an options object. Detection there checks for `setHttpOnly`/`setSecure` calls absent from the same basic block as `addCookie`. This is achievable with a small "negative pattern" — covered as `ast_call` with `arg_text_missing_any` against the surrounding statement source. Acceptable false-negative rate; we explicitly accept that Java cookie misconfig is the trickiest of the four.

### 5.2 JWT rules (12)

CWE-347 (improper signature verification), CWE-327 (weak algorithm). OWASP A02:2021, A07:2021.

| Rule ID | Detection | Sink target |
|---|---|---|
| `SC-{LANG}-JWT-001` `verify=False` / unsigned decode | `ast_call` + arg-text or arg-regex | jsonwebtoken `jwt.verify(t, secret, {algorithms:false})` and `jwt.decode` without verify; pyjwt `jwt.decode(t, options={"verify_signature": False})`; jjwt `Jwts.parser().setSigningKey()` absence; System.IdentityModel `JwtSecurityTokenHandler.ReadJwtToken` (no validation) |
| `SC-{LANG}-JWT-002` `alg=none` accepted | `ast_call` + `arg_text_contains_any: ["alg.*none", "HS256.*none"]` | algorithms list literally containing "none" or empty |
| `SC-{LANG}-JWT-003` Hardcoded JWT secret | `ast_assign` (existing schema, narrower NameMatchesAny: `jwt.*secret`, `jwt_key`, `JWT_SECRET`) | regular variable/property assignments |

For all 4 languages we have 3 rules each = 12.

### 5.3 Session rules (5)

CWE-330 (insufficient randomness), CWE-384 (session fixation). OWASP A07:2021.

| Rule ID | Detection | Sink target |
|---|---|---|
| `SC-JS-SESSION-001` Predictable session ID | `ast_call` (any of `Math.random`, `crypto.pseudoRandomBytes`) feeding into `req.session.id =` or `req.sessionID =` (taint) | actually implemented as a small-radius `ast_call` on `Math.random()` whose surrounding statement contains `session` |
| `SC-JAVA-SESSION-001` Predictable session ID | `ast_call` on `java.util.Random.nextInt/nextLong` whose statement source contains `session`/`sessionId` | servlet contexts |
| `SC-CSHARP-SESSION-001` Predictable session ID | `ast_call` on `System.Random.Next` near `Session.Id`/`SessionState.SessionID` | ASP.NET |
| `SC-PY-SESSION-002` Missing session regeneration after auth | `ast_call` on `flask_login.login_user` / `session["user_id"] = …` whose enclosing function does not call `session.clear()` or `session.regenerate()` | Flask only |
| `SC-JAVA-SESSION-002` Missing `request.changeSessionId()` | `ast_call` — login pattern (`request.login(…)`, `Authentication auth =`) without subsequent `request.changeSessionId()` | Servlet, Spring Security |

The PY/Java SESSION-002 rules use a "function-scope absence" pattern — implemented as a synthetic `ast_call` that fires when the enclosing function contains the trigger but lacks the rotation call. This is a pragmatic best-effort: it produces some false positives where the rotation happens in middleware but is acceptable for a static-detection signal.

### 5.4 Authorization header injection (4)

CWE-113. OWASP A03:2021.

| Rule ID | Detection | Sink target |
|---|---|---|
| `SC-{LANG}-AUTHHEADER-001` Tainted Authorization header | `taint` on new vuln_class `auth_header_injection` | Restricted subset of existing http-header sinks: only fires when the header name argument matches `Authorization` or `Cookie` |

Implementation: the existing `http_header_injection` sinks gain a sibling vuln_class `auth_header_injection` for sinks where `args[0]` is a literal matching `"Authorization"` or `"Cookie"`. The taint engine matches based on `vuln_class`, so the same sink position can register both classes — the rule that fires depends on which `vuln_class` is queried. Concretely, in framework model JSONs we add new entries:

```json
{"kind": "sink", "receiver_fqn": "res", "method": "setHeader", "vuln_class": "auth_header_injection", "args": [1], "arg_match": "Authorization|Cookie"}
```

`arg_match` is **already** supported by some sinks in the existing models (verified in `engine/models.go`); if not, add it as part of PR A.

### 5.5 CSRF unsafe compare (3)

CWE-203 (timing-side-channel) + CWE-352. OWASP A01:2021.

| Rule ID | Detection | Pattern |
|---|---|---|
| `SC-JS-CSRF-001` | `ast_call` on `===` / `==` between an expression matching `csrfToken`/`x_csrf_token`/`req.csrf*` (textually) — i.e. `arg_text_contains_any` against the binary-expr source. Negative variant: `crypto.timingSafeEqual` present | Express csurf, custom CSRF middlewares |
| `SC-PY-CSRF-001` | `ast_call` similar pattern; negative: `hmac.compare_digest` | Flask, Django |
| `SC-JAVA-CSRF-001` | `ast_call`; negative: `MessageDigest.isEqual` | Spring SecurityFilter |

Implementation note: detecting `==` operators requires lowering binary expressions to Call instructions (or adding a new `ast_binop` detection kind). To keep PR A scope tight, we instead detect the **safe** comparison's absence in functions that obviously handle CSRF tokens (function name or parameter contains "csrf"). Slightly higher false-positive risk; documented in §8.

---

## 6. PR strategy — 4 PRs

| PR | Scope | LoC estimate |
|---|---|---|
| **PR A** | Engine extension: schema fields, IR `ArgSourceText` propagation, `arg_text_contains_any` / `arg_text_missing_any` matcher, unit tests | ~150 LoC |
| **PR B** | 12 cookie rules + 4 framework-model extensions (Flask/Django/Express/ASP.NET cookie sinks) + fixtures | ~600 LoC config/fixtures |
| **PR C** | 12 JWT rules + 5 session rules + 4 auth-header rules + framework-model extensions + fixtures (largest PR) | ~900 LoC config/fixtures |
| **PR D** | 3 CSRF rules + fixtures + loader test additions | ~200 LoC |

Each PR builds the controlplane image, deploys via the production compose stack (same flow as SAST expansion), and is independently reverable via the rollback tag taken before PR A.

---

## 7. File layout

### New files

```
internal/sast/engine/models/
  python-cookie.json       # set_cookie sink for Flask/Django
  js-cookie.json           # res.cookie / cookie-session
  java-cookie.json         # javax.servlet.Cookie / Spring ResponseCookie
  csharp-cookie.json       # CookieOptions
  python-jwt.json          # pyjwt
  js-jwt.json              # jsonwebtoken
  java-jwt.json            # jjwt
  csharp-jwt.json          # System.IdentityModel.Tokens.Jwt
  python-session.json      # Flask session / Django auth
  java-session.json        # Servlet HttpSession
  csharp-session.json      # ASP.NET SessionState
  js-csrf.json             # csurf
  python-csrf.json         # Flask-WTF
  java-csrf.json           # Spring CSRF

internal/sast/rules/builtins/
  SC-PY-COOKIE-001..003.json (×3)
  SC-JS-COOKIE-001..003.json (×3)
  SC-JAVA-COOKIE-001..003.json (×3)
  SC-CSHARP-COOKIE-001..003.json (×3)
  SC-PY-JWT-001..003.json (×3)
  SC-JS-JWT-001..003.json (×3)
  SC-JAVA-JWT-001..003.json (×3)
  SC-CSHARP-JWT-001..003.json (×3)
  SC-JS-SESSION-001.json
  SC-JAVA-SESSION-001.json
  SC-CSHARP-SESSION-001.json
  SC-PY-SESSION-002.json
  SC-JAVA-SESSION-002.json
  SC-PY-AUTHHEADER-001.json
  SC-JS-AUTHHEADER-001.json
  SC-JAVA-AUTHHEADER-001.json
  SC-CSHARP-AUTHHEADER-001.json
  SC-JS-CSRF-001.json
  SC-PY-CSRF-001.json
  SC-JAVA-CSRF-001.json

internal/sast/fixtures/{python,javascript,java,csharp}/
  cookie_positive.{ext}   cookie_negative.{ext}
  jwt_positive.{ext}      jwt_negative.{ext}
  session_positive.{ext}  session_negative.{ext}
  authheader_positive.{ext}  authheader_negative.{ext}
  csrf_positive.{ext}     csrf_negative.{ext}    (only JS/Py/Java)
```

### Modified files

```
internal/sast/rules/schema.go             # +ArgTextContainsAny, +ArgTextMissingAny
internal/sast/engine/adapter.go           # populate ArgSourceText on Call IR
internal/sast/engine/rule_engine.go       # apply new matchers
internal/sast/rules/loader_test.go        # extend assertion lists
internal/sast/engine/models/python-stdlib.json   # auth_header_injection sink
internal/sast/engine/models/js-http.json         # auth_header_injection sink
internal/sast/engine/models/java-servlet.json    # auth_header_injection sink
internal/sast/engine/models/csharp-aspnet.json   # auth_header_injection sink
scripts/acceptance-test.sh                # adjust expected finding-count threshold
```

---

## 8. False-positive strategy

Auth/session rules historically have higher FP rates than injection rules because:

1. **Cookie config defaults vary by framework version.** Express 5 sets `httpOnly: true` by default; Express 4 does not. Our rules can't read the framework version, so they assume the worst case. Negative fixtures explicitly opt into safe defaults.
2. **Test code triggers patterns.** Test files often use `Math.random`, hardcoded JWT secrets, or `verify=False`. We mitigate by exposing rule-level path filters (already supported via the `excluded_paths` field in the engine config — verify in PR A).
3. **Session rotation is sometimes done in middleware.** A function-scope-absence rule for `request.changeSessionId()` will FP when the rotation is in upstream middleware. We document this and ship the rule at confidence `0.55` (same tier as `prototype_pollution`).

Per-rule confidence tier:

- 0.85+ — JWT alg=none, JWT verify=False, hardcoded JWT secret with framework-specific key name (clear anti-patterns)
- 0.70–0.80 — Cookie missing attributes, predictable session ID near "session" keyword
- 0.55–0.65 — Session rotation absence, CSRF unsafe-compare absence (heuristic)

Confidence is reflected in finding payload and risk-correlation cluster scoring.

---

## 9. Testing

Same fixture-driven approach as SAST rule expansion (PR #7):

- Each rule ships a `*_positive` fixture that should fire and a `*_negative` fixture that must not.
- `internal/sast/worker_test.go` already iterates all fixtures by language extension; new fixtures auto-load.
- New loader tests (`TestLoadBuiltins_AuthRulesPR`) assert each rule ID is loaded and has non-empty severity / description / remediation, mirroring `TestLoadBuiltins_NewClassesPR` and `TestLoadBuiltins_MatrixGapsPR`.
- Engine matcher gets a focused unit test (`TestArgTextContainsAny_*`) covering: literal arg, multi-line object literal, missing arg-index, no-match.

Acceptance test (`scripts/acceptance-test.sh`) raises the expected finding-count from 64 baseline by ~10 to verify at least some new rules fire on the seeded demo project. Exact threshold tuned in PR D after a real scan.

---

## 10. Risks

1. **Engine extension correctness.** Adding source-text propagation to IR is small but cross-cuts all four AST adapters. Mitigation: PR A is dedicated to this with unit tests covering every adapter path before any rule consumes the new matcher.
2. **Cookie rule cross-dialect drift.** Express vs cookie-session vs express-session vs set-cookie-parser all encode options differently. Mitigation: PR B adds one rule per attribute that supports multiple sink fully-qualified names; positive fixtures exercise every supported framework.
3. **JWT alg=none false negatives.** Some libraries accept `alg: ["none"]` as an array; arg-text matching catches both. Documented in rule descriptions.
4. **Session-rotation absence FPs.** Middleware-based rotation is the dominant pattern in real apps. This rule ships at low confidence (0.55) and includes a remediation note explaining why it may be a false positive.
5. **Production deploy cadence.** 4 PRs back-to-back means 4 controlplane image builds. Each ~3 min on the server. Total ~15 min of build time over the work session.

---

## 11. Open questions

None as of design completion. Implementation plan (writing-plans next) will pin specific rule IDs, sink-method names, and acceptance thresholds.

---

## 12. Out-of-scope follow-ups (Faz 8.5+)

These are recorded here to set expectations, not to commit to delivery:

- **Framework-aware authorization detection.** "Missing `@PreAuthorize` on Spring controller" requires building a controller-graph (annotation index → route handler list) and computing the set of un-annotated handlers. New analysis pass; estimated 2-3 day spike.
- **OAuth flow misconfiguration.** Missing `state` parameter, weak redirect_uri matching. Pattern-detectable but framework-specific (oauth-toolkit, simple-oauth2, ms-identity-web).
- **Authorization context propagation.** Detecting code that calls a privileged operation (`db.delete(user_id)`) without a preceding authz check on the same user_id. Requires inter-procedural taint with two-source flow — heavy.
- **Go language coverage.** SentinelCore's own codebase is Go. Adding net/http + gin + chi cookie/JWT/session models would let us dogfood. Reasonable next phase.
