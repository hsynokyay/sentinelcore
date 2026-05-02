# Static Coverage Expansion Sprint — Design Spec

## Goal

Expand SentinelCore SAST coverage with 4 new taint-backed rules across Java and JS/TS, using the existing engine architecture with one minimal schema extension.

## New Rules

| Rule ID | Language | Class | vuln_class | Severity | Confidence | Sinks |
|---|---|---|---|---|---|---|
| SC-JAVA-SSRF-001 | Java | SSRF (CWE-918) | `ssrf` | high | 0.80 | URL.\<init\>, URI.create, HttpGet/Post.\<init\> |
| SC-JAVA-REDIRECT-001 | Java | Open Redirect (CWE-601) | `open_redirect` | medium | 0.75 | HttpServletResponse.sendRedirect, RedirectView.\<init\> |
| SC-JS-SQL-001 | JavaScript | SQL Injection (CWE-89) | `sql_injection` | critical | 0.85 | mysql.query, mysql2.query, pg.query (arg_count_exact:1) |
| SC-JS-SSRF-001 | JavaScript | SSRF (CWE-918) | `ssrf` | high | 0.75 | http/https .get/.request, axios .get/.post/.request |

### Canonical vuln_class strings

New: `ssrf`, `open_redirect`. Existing (unchanged): `sql_injection`, `command_injection`, `path_traversal`, `weak_crypto`, `hardcoded_secret`, `xss`, `unsafe_eval`.

## Engine Extension

Add `ArgCountExact *int` to `TaintModel`. When set, a sink only matches if the call's operand count equals that value. This lets `query(sql)` fire while `query(sql, [params])` does not.

- Field: `arg_count_exact` (optional int, JSON omitempty)
- Location: `internal/sast/engine/models.go` TaintModel struct
- Impact on existing rules: zero (field omitted = check skipped)

### IsSink API change

The current `IsSink(calleeFQN) → (bool, string)` discards the full model, so the caller can't inspect `ArgCountExact`. The implementation will change `IsSink` to also return the matching models slice:

```go
func (ms *ModelSet) IsSink(calleeFQN string) (bool, string, []TaintModel)
```

The sink matching in `handleCall` will then iterate the returned models and check `ArgCountExact` against `len(inst.Operands)`. If `ArgCountExact` is nil, the check is skipped (backward-compatible).

**Realistic LOC estimate**: ~20 LOC (1 struct field + IsSink return-type change + 2 caller updates + arg-count check + test).

## Sources (all reuse existing models)

- Java: `HttpServletRequest.getParameter/getHeader/getCookies/getQueryString`
- JS: `req.query`, `req.body`, `req.params`

## New Model Packs

### java-net.json (ssrf sinks)
- `java.net.URL.<init>` vuln_class:`ssrf` arg_index:0
- `java.net.URI.create` vuln_class:`ssrf` arg_index:0
- `org.apache.http.client.methods.HttpGet.<init>` vuln_class:`ssrf` arg_index:0
- `org.apache.http.client.methods.HttpPost.<init>` vuln_class:`ssrf` arg_index:0

### java-redirect.json (open_redirect sinks)
- `javax.servlet.http.HttpServletResponse.sendRedirect` vuln_class:`open_redirect` arg_index:0
- `org.springframework.web.servlet.view.RedirectView.<init>` vuln_class:`open_redirect` arg_index:0

### js-sql.json (sql_injection sinks)
- `mysql.query` vuln_class:`sql_injection` arg_count_exact:1
- `mysql2.query` vuln_class:`sql_injection` arg_count_exact:1
- `pg.query` vuln_class:`sql_injection` arg_count_exact:1

Note: `arg_index` is intentionally omitted for JS sinks. JS taint tracking propagates through any operand position. The `arg_count_exact` field is the precision mechanism for JS SQL injection (not `arg_index`).

### js-http.json (ssrf sinks)
- `http.get`, `http.request` vuln_class:`ssrf`
- `https.get`, `https.request` vuln_class:`ssrf`
- `axios.get`, `axios.post`, `axios.request` vuln_class:`ssrf`

Note: `arg_index` omitted for JS SSRF sinks. For `axios.post(url, data)`, a tainted `data` argument with a hardcoded `url` is an acceptable FP for MVP — the remediation guides URL validation regardless.

### Model pack strategy

JS model packs are split into separate files per domain (`js-sql.json`, `js-http.json`) rather than consolidated into `js-node.json`. This matches the Java pattern where each domain has its own file and keeps each pack focused and reviewable.

## Rule File Names

Using the ID-based convention (matching newer JS rules):

```
internal/sast/rules/builtins/SC-JAVA-SSRF-001.json
internal/sast/rules/builtins/SC-JAVA-REDIRECT-001.json
internal/sast/rules/builtins/SC-JS-SQL-001.json
internal/sast/rules/builtins/SC-JS-SSRF-001.json
```

## Remediation Packs (4 new)

```
internal/remediation/packs/SC-JAVA-SSRF-001.json
internal/remediation/packs/SC-JAVA-REDIRECT-001.json
internal/remediation/packs/SC-JS-SQL-001.json
internal/remediation/packs/SC-JS-SSRF-001.json
```

Each with: title, summary, why_it_matters, how_to_fix, unsafe_example, safe_example, developer_notes, verification_checklist (4-6 items), references (3-4 CWE/OWASP links).

## Benchmark Cases (9 new, total 30)

| ID | File | Class | Expect | Rule |
|---|---|---|---|---|
| SSRF-P-001 | ssrf/positive/BenchSsrf001.java | ssrf | positive | SC-JAVA-SSRF-001 |
| SSRF-P-002 | ssrf/positive/BenchSsrf002.java | ssrf | positive | SC-JAVA-SSRF-001 |
| SSRF-N-001 | ssrf/negative/BenchSsrfSafe001.java | ssrf | negative | SC-JAVA-SSRF-001 |
| REDIR-P-001 | redirect/positive/BenchRedirect001.java | open_redirect | positive | SC-JAVA-REDIRECT-001 |
| REDIR-N-001 | redirect/negative/BenchRedirectSafe001.java | open_redirect | negative | SC-JAVA-REDIRECT-001 |
| JSSQLI-P-001 | jssqli/positive/BenchJsSqli001.js | sql_injection | positive | SC-JS-SQL-001 |
| JSSQLI-N-001 | jssqli/negative/BenchJsSqliSafe001.js | sql_injection | negative | SC-JS-SQL-001 |
| JSSSRF-P-001 | jsssrf/positive/BenchJsSsrf001.js | ssrf | positive | SC-JS-SSRF-001 |
| JSSSRF-N-001 | jsssrf/negative/BenchJsSsrfSafe001.js | ssrf | negative | SC-JS-SSRF-001 |

Manifest description updated to: "30 cases across 7 vulnerability classes" (JS SQL injection reuses the existing `sql_injection` class string). Scorecard banner updated from "Java SAST" to "SAST" to reflect multi-language coverage.

### Benchmark runner JS support

The benchmark runner (`internal/sast/bench/bench.go`) currently only imports the Java frontend. **Chunk 1 must extend it** to detect `.js`/`.ts` files by extension and dispatch to the JS frontend parser. This is ~15 LOC: import `js` package, check `filepath.Ext`, call `js.ParseFile` for JS extensions and `java.ParseFile` for Java.

The scorecard's `PrintScorecard` order slice must also be extended to include `ssrf` and `open_redirect`.

## Implementation Chunks

### Chunk 1: Engine schema extension + benchmark runner
- Add `ArgCountExact *int` to TaintModel struct
- Change `IsSink` to return `(bool, string, []TaintModel)`
- Update 2 callers in `taint_engine.go` to use new return type
- Add arg-count check in handleCall sink path
- Extend benchmark runner for JS file parsing
- Extend scorecard order slice for new classes
- Unit test: sink with `arg_count_exact:1` matches 1-arg, rejects 2-arg
- Full regression pass

### Chunk 2: Java SSRF + Open Redirect
- Model packs: `java-net.json` + `java-redirect.json`
- Rules: `SC-JAVA-SSRF-001.json` + `SC-JAVA-REDIRECT-001.json`
- Remediation packs: both
- Test fixtures: 2 Java files per rule (vuln + safe)
- Benchmark cases: 5 new manifest entries
- E2E tests: parse real Java → engine → finding with trace

### Chunk 3: JS SQL Injection + SSRF
- Model packs: `js-sql.json` + `js-http.json`
- Rules: `SC-JS-SQL-001.json` + `SC-JS-SSRF-001.json`
- Remediation packs: both
- Test fixtures: 2 JS files per rule (vuln + safe)
- **Mandatory**: `query(sql, [params])` negative test must pass
- Benchmark cases: 4 new manifest entries
- E2E tests: parse real JS → engine → finding

### Chunk 4: Deploy + live verification
- Rebuild + deploy controlplane + sast-worker
- Upload Java + JS test artifacts
- Verify all 4 new rules fire live
- Verify safe cases produce zero findings
- Verify exports (MD + SARIF) include new rules
- Run benchmark, produce before/after scorecard delta
- Verify metrics increment correctly

## Constraints

- No new languages
- No ORM coverage (Sequelize, Knex, Prisma, TypeORM)
- No `connection.query`/`pool.query` (low type confidence)
- No `fetch`/`got`/`node-fetch` SSRF sinks (wave 2)
- No `setHeader("Location")` for open redirect
- `HttpURLConnection.openConnection` deferred (secondary sink)
- Sanitizer models deferred — SSRF and open redirect sanitization is allowlist-based, not modelable as a single function call. Follow-up item for custom sanitizer declaration.

## Risk Areas

| Risk | Mitigation |
|---|---|
| JS SQLi FP on parameterized queries | `arg_count_exact:1` — mandatory negative test; hard gate |
| Java SSRF FP on allowlist-validated URLs | Accept for MVP — remediation guides allowlist |
| JS SSRF FP on intentional outbound calls | confidence 0.75 (medium), remediation guides URL validation |
| Open redirect FP on relative-path redirects | Taint requires user-controlled input — hardcoded paths won't taint |
| `IsSink` API change cascading | Only 2 callers in taint_engine.go; sanitizer check unaffected |

## Hard Gate

JS SQLi must NOT ship if `query(sql, [params])` negative test fails.
