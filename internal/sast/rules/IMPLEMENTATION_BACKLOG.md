# SAST Rule Library — Implementation Backlog

> Reference: `docs/superpowers/specs/2026-05-02-fortify-parity-design.md` (TBD —
> design doc lives in chat for now). This backlog is the operational source
> of truth for "which rules ship in which faz".

**Inputs:**

- `~/Downloads/fortify_full_rules.csv` — 499 rule slots across 20 categories
  (synthetic — used only as **rule budget** per category, not literal names)
- Existing builtins: 36 rules across SQL/CMD/Path/SSRF/XSS/Crypto/Deser/Secret/
  Log/Redirect — see `LoadBuiltins`

**Targets after all fazes ship:** ~475 new rules added on top of the 36 existing.

---

## Status legend

- `[ ]` not started
- `[~]` in progress
- `[x]` done

---

## Epic 1 — Schema v2 + engine extensibility (FAZ 1) ✅

**Why:** every later faz needs a stable rule shape; FP reduction needs
`confidence.modifiers`; FAZ 12 taint engine needs `taint{sources/propagators/
sanitizers/sinks}`.

- [x] Story 1.1 — Rule schema v2 fields (additive)
  - [x] `schema_version`, `category`, `languages[]`, `tags[]`
  - [x] `confidence.modifiers[]`
  - [x] `detection.taint{...}` with five TaintNode kinds
  - **AC:** `go test ./internal/sast/rules/...` passes
  - **AC:** existing 36 rules still load + validate
- [x] Story 1.2 — v1→v2 in-memory migrator
  - [x] `MigrateInPlace` adds defaults; idempotent; normalizes `js→javascript`
  - [x] Category inference from `rule_id` token
  - **AC:** `TestBuiltinsAllHaveCategoryAfterMigration` passes
- [x] Story 1.3 — Validator CLI for CI gating
  - [x] `cmd/sast-rules-validate` — exit 0 / 1 with per-rule error report
  - **AC:** runs against `internal/sast/rules/builtins`, reports 36 OK
- [x] Story 1.4 — One-shot disk upgrader
  - [x] `cmd/sast-rules-upgrade` — rewrites JSON to canonical v2 shape, idempotent
  - **AC:** all 36 builtins on disk are v2-native (`schema_version: 2`, `category`, `languages[]`)
- [x] Story 1.5 — This backlog

---

## Epic 2 — Secrets & hardcoded credentials (FAZ 2)

**Budget:** 27 Credentials rules (existing: 4 → add 23).
**Detection mix:** mostly `ast_assign` regex+entropy; 3-4 `ast_call` for known
SDK constructors (e.g. `BasicAWSCredentials("…","…")`).
**Languages:** Java, JS/TS, Python, C#.

- [ ] Story 2.1 — Secret matcher entropy tuning
  - [ ] Add Shannon-entropy threshold knob to `internal/sast/engine/secret_matcher.go`
  - [ ] Add deny-list of common test fixtures (`changeme`, `test1234`, `Passw0rd!`)
  - **AC:** false positive rate on `internal/sast/fixtures/safe/*` stays ≤ 1
- [ ] Story 2.2 — Cloud key formats (AWS / GCP / Azure)
  - [ ] `SC-COMMON-SECRET-AWS-ACCESS-KEY-001` — AKIA[A-Z0-9]{16}
  - [ ] `SC-COMMON-SECRET-AWS-SECRET-001` — 40-char base64-ish next to `aws_secret_access_key`
  - [ ] `SC-COMMON-SECRET-GCP-001` — `private_key_id` + `BEGIN PRIVATE KEY`
  - [ ] `SC-COMMON-SECRET-AZURE-CONNSTR-001` — `DefaultEndpointsProtocol=...AccountKey=...`
  - **AC:** unit test `tests/sast/secrets/cloud-keys.json` produces 4 findings on positive fixture
- [ ] Story 2.3 — Provider tokens (GitHub / Slack / Stripe / OpenAI)
  - [ ] `SC-COMMON-SECRET-GITHUB-001` — `gh[ps]_[A-Za-z0-9]{36,}`
  - [ ] `SC-COMMON-SECRET-SLACK-001` — `xox[abp]-[0-9A-Za-z-]+`
  - [ ] `SC-COMMON-SECRET-STRIPE-001` — `sk_live_[0-9A-Za-z]{24,}`
  - [ ] `SC-COMMON-SECRET-OPENAI-001` — `sk-proj-[A-Za-z0-9_-]{30,}`
  - **AC:** each rule has positive + negative test
- [ ] Story 2.4 — Generic credential context
  - [ ] Per-language `SC-<LANG>-SECRET-PASSWORD-001` already exists; extend to also
    catch `connectionString`, `db_url`, `bearerToken`, `clientSecret`
  - [ ] `SC-COMMON-SECRET-PRIVATE-KEY-001` — `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`
  - **AC:** OWASP A07 mapping
- [ ] Story 2.5 — Connection-string heuristics (4 langs)
  - [ ] Java: `DriverManager.getConnection("jdbc:…?password=…")`
  - [ ] Python: `psycopg2.connect("host=… password=…")`, `pymongo.MongoClient("mongodb://u:p@…")`
  - [ ] JS: `mongoose.connect("mongodb+srv://u:p@…")`
  - [ ] C#: `new SqlConnection("…Password=…")`
  - **AC:** detection works for both call-arg and assigned-variable forms

**Faz 2 done when:** 27+ secret rules live, FP rate on `internal/sast/fixtures/safe/`
≤ 2/100 LOC, validator CLI gates secret PRs.

---

## Epic 3 — Injection (FAZ 3)

**Budget:** 29 Injection + 29 Validation = 58. Existing: 8 → add 50.
**Detection mix:** taint v2 (sources from framework_param + api, sinks from
api list, sanitizers from prepared-statement / query-builder API).
**Per-language sink models** already present in `internal/sast/engine/models/`
— extend, don't re-build.

- [ ] Story 3.1 — SQLi expansion
  - [ ] Java JPA / Hibernate / MyBatis sinks
  - [ ] Python SQLAlchemy raw `execute(text(...))`, asyncpg `fetch(query)`
  - [ ] JS Sequelize `query()`, knex raw, Prisma `$queryRaw`
  - [ ] C# Dapper `Execute(query, ...)`, EF `FromSqlRaw`
- [ ] Story 3.2 — Command injection expansion
  - [ ] Java: `ProcessBuilder` + `Runtime.exec(String)` (single-string form is the dangerous one)
  - [ ] Python: `os.system`, `subprocess.run(shell=True)`, `commands.getoutput`
  - [ ] JS: `child_process.exec` (vs `execFile`), `spawn` with `shell: true`
  - [ ] C#: `Process.Start(ProcessStartInfo{UseShellExecute=true})`
- [ ] Story 3.3 — LDAP / XPath / NoSQL injection
  - [ ] Java: `DirContext.search(filter)`, `XPath.compile(expr)`
  - [ ] Python: `ldap3.search`, `lxml etree.XPath(expr)`
  - [ ] JS: `mongoose.find({ $where: q })`, `mongodb db.collection.find()` operator injection
  - [ ] C#: `DirectorySearcher.Filter`
- [ ] Story 3.4 — Template / Expression-Language injection
  - [ ] Java: Velocity `Velocity.evaluate`, FreeMarker `Template.process`
  - [ ] Python: Jinja2 `render_template_string` (already plan'd above)
  - [ ] JS: Handlebars `compile` from user input, EJS render with user template
  - [ ] C#: Razor `RazorEngine.Razor.Parse` from user input

**Faz 3 done when:** 50+ injection rules, taint engine recognises 4-language sink models, FP rate ≤ 3/100 LOC on safe fixtures.

---

## Epic 4 — XSS (FAZ 4)

**Budget:** 21 XSS rules. Existing: 1.
**Detection mix:** taint, with framework awareness (React/Vue/Angular).

- [ ] Story 4.1 — Server-side reflected/stored XSS
  - [ ] Java: JSP `<%= req.getParameter() %>`, Spring `@ResponseBody String` of user input
  - [ ] Python: Flask `make_response`, Django `mark_safe(user_input)`
  - [ ] JS Express: `res.send(html_with_user_input)`
- [ ] Story 4.2 — DOM XSS (browser sinks)
  - [ ] JS/TS: `element.innerHTML = userInput`, `document.write(userInput)`, `eval(userInput)`
- [ ] Story 4.3 — Framework-specific
  - [ ] React: `dangerouslySetInnerHTML` with non-sanitized value
  - [ ] Vue: `v-html` directive with user input
  - [ ] Angular: `bypassSecurityTrustHtml` calls

---

## Epic 5 — Path / file / resource manipulation (FAZ 5)

**Budget:** 26 Path rules. Existing: 4.

- [ ] Story 5.1 — Path traversal expansion (4 langs)
- [ ] Story 5.2 — Zip slip
  - [ ] Java: `ZipInputStream.getNextEntry().getName()` written without normalization
  - [ ] Python: `zipfile.extractall` without `members` filter
  - [ ] JS: `unzipper.Open.file` extract without path check
  - [ ] C#: `ZipArchive.Entries[i].FullName` extract without path check
- [ ] Story 5.3 — Unsafe file upload (no MIME / extension check)
- [ ] Story 5.4 — Arbitrary file write (template path from request)

---

## Epic 6 — SSRF / XXE / Network (FAZ 6)

**Budget:** 30 SSRF + 33 Redirect + 18 XML = 81. Existing: 5.

- [ ] Story 6.1 — SSRF expansion (4 langs HTTP clients)
- [ ] Story 6.2 — XXE expansion
  - [ ] Java: SAXParserFactory, XMLInputFactory, XMLReader without disabled DTD
  - [ ] Python: `lxml.etree.parse` with `resolve_entities=True`, `xml.sax.make_parser` defaults
  - [ ] C#: XmlDocument/XmlReader with default settings
- [ ] Story 6.3 — Open redirect expansion
- [ ] Story 6.4 — Insecure TLS validation
  - [ ] Java: `TrustManager` that returns true unconditionally
  - [ ] Python: `requests.get(url, verify=False)`, `urllib3.disable_warnings`
  - [ ] JS: `https.Agent({ rejectUnauthorized: false })`
  - [ ] C#: `ServicePointManager.ServerCertificateValidationCallback = (s,c,ch,e) => true`
- [ ] Story 6.5 — Host header injection (response.redirect with host from header)

---

## Epic 7 — Crypto / Randomness (FAZ 7)

**Budget:** 29 Crypto + 20 Randomness = 49. Existing: 2.

- [ ] Story 7.1 — Weak hash expansion (4 langs)
- [ ] Story 7.2 — Weak ciphers
  - [ ] Java: `Cipher.getInstance("DES"|"RC4"|"AES/ECB/...")`
  - [ ] Python: PyCrypto/PyCryptodome `DES.new`, `ARC4.new`, `AES.new(... MODE_ECB)`
  - [ ] JS: `crypto.createCipheriv("des-cbc", ...)`, `aes-128-ecb`
  - [ ] C#: `DESCryptoServiceProvider`, `RC2CryptoServiceProvider`, `Aes { Mode = CipherMode.ECB }`
- [ ] Story 7.3 — Hardcoded crypto key (overlap with FAZ 2 — share matcher)
- [ ] Story 7.4 — Insecure randomness
  - [ ] Java: `Math.random()` in security context, `new Random()` for token gen
  - [ ] Python: `random.choice(token_chars)` (vs `secrets.choice`)
  - [ ] JS: `Math.random()` for token gen
  - [ ] C#: `new Random()` for token / nonce
- [ ] Story 7.5 — Weak TLS protocol pin
  - [ ] Java: `SSLContext.getInstance("TLS")` (versionless), `"SSLv3"`, `"TLSv1"`, `"TLSv1.1"`
  - [ ] Python: `ssl.PROTOCOL_SSLv3`, `PROTOCOL_TLSv1`
  - [ ] C#: `SslProtocols.Tls`, `Ssl3`

---

## Epic 8 — Auth / Authz / Session / CSRF (FAZ 8)

**Budget:** 39 Auth + 20 Authz + 20 Session + 23 CSRF = 102. Existing: 0.
**Detection mix:** semantic / framework-aware. Many of these are
"missing X" patterns rather than "presence of bad call" — needs the
semantic matcher kind (introduce in FAZ 12 if simpler).

- [ ] Story 8.1 — Missing authorization
  - [ ] Spring: `@RestController` method without `@PreAuthorize` / `@Secured` / `@RolesAllowed`
  - [ ] ASP.NET Core: `[ApiController]` action without `[Authorize]`
  - [ ] Express: route handler without `authMiddleware` upstream
  - [ ] Flask: route without `@login_required` or equivalent decorator
- [ ] Story 8.2 — JWT validation issues
  - [ ] `jwt.decode(token, verify=False)` (Python pyjwt)
  - [ ] `jsonwebtoken.verify(token, null)` (JS)
  - [ ] `Jwts.parser().setSigningKey(null)` (Java)
- [ ] Story 8.3 — Session fixation / weak session id
- [ ] Story 8.4 — Cookie flags (Secure, HttpOnly, SameSite) — overlap with DAST passive checks
- [ ] Story 8.5 — CSRF protection missing
  - [ ] Spring: form POST handler without `@CsrfProtection` (or `csrf().disable()` in security config)
  - [ ] Django: `@csrf_exempt`
  - [ ] Express: app without `csurf` middleware

---

## Epic 9 — Deserialization & dynamic loading (FAZ 9)

**Budget:** 21 Serialization rules. Existing: 3.

- [ ] Story 9.1 — Java: Jackson polymorphic deser, SnakeYAML, XStream
- [ ] Story 9.2 — Python: pickle (already), `marshal`, `shelve`, `dill`
- [ ] Story 9.3 — JS: `JSON.parse(reviver)` with eval-style reviver, `node-serialize`
- [ ] Story 9.4 — C#: `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`
- [ ] Story 9.5 — Dynamic code loading: Java `Class.forName(name)` + `newInstance` from request, .NET `Activator.CreateInstance(Type.GetType(s))`

---

## Epic 10 — Logging / Privacy / Error handling (FAZ 10)

**Budget:** 23 Logging + 17 Privacy + 28 Error Handling = 68. Existing: 1.

- [ ] Story 10.1 — Log forging (CRLF in logged user input)
- [ ] Story 10.2 — Sensitive data in logs
  - [ ] User input flowing into `logger.info` / `console.log` / `print` / `Trace.Write` without masking
  - [ ] Variable name heuristics (any `password` / `token` / `ssn` / `tcKimlik` / `iban` near a logger call)
- [ ] Story 10.3 — Stack trace exposure to user
  - [ ] Spring: `@ExceptionHandler` returning `e.getStackTrace()` in response
  - [ ] Flask: `app.run(debug=True)` in production code
  - [ ] Express: `err.stack` in response body
  - [ ] ASP.NET: `customErrors mode="Off"`, `developerExceptionPage` in production
- [ ] Story 10.4 — Local PII matchers (Turkey-specific bonus)
  - [ ] TC Kimlik (11-digit checksum)
  - [ ] IBAN (`TR\d{24}` checksum)
  - [ ] Phone numbers (`+90 5\d\d ...`)
- [ ] Story 10.5 — Generic information leakage (server version, full file paths in errors)

---

## Epic 11 — Memory / Concurrency (FAZ 11)

**Budget:** 23 Memory + 24 Concurrency = 47. Existing: 0.

- [ ] Story 11.1 — Java: thread-safety on shared mutable state, `SimpleDateFormat` shared
- [ ] Story 11.2 — Python: GIL-ignorant assumptions, `pickle` in multiprocessing without auth
- [ ] Story 11.3 — JS: race condition in async/await + shared state
- [ ] Story 11.4 — C#: locking on `this` / `typeof`, double-checked locking without volatile
- [ ] Story 11.5 — Common: TOCTOU on file existence checks (`if File.Exists then File.Open` patterns)

---

## Epic 12 — Engine: inter-procedural taint, sanitizer model, FP reduction (FAZ 12)

- [ ] Story 12.1 — Sanitizer model wired into taint engine
  - [ ] Engine reads `taint.sanitizers[]` and prunes paths that pass through one
  - **AC:** sanitized SQLi fixture stops producing finding without losing positive cases
- [ ] Story 12.2 — Confidence-modifier evaluation at finding time
  - [ ] Engine evaluates each `confidence.modifiers[i].if` against the matched context and applies delta
  - [ ] Standard conditions: `sanitizer_present`, `source_is_user_input`, `source_is_constant`, `in_test_path`, `short_path`
- [ ] Story 12.3 — Framework-aware source detection
  - [ ] Spring `@RequestParam`/`@PathVariable`/`@RequestBody` recognised as taint source
  - [ ] ASP.NET `[FromBody]`/`[FromQuery]`/`[FromRoute]` recognised
  - [ ] Flask/Django request objects recognised
  - [ ] Express middleware/req params recognised
- [ ] Story 12.4 — Suppress / baseline file
  - [ ] `.sentinel/baseline.json` records accepted findings; engine omits them on next scan
- [ ] Story 12.5 — Triage round-trip
  - [ ] When operator marks finding as `false_positive`, automatically add a `path_filter` to a project-level rule overlay

---

## Epic 13 — Reporting (FAZ 13)

- [ ] Story 13.1 — SARIF 2.1.0 export per scan
- [ ] Story 13.2 — HTML interactive report (Fortify-style flow trace)
- [ ] Story 13.3 — Per-finding markdown export (already have for DAST — reuse)

---

## Working agreement for each rule PR

Every new rule PR MUST include:

1. The rule JSON (canonical v2 shape — `schema_version: 2`, `category`, `languages[]`, full description + remediation + references)
2. **Positive fixture** under `internal/sast/fixtures/<lang>/<category>/positive_<rule_id>.<ext>` — engine MUST flag it
3. **Negative fixture** under `internal/sast/fixtures/<lang>/<category>/negative_<rule_id>.<ext>` — engine MUST NOT flag it
4. **Sanitized-positive fixture** when applicable — same dangerous pattern but with the documented sanitizer applied; engine MUST NOT flag it (validates the sanitizer model)
5. Test in `internal/sast/frontend/<lang>/frontend_test.go` (or new `<rule_id>_test.go`) that asserts the right findings come out
6. `cmd/sast-rules-validate internal/sast/rules/builtins` exits 0
7. CI job runs the validator + the fixture tests
