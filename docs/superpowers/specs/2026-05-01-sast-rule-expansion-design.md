# SAST Rule Expansion — Design Spec

**Status:** Design complete, awaiting implementation plan
**Owner:** Huseyin
**Target:** `internal/sast/` — add 28 new SAST rules + 5 new vulnerability classes to the taint engine, with fixtures and tests
**Date:** 2026-05-01

---

## 1. Goals & non-goals

### Goals

- Expand SAST coverage from ~30 rules to ~58 rules.
- Add five **new vulnerability classes** the taint engine doesn't yet recognize: `ssti`, `nosql_injection`, `prototype_pollution`, `mass_assignment`, `http_header_injection`.
- Fill gaps in the existing **language × class matrix**: cover XSS, log injection, XXE, weak crypto, and unsafe eval where missing in Python, Java, JavaScript, and C#.
- Each new rule ships with a positive + negative fixture so detection is verifiable, not aspirational.

### Non-goals

- No changes to the engine's IR, taint propagation algorithm, or analyzer pipeline. Only data (sink/source/sanitizer JSON) is added.
- No new languages. Coverage stays Python, JavaScript, Java, C#.
- No DAST rules. DAST rule_ids are tracked separately under migration `021_dast_rule_ids`.
- No DB migration. `findings.findings.rule_id` is already `TEXT` and `vuln_class` is opaque — new enum values are accepted without schema changes.

---

## 2. Background & current state

The SAST stack has two rule layers:

1. **Structured taint rules:** `internal/sast/rules/builtins/SC-<LANG>-<CLASS>-NNN.json` (~30 files). Each rule references a `vuln_class` (e.g. `sql_injection`) which the engine uses to match against sink declarations in `internal/sast/engine/models/<lang>-<framework>.json`.
2. **Legacy regex patterns:** `rules/builtin/sast-patterns.json` (~21 patterns). Out of scope for this spec.

Current matrix (structured rules):

| Lang | Classes covered |
|------|------------------|
| C# | CMD, DESER, PATH, SECRET, SQL, SSRF (6) |
| Java | DESER, LOG, REDIRECT, SSRF, XXE (5) |
| JS | CMD, CRYPTO, EVAL, PATH, REDIRECT, SECRET, SQL, SSRF×2, XSS (10) |
| Python | CMD, CRYPTO, DESER, EVAL, PATH, REDIRECT, SECRET, SQL, SSRF (9) |

Engine code in `internal/sast/engine/` reads `vuln_class` as an opaque string field. Adding new values to sink JSON files automatically propagates them through the pipeline; the only consumers that distinguish classes are reporting/UI, which already render generic severity-tinted findings.

---

## 3. New vulnerability classes (5)

Each new class adds:
- A `vuln_class` value to one or more sink declarations in `engine/models/`
- One or more rule JSON files in `rules/builtins/`
- A positive + negative fixture in `internal/sast/fixtures/`

### 3.1 `ssti` — Server-side template injection (CWE-1336)

User input flows into a template render call that interprets template syntax.

| Lang | Sink shape | New model file |
|------|------------|----------------|
| Python | `flask.render_template_string`, `jinja2.Template().render` | `python-templating.json` |
| JS | `handlebars.compile`, `ejs.render` | `js-templating.json` |
| Java | `org.apache.velocity.app.VelocityEngine.evaluate` | `java-templating.json` |
| C# | `RazorEngine.Engine.Razor.RunCompile` | `csharp-razor.json` |

### 3.2 `nosql_injection` — NoSQL injection (CWE-943)

User input flows into a MongoDB/Redis query method without parameter coercion.

| Lang | Sink shape | New model file |
|------|------------|----------------|
| Python | `pymongo.collection.Collection.find/find_one/update_one` w/ dict containing user input | `python-mongo.json` |
| JS | `mongoose.Model.find`, `mongoose.Model.where`, native MongoDB driver `collection.find` | `js-mongoose.json` |

### 3.3 `prototype_pollution` — Prototype pollution (CWE-1321)

JS-only. Recursive merge / object assignment receives a user-controlled key path that includes `__proto__` / `constructor` / `prototype`.

Sinks added to existing `js-node.json`:
- `Object.assign` (when target is `{}` and source is user-controlled)
- `lodash.merge` / `lodash.defaultsDeep` / `lodash.set`
- Hand-rolled deep-merge functions matching the recursive-assignment shape (heuristic: function with parameter named `target`/`dest`/`out` that loops over source keys)

Detection initially uses a **regex-pattern fallback** (the recursive-key-walk shape doesn't fit the standard taint paradigm). A future PR can upgrade this to a dedicated analyzer pass.

### 3.4 `mass_assignment` — Mass assignment (CWE-915)

Request-body object passed wholesale into a model constructor / ORM `create`.

| Lang | Sink shape | Existing model file |
|------|------------|---------------------|
| JS | `Model.create(req.body)`, `Object.assign(model, req.body)` | `js-http.json` (extend) |
| Python | `Django.Model(**request.POST)`, `Model(**request.GET)` | `python-stdlib.json` (extend) |

### 3.5 `http_header_injection` — Response header injection (CWE-113)

User input concatenated into HTTP response header value, where `\r\n` would split the response.

| Lang | Sink shape | Existing model file |
|------|------------|---------------------|
| Python | `flask.Response(headers=...)`, `django.http.HttpResponse(...)['Header'] = userInput` | `python-stdlib.json` (extend) |
| JS | `res.setHeader(name, userInput)`, `res.header(name, userInput)` | `js-http.json` (extend) |
| Java | `HttpServletResponse.addHeader(name, userInput)`, `setHeader(name, userInput)` | `java-servlet.json` (extend) |

---

## 4. Matrix gap fills (13 rules across existing classes)

These rules add coverage for vuln_classes the engine already supports but that aren't represented in some languages.

### 4.1 XSS (3 new rules)

| Rule ID | Lang | Sink |
|---------|------|------|
| `SC-PY-XSS-001` | Python | `flask.Markup(user)`, `django.utils.safestring.mark_safe(user)` |
| `SC-JAVA-XSS-001` | Java | `HttpServletResponse.getWriter().println(req.getParameter(...))` |
| `SC-CSHARP-XSS-001` | C# | Razor `@Html.Raw(input)`, `@:input` raw output |

### 4.2 Log injection (3 new rules)

| Rule ID | Lang | Sink |
|---------|------|------|
| `SC-PY-LOG-001` | Python | `logging.Logger.info/warning/error(userInput)` no sanitize |
| `SC-JS-LOG-001` | JS | `winston.log(userInput)`, `console.log(userInput)` w/ `\n` |
| `SC-CSHARP-LOG-001` | C# | `ILogger.LogInformation(userInput)` no template params |

### 4.3 XXE (3 new rules)

| Rule ID | Lang | Sink |
|---------|------|------|
| `SC-PY-XXE-001` | Python | `lxml.etree.parse(file, parser=XMLParser(no_network=False, resolve_entities=True))` |
| `SC-JS-XXE-001` | JS | `xml2js.parseString(input, { explicitRoot: true, ... })` w/ external entity defaults |
| `SC-CSHARP-XXE-001` | C# | `XmlDocument.Load(input)` with default `XmlResolver` |

### 4.4 Weak crypto (2 new rules)

| Rule ID | Lang | Sink |
|---------|------|------|
| `SC-JAVA-CRYPTO-001` | Java | `MessageDigest.getInstance("MD5"\|"SHA-1")` |
| `SC-CSHARP-CRYPTO-001` | C# | `MD5.Create()`, `SHA1.Create()` |

### 4.5 Unsafe eval (2 new rules)

| Rule ID | Lang | Sink |
|---------|------|------|
| `SC-JAVA-EVAL-001` | Java | `ScriptEngine.eval(userInput)` |
| `SC-CSHARP-EVAL-001` | C# | `Microsoft.CSharp.CSharpCodeProvider.CompileAssemblyFromSource(userInput)` |

---

## 5. Rule file schema

Existing schema (do not change):

```json
{
  "rule_id": "SC-PY-SSTI-001",
  "name": "Server-side template injection via render_template_string",
  "language": "python",
  "cwe": ["CWE-1336"],
  "owasp": ["A03:2021"],
  "severity": "critical",
  "confidence": { "base": 0.85 },
  "detection": { "kind": "taint", "vuln_class": "ssti" },
  "description": "User input flows into a Jinja2 template string at render time, allowing template-syntax injection.",
  "remediation": "Use `render_template` with a fixed template file and pass user data as context variables.",
  "references": [
    "https://cwe.mitre.org/data/definitions/1336.html",
    "https://owasp.org/Top10/A03_2021-Injection/"
  ]
}
```

For `prototype_pollution` rules, `detection.kind` is `pattern` (regex) instead of `taint`:

```json
{
  "detection": {
    "kind": "pattern",
    "regex": "(?i)(Object\\.assign|_\\.merge|_\\.defaultsDeep)\\s*\\([^)]*req\\.(body|query|params)"
  }
}
```

The loader (`internal/sast/rules/loader.go`) already handles both `taint` and `pattern` kinds.

---

## 6. Engine sink JSON schema

Existing format used in every `models/*.json`:

```json
{
  "kind": "sink",
  "receiver_fqn": "flask",
  "method": "render_template_string",
  "vuln_class": "ssti",
  "args": [0]
}
```

For new framework files (`python-templating.json`, etc.), the file is a plain JSON array of these declarations. The engine auto-loads any file matching `models/<lang>-*.json`.

---

## 7. Fixtures

Each new rule gets two fixtures in `internal/sast/fixtures/<lang>/`:
- `<rule>_positive.<ext>` — minimal code that should trigger the rule
- `<rule>_negative.<ext>` — equivalent code with sanitization / safe variant

Example for `SC-PY-SSTI-001`:

```python
# ssti_positive.py
from flask import render_template_string, request
def view():
    name = request.args.get("name")
    return render_template_string("Hello " + name)  # vulnerable

# ssti_negative.py
from flask import render_template, request
def view():
    name = request.args.get("name")
    return render_template("hello.html", name=name)  # safe
```

`internal/sast/worker_test.go` already iterates fixtures; new fixtures are picked up automatically.

---

## 8. Testing

### 8.1 Loader unit tests

Extend `internal/sast/rules/loader_test.go` with a table driven case asserting all 28 new rule IDs load with required metadata fields populated:

```go
var newRules = []string{
  "SC-PY-SSTI-001", "SC-JS-SSTI-001", /* ...28 entries */
}
for _, id := range newRules {
  t.Run(id, func(t *testing.T) {
    rule, ok := loaded[id]
    require.True(t, ok, "rule %s missing", id)
    require.NotEmpty(t, rule.Severity)
    require.NotEmpty(t, rule.Detection.VulnClass)
    // ...etc
  })
}
```

### 8.2 Fixture-driven detection tests

`internal/sast/worker_test.go` already runs each fixture against the analyzer and asserts findings. New fixtures are exercised automatically. Verify each positive fixture produces ≥ 1 finding with the expected `rule_id` and `vuln_class`, and each negative fixture produces 0 findings of that rule_id.

### 8.3 Acceptance test

`scripts/acceptance-test.sh` runs the seeded demo project through SAST and checks finding count. After this PR, expected finding count increases. Update the threshold (or convert it to a "≥ N" check) in the acceptance script.

---

## 9. Implementation strategy — 3 PRs

| PR | Scope | Estimate |
|----|-------|----------|
| **A — Engine sinks** | Add new model files (`python-templating.json`, `js-templating.json`, `java-templating.json`, `csharp-razor.json`, `python-mongo.json`, `js-mongoose.json`) + extend existing models (`js-node.json`, `js-http.json`, `python-stdlib.json`, `java-servlet.json`, `csharp-aspnet.json`) with sinks for the new classes. No rule files yet. | 1.5h |
| **B — New-class rules** | 15 rule JSON files + 30 fixtures + loader test extension covering SSTI (×4), NoSQL injection (×2), prototype pollution (×2), mass assignment (×2), HTTP header injection (×3), plus prototype_pollution as `kind: "pattern"` rules. | 2h |
| **C — Matrix gap fills** | 13 rule JSON files + 26 fixtures + loader test extension covering XSS (×3), log injection (×3), XXE (×3), weak crypto (×2), unsafe eval (×2). Engine sinks already exist (extend if needed). | 1.5h |

Each PR is independently buildable and testable. PRs A → B → C is the only valid order (B and C depend on A's sinks).

---

## 10. Risks & mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| New sink FQN typos in JSON cause silent no-match (rule loads but never fires) | High — false sense of coverage | Every rule has a positive fixture; CI fails if positive fixture doesn't trigger. |
| Prototype pollution as regex-pattern is noisy on legitimate `Object.assign` usage | Medium — false positives | Restrict regex to require `req.(body\|query\|params)` adjacent to merge call. False-positive rate is monitored via the negative fixture. Future upgrade to dedicated analyzer noted in `risks/issues.md`. |
| Mass assignment rule on Express may flag legitimate API endpoints | Medium — alarm fatigue | Confidence base set to 0.5 (medium) instead of 0.85; rule docs explain the field-allowlist remediation. |
| Acceptance test threshold becomes brittle | Low | Convert hardcoded count to `≥ N` ranges; document in test comments. |

---

## 11. Open questions

(None — all addressed during brainstorming.)
