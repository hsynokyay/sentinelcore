# Remediation Pack Authoring Guide

## Overview

Every SentinelCore SAST/secret rule can have a deterministic remediation pack
that provides structured developer guidance. Packs are JSON files embedded in
the binary at build time via `//go:embed`.

## File location

```
internal/remediation/packs/<RULE_ID>.json
```

Example: `internal/remediation/packs/SC-JAVA-SQL-001.json`

## Schema

```json
{
  "rule_id": "SC-JAVA-SQL-001",
  "version": "1.0.0",
  "title": "SQL Injection via unsanitized input",
  "summary": "What the rule detected (1-3 sentences)",
  "why_it_matters": "Risk explanation for developers (1 paragraph)",
  "how_to_fix": "Step-by-step fix guidance with numbered steps",
  "unsafe_example": "// Code showing the anti-pattern",
  "safe_example": "// Code showing the recommended fix",
  "developer_notes": "Optional framework-specific notes",
  "verification_checklist": [
    "First thing to verify after fixing",
    "Second thing to verify"
  ],
  "references": [
    {"title": "CWE-89: SQL Injection", "url": "https://cwe.mitre.org/data/definitions/89.html"}
  ]
}
```

## Required fields

Every pack must include:
- `rule_id` — must match the rule's `rule_id` exactly
- `version` — semver, currently `1.0.0`
- `title` — short, descriptive
- `summary` — what the rule found
- `why_it_matters` — risk explanation
- `how_to_fix` — actionable guidance with numbered steps
- `unsafe_example` — code anti-pattern (generic, NOT from user's code)
- `safe_example` — code showing the fix
- `verification_checklist` — 3-6 items a reviewer checks after the fix
- `references` — at least CWE + OWASP links

## Security requirements

**CRITICAL**: Never include real secret values in examples. Use generic
placeholders:
- `"sk-live-abcdef1234567890"` is acceptable in unsafe examples as a
  *generic pattern*, but the safe example must NOT echo it back.
- Safe examples should show `System.getenv("API_KEY")` or similar.

## Content quality

- Be concise but not shallow
- Be technically correct
- Be enterprise-appropriate
- Give exact code-level guidance, not vague "sanitize input" advice
- Include framework-specific notes where relevant
- Keep consistent tone across all packs

## Adding a new pack

1. Create `internal/remediation/packs/<RULE_ID>.json`
2. Fill in all required fields
3. Run tests: `go test ./internal/remediation/`
4. The registry auto-loads via `//go:embed` — no code changes needed
5. The finding detail API will serve the pack for any finding with matching `rule_id`

## How it flows to the UI

1. SAST worker stores `rule_id` on `findings.findings` rows
2. DAST findings get `rule_id` via CWE/title-based mapping (migration 021)
3. `GET /api/v1/findings/{id}` reads `rule_id`, looks up the remediation pack
4. If found, the `remediation` block is included in the response
5. Frontend renders it in the Remediation Guidance section
6. Findings without a `rule_id` (or with an unmapped rule) get no remediation block

## Current coverage

### SAST rules (5 packs)

| Rule ID | Class | Status |
|---|---|---|
| SC-JAVA-SQL-001 | SQL Injection | ✅ |
| SC-JAVA-CMD-001 | Command Injection | ✅ |
| SC-JAVA-PATH-001 | Path Traversal | ✅ |
| SC-JAVA-CRYPTO-001 | Weak Crypto | ✅ |
| SC-JAVA-SECRET-001 | Hardcoded Secret | ✅ |

### DAST rules (10 packs)

| Rule ID | Class | Status |
|---|---|---|
| SC-DAST-CSRF-001 | Missing CSRF Protection | ✅ |
| SC-DAST-MIXED-001 | Mixed Content | ✅ |
| SC-DAST-AUTOCOMPLETE-001 | Password Autocomplete | ✅ |
| SC-DAST-INLINE-001 | Excessive Inline Scripts | ✅ |
| SC-DAST-AUTHZ-001 | Unauthenticated Sensitive Form | ✅ |
| SC-DAST-XSS-001 | Reflected XSS | ✅ |
| SC-DAST-SSRF-001 | Server-Side Request Forgery | ✅ |
| SC-DAST-OPENREDIRECT-001 | Open Redirect | ✅ |
| SC-DAST-SECHEADERS-001 | Missing Security Headers | ✅ |
| SC-DAST-COOKIEFLAGS-001 | Insecure Cookie Flags | ✅ |

## DAST remediation tone

DAST findings are observational — the scanner observed behavior but did not
necessarily confirm exploitation. Remediation text must:
- Use "observed", "may indicate", "verify that" rather than "is definitely exploitable"
- Acknowledge that DAST findings reflect runtime behavior, not confirmed exploitation
- Provide verification steps so the reviewer can confirm the observation
- Keep language technically correct and enterprise-safe
