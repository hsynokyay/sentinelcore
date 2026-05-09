package dast

import (
	"fmt"
	"sort"
	"strings"
)

// RuleMetadata holds enterprise-grade enrichment for a DAST rule.
// It's looked up at finding-persistence time to populate the dozen-or-so
// findings.findings columns that don't fit on the wire-level Finding
// struct (CWE, OWASP, CVSS, remediation, references, tags).
//
// All fields are intentionally rule-static (do not depend on the request
// or response) — per-finding context goes in Evidence + the rendered
// description.
type RuleMetadata struct {
	// CWEID is the primary CWE classification (single ID; secondary CWEs
	// can go in description). Zero means "unmapped" and will be skipped.
	CWEID int

	// OWASPCategory is the OWASP Top 10 2021 mapping, e.g. "A03:2021".
	OWASPCategory string

	// CVSSScore is the CVSS 3.1 base score. Zero means "informational" —
	// the column is left NULL.
	CVSSScore float64

	// CVSSVector is the CVSS 3.1 base vector. Empty when CVSSScore is 0.
	CVSSVector string

	// RiskScore is the displayed risk score. We default it to CVSSScore
	// unless the rule has reason to differ (e.g. exploit availability).
	RiskScore float64

	// Tags are searchable/filterable labels. Always include "dast" plus
	// at least one category tag.
	Tags []string

	// Impact explains *why this matters* in 1-2 plain-English sentences.
	// Rendered as "**Impact:**" in the finding description.
	Impact string

	// Remediation gives a concrete fix recipe — short, actionable.
	// Rendered as "**Remediation:**" in the finding description.
	Remediation string

	// References point to authoritative documentation (OWASP, MDN, IETF).
	// Rendered as a bulleted list under "**References:**".
	References []string
}

// ruleMetadataRegistry maps rule_id → metadata. Populated at init time so
// lookups are constant-time. Adding a rule without an entry here logs a
// warning at finding-persistence time and falls back to bare metadata.
var ruleMetadataRegistry = map[string]RuleMetadata{
	// ---------- INJECTION FAMILY ----------

	"DAST-SQLI-001": {
		CWEID:         89,
		OWASPCategory: "A03:2021",
		CVSSScore:     9.8,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Tags:          []string{"injection", "sqli", "owasp:a03"},
		Impact:        "An attacker can read, modify, or destroy database contents — including credentials, customer data, and audit trails. Frequently leads to full database compromise and lateral movement into the application server.",
		Remediation:   "Use parameterized queries / prepared statements for *every* DB call. Validate input against an allow-list of expected types. Apply least-privilege DB credentials so the app cannot DROP or read system tables.",
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/89.html",
		},
	},
	"DAST-XSS-001": {
		CWEID:         79,
		OWASPCategory: "A03:2021",
		CVSSScore:     6.1,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		Tags:          []string{"injection", "xss", "owasp:a03"},
		Impact:        "Reflected/stored XSS lets an attacker execute JavaScript in another user's browser — stealing session tokens, MFA codes, or driving privileged API calls under the victim's identity.",
		Remediation:   "Output-encode user-controlled values in their target context (HTML, attribute, JS, URL). Use a templating engine that auto-escapes by default. Add a strong Content-Security-Policy as defense-in-depth.",
		References: []string{
			"https://owasp.org/Top10/A03_2021-Injection/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/79.html",
		},
	},
	"DAST-PT-001": {
		CWEID:         22,
		OWASPCategory: "A01:2021",
		CVSSScore:     7.5,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		Tags:          []string{"path_traversal", "owasp:a01"},
		Impact:        "An attacker can read arbitrary files outside the intended directory — config files with credentials, source code, /etc/passwd, cloud metadata files.",
		Remediation:   "Resolve user paths to an absolute form and verify they sit under the allowed root before opening. Reject any path containing `..` or non-canonical segments. Prefer opaque IDs over file names in URLs.",
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/22.html",
		},
	},
	"DAST-SSRF-001": {
		CWEID:         918,
		OWASPCategory: "A10:2021",
		CVSSScore:     8.6,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
		Tags:          []string{"ssrf", "owasp:a10"},
		Impact:        "The server can be coerced into reaching internal services — cloud metadata endpoints (169.254.169.254), private subnets, admin panels — exposing IAM credentials or internal API state.",
		Remediation:   "Validate URLs against an allow-list of hosts. Reject private/loopback/link-local IPs both pre-DNS and post-DNS. Use IMDSv2 on AWS so the metadata endpoint requires a session token.",
		References: []string{
			"https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
			"https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/918.html",
		},
	},
	"DAST-IDOR-001": {
		CWEID:         639,
		OWASPCategory: "A01:2021",
		CVSSScore:     6.5,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
		Tags:          []string{"access_control", "idor", "owasp:a01"},
		Impact:        "An authenticated user can read/modify another user's data by guessing or enumerating IDs. Often impacts billing, PII, and tenant isolation.",
		Remediation:   "Authorize every object access against the current user — don't rely on the URL alone. Prefer unguessable opaque IDs (UUIDs) and centralize the check in middleware so you can't forget it on a new endpoint.",
		References: []string{
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
			"https://cwe.mitre.org/data/definitions/639.html",
		},
	},
	"DAST-HI-001": {
		CWEID:         93,
		OWASPCategory: "A03:2021",
		CVSSScore:     6.5,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
		Tags:          []string{"injection", "header_injection", "owasp:a03"},
		Impact:        "An attacker can inject CRLF sequences into response headers, splitting the response — used for cache poisoning, session fixation, and bypassing security headers.",
		Remediation:   "Strip CR/LF from any header value sourced from user input. Use a framework setter that rejects illegal characters rather than building headers via string concatenation.",
		References: []string{
			"https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
			"https://cwe.mitre.org/data/definitions/93.html",
		},
	},
	"DAST-XXE-001": {
		CWEID:         611,
		OWASPCategory: "A05:2021",
		CVSSScore:     8.2,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L",
		Tags:          []string{"injection", "xxe", "owasp:a05"},
		Impact:        "An XML parser that resolves external entities lets an attacker exfiltrate local files (e.g. `/etc/passwd`), pivot to internal services (SSRF), or DoS the server with billion-laughs.",
		Remediation:   "Disable external entity resolution and DTD loading on every XML parser. In Java: `setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)`. In .NET: `XmlReaderSettings{DtdProcessing=Prohibit}`. Prefer JSON over XML where possible.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/611.html",
		},
	},
	"DAST-NOSQL-001": {
		CWEID:         943,
		OWASPCategory: "A03:2021",
		CVSSScore:     8.6,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Tags:          []string{"injection", "nosqli", "owasp:a03"},
		Impact:        "MongoDB/CouchDB-style operator injection (`$ne`, `$gt`, `$where`) bypasses authentication and dumps collections — historically responsible for major data breaches in Node.js + Mongo stacks.",
		Remediation:   "Cast all user input to the expected type before passing to the query builder. In Mongo: `mongo-sanitize` or driver-level operator stripping. Prefer ODMs that enforce schemas (Mongoose with strict mode).",
		References: []string{
			"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
			"https://cwe.mitre.org/data/definitions/943.html",
		},
	},
	"DAST-GRAPHQL-001": {
		CWEID:         200,
		OWASPCategory: "A05:2021",
		CVSSScore:     5.3,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Tags:          []string{"info_disclosure", "graphql", "owasp:a05"},
		Impact:        "Public GraphQL introspection lets attackers map the entire schema — including internal types, admin mutations, and field names that disclose business logic.",
		Remediation:   "Disable introspection in production (`introspection: false` in Apollo Server, or strip `__schema`/`__type` at the gateway). Combine with query depth/complexity limits and persisted queries.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/200.html",
		},
	},

	// ---------- AUTH / JWT ----------

	"DAST-JWT-001": {
		CWEID:         347,
		OWASPCategory: "A02:2021",
		CVSSScore:     9.8,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Tags:          []string{"auth", "jwt", "owasp:a02"},
		Impact:        "Server accepts JWTs signed with `alg: none` — anyone can forge any identity, including admins, by stripping the signature. Total auth bypass.",
		Remediation:   "Reject `alg: none` outright. Pin the expected algorithm (e.g. `RS256`) at verification time rather than trusting the JWT header. Keep your JWT library current — older versions allowed alg confusion.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc7519#section-6.1",
			"https://www.rfc-editor.org/rfc/rfc8725#section-3.1",
			"https://cwe.mitre.org/data/definitions/347.html",
		},
	},
	"DAST-JWT-002": {
		CWEID:         326,
		OWASPCategory: "A02:2021",
		CVSSScore:     8.1,
		CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Tags:          []string{"auth", "jwt", "crypto", "owasp:a02"},
		Impact:        "JWT signing key is short or low-entropy — an attacker can crack it offline (rockyou.txt + hashcat finishes in minutes) and forge arbitrary tokens.",
		Remediation:   "Use ≥256 bits of randomness for HS256 keys, or move to RS256/EdDSA with proper key storage (KMS/HSM). Rotate keys on a schedule and on suspected exposure.",
		References: []string{
			"https://www.rfc-editor.org/rfc/rfc8725#section-3.5",
			"https://cwe.mitre.org/data/definitions/326.html",
		},
	},

	// ---------- ACCESS CONTROL / DATA ----------

	"DAST-CRLF-001": {
		CWEID:         93,
		OWASPCategory: "A03:2021",
		CVSSScore:     6.1,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		Tags:          []string{"injection", "crlf", "owasp:a03"},
		Impact:        "User input ends up in a response header without CR/LF stripping, letting an attacker split the response — enabling cache poisoning and session fixation.",
		Remediation:   "Use the framework's header-setting API (which rejects illegal characters) rather than concatenating strings. Strip `\\r` and `\\n` at the boundary if you must accept the value.",
		References: []string{
			"https://owasp.org/www-community/attacks/HTTP_Response_Splitting",
			"https://cwe.mitre.org/data/definitions/93.html",
		},
	},
	"DAST-OPENREDIR-001": {
		CWEID:         601,
		OWASPCategory: "A01:2021",
		CVSSScore:     6.1,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
		Tags:          []string{"access_control", "open_redirect", "owasp:a01"},
		Impact:        "An attacker can craft a link to your domain that redirects victims to a phishing page. Severely undermines URL-trust signals (browser warnings, DKIM, password-manager autofill).",
		Remediation:   "Validate redirect targets against an allow-list of known paths/hosts. If you must accept a `next=` parameter, require it to be a relative path (start with `/`) and reject anything containing `://`.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/601.html",
		},
	},
	"DAST-MASS-001": {
		CWEID:         915,
		OWASPCategory: "A04:2021",
		CVSSScore:     7.5,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
		Tags:          []string{"access_control", "mass_assignment", "owasp:a04"},
		Impact:        "API binds request JSON directly to backing models, letting an attacker set fields they shouldn't (`is_admin: true`, `org_id: <other>`) by adding extra keys to the payload.",
		Remediation:   "Define explicit DTOs for inbound requests — never bind raw JSON to an ORM model. Use allow-lists on inbound fields, not deny-lists. Validate authorization-relevant fields are read-only via a schema, not via runtime checks.",
		References: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html",
			"https://cwe.mitre.org/data/definitions/915.html",
		},
	},
	"DAST-PROTO-POL-001": {
		CWEID:         1321,
		OWASPCategory: "A03:2021",
		CVSSScore:     7.5,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Tags:          []string{"injection", "prototype_pollution", "owasp:a03"},
		Impact:        "JavaScript merge/clone helpers walk into `__proto__` and write to `Object.prototype` — every object in the runtime gets the attacker-controlled property. Frequently chains into RCE.",
		Remediation:   "Use a merge library that explicitly rejects `__proto__`/`constructor`/`prototype` keys (`lodash.mergeWith` with a sanitizer, or `Object.create(null)` for parsed bags). Update Node + libs that have known pollution CVEs.",
		References: []string{
			"https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf",
			"https://cwe.mitre.org/data/definitions/1321.html",
		},
	},

	// ---------- PASSIVE: HEADERS ----------

	"DAST-HEAD-CSP-001": {
		CWEID:         693,
		OWASPCategory: "A05:2021",
		CVSSScore:     4.3,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
		Tags:          []string{"headers", "security_misconfig", "passive", "owasp:a05"},
		Impact:        "Without Content-Security-Policy, an XSS injection has no policy-level mitigation — every script the page loads is implicitly trusted.",
		Remediation:   "Send a strict CSP header on every HTML response. Start with `default-src 'self'; script-src 'self' 'nonce-<random>'; object-src 'none'; base-uri 'self'` and tighten from there.",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
			"https://owasp.org/www-project-secure-headers/#content-security-policy",
		},
	},
	"DAST-HEAD-HSTS-001": {
		CWEID:         319,
		OWASPCategory: "A02:2021",
		CVSSScore:     5.3,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Tags:          []string{"headers", "crypto", "passive", "owasp:a02"},
		Impact:        "Without HSTS, a network attacker can downgrade clients to plain HTTP on first visit (sslstrip) and intercept traffic before TLS is established.",
		Remediation:   "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` on every HTTPS response. Apply for inclusion in the HSTS preload list once you've verified no subdomain breaks.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc6797",
			"https://hstspreload.org/",
		},
	},
	"DAST-HEAD-XFO-001": {
		CWEID:         1021,
		OWASPCategory: "A05:2021",
		CVSSScore:     4.3,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
		Tags:          []string{"headers", "clickjacking", "security_misconfig", "passive", "owasp:a05"},
		Impact:        "Without X-Frame-Options or a frame-ancestors CSP directive, the page can be embedded in an attacker iframe and used for clickjacking — tricking users into authorizing destructive actions.",
		Remediation:   "Send `X-Frame-Options: DENY` (or `SAMEORIGIN` if you legitimately frame yourself), or — better — use `Content-Security-Policy: frame-ancestors 'none'`.",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
			"https://owasp.org/www-community/attacks/Clickjacking",
		},
	},
	"DAST-HEAD-XCTO-001": {
		CWEID:         693,
		OWASPCategory: "A05:2021",
		CVSSScore:     3.7,
		CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
		Tags:          []string{"headers", "security_misconfig", "passive", "owasp:a05"},
		Impact:        "Without `X-Content-Type-Options: nosniff`, browsers may MIME-sniff a response — turning an attacker-controlled upload into executable JS or a stylesheet.",
		Remediation:   "Send `X-Content-Type-Options: nosniff` on every response. Always set explicit `Content-Type` headers (don't rely on browser detection).",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
			"https://owasp.org/www-project-secure-headers/#x-content-type-options",
		},
	},
	"DAST-HEAD-REFER-001": {
		CWEID:         200,
		OWASPCategory: "A01:2021",
		CVSSScore:     3.1,
		CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Tags:          []string{"headers", "info_disclosure", "passive", "owasp:a01"},
		Impact:        "Without an explicit Referrer-Policy, full URLs (including query strings with sensitive tokens) leak to third-party origins via the `Referer` header.",
		Remediation:   "Send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for stricter posture).",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
		},
	},
	"DAST-HEAD-PERM-001": {
		CWEID:         693,
		OWASPCategory: "A05:2021",
		CVSSScore:     0,
		Tags:          []string{"headers", "security_misconfig", "passive", "owasp:a05"},
		Impact:        "Without Permissions-Policy, sensitive browser APIs (camera, microphone, geolocation, payment) are not actively restricted, leaving them open to abuse from injected scripts or compromised dependencies.",
		Remediation:   "Send `Permissions-Policy` denying features you don't need, e.g. `camera=(), microphone=(), geolocation=(), payment=()`. Allow specific origins only where required.",
		References: []string{
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
			"https://www.w3.org/TR/permissions-policy/",
		},
	},
	"DAST-HEAD-SERVER-001": {
		CWEID:         200,
		OWASPCategory: "A05:2021",
		CVSSScore:     3.7,
		CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Tags:          []string{"headers", "info_disclosure", "passive", "owasp:a05"},
		Impact:        "Server header includes a software version — attackers can map straight from version to known CVEs without any probing.",
		Remediation:   "Strip the version from your Server header (nginx: `server_tokens off`; Apache: `ServerTokens Prod`; IIS: remove via URL Rewrite). Or omit the header entirely at the edge proxy.",
		References: []string{
			"https://owasp.org/www-project-secure-headers/#server",
		},
	},
	"DAST-HEAD-XPOWERED-001": {
		CWEID:         200,
		OWASPCategory: "A05:2021",
		CVSSScore:     3.7,
		CVSSVector:    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
		Tags:          []string{"headers", "info_disclosure", "passive", "owasp:a05"},
		Impact:        "X-Powered-By advertises the runtime/framework (PHP, ASP.NET, Express, Next.js) — attackers can target known issues without fingerprinting first.",
		Remediation:   "Disable the framework's auto-inserted X-Powered-By: in Express `app.disable('x-powered-by')`, in PHP `expose_php = Off`, in Next.js `poweredByHeader: false`. Or strip at the edge proxy.",
		References: []string{
			"https://owasp.org/www-project-secure-headers/#x-powered-by",
		},
	},

	// ---------- PASSIVE: COOKIES ----------

	"DAST-COOKIE-SECURE-001": {
		CWEID:         614,
		OWASPCategory: "A02:2021",
		CVSSScore:     5.4,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
		Tags:          []string{"cookies", "crypto", "passive", "owasp:a02"},
		Impact:        "Cookie set without `Secure` over HTTPS will be sent over plain HTTP if the site ever serves on HTTP — exposing sessions to network attackers.",
		Remediation:   "Always set `Secure` on cookies issued over HTTPS. Use the `__Host-` cookie prefix to enforce this at the browser level.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.2.5",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#restrict_access_to_cookies",
		},
	},
	"DAST-COOKIE-HTTPONLY-001": {
		CWEID:         1004,
		OWASPCategory: "A05:2021",
		CVSSScore:     5.4,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
		Tags:          []string{"cookies", "security_misconfig", "passive", "owasp:a05"},
		Impact:        "Cookie without `HttpOnly` is readable by JavaScript — any XSS goes from \"can run JS\" to \"can steal the session\".",
		Remediation:   "Set `HttpOnly` on every cookie used for authentication or session state.",
		References: []string{
			"https://owasp.org/www-community/HttpOnly",
			"https://cwe.mitre.org/data/definitions/1004.html",
		},
	},
	"DAST-COOKIE-SAMESITE-001": {
		CWEID:         1275,
		OWASPCategory: "A05:2021",
		CVSSScore:     4.3,
		CVSSVector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
		Tags:          []string{"cookies", "csrf", "passive", "owasp:a05"},
		Impact:        "Cookie without an explicit `SameSite` attribute relies on the browser default — historically `None`, which leaves you exposed to CSRF on older clients.",
		Remediation:   "Set `SameSite=Lax` (good default) or `SameSite=Strict` (best for high-value cookies). Avoid `SameSite=None` unless you genuinely need cross-site usage and pair it with `Secure`.",
		References: []string{
			"https://datatracker.ietf.org/doc/html/draft-west-cookie-incrementalism-00",
			"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
		},
	},
}

// LookupRuleMetadata returns the registry entry for a rule_id, or a zero
// value with Tags=["dast","unmapped"] when the rule is unknown. Always
// returns non-nil — callers don't need to nil-check.
func LookupRuleMetadata(ruleID string) RuleMetadata {
	if m, ok := ruleMetadataRegistry[ruleID]; ok {
		// Make sure dast tag is always present, then ensure determinism.
		m.Tags = withDastTag(m.Tags)
		if m.RiskScore == 0 {
			m.RiskScore = m.CVSSScore
		}
		return m
	}
	return RuleMetadata{
		Tags: []string{"dast", "unmapped"},
	}
}

func withDastTag(tags []string) []string {
	out := make([]string, 0, len(tags)+1)
	hasDast := false
	for _, t := range tags {
		if t == "dast" {
			hasDast = true
		}
		out = append(out, t)
	}
	if !hasDast {
		out = append(out, "dast")
	}
	sort.Strings(out)
	return out
}

// RenderDescription produces the markdown body that goes into
// findings.findings.description. Sections are stable so the UI can render
// them with consistent styling.
//
// Layout:
//
//	What was observed: <matcher reason>
//
//	**Impact**
//	<impact paragraph>
//
//	**Remediation**
//	<remediation paragraph>
//
//	**References**
//	- <ref 1>
//	- <ref 2>
//
// matchDetail is the per-finding detail from the matcher (e.g.
// "X-Powered-By disclosed: Next.js"); it grounds the description in the
// actual evidence rather than the generic rule text.
func (m RuleMetadata) RenderDescription(matchDetail string) string {
	var b strings.Builder

	if matchDetail != "" {
		b.WriteString("**What was observed:** ")
		b.WriteString(matchDetail)
		b.WriteString("\n\n")
	}

	if m.Impact != "" {
		b.WriteString("**Impact**\n\n")
		b.WriteString(m.Impact)
		b.WriteString("\n\n")
	}

	if m.Remediation != "" {
		b.WriteString("**Remediation**\n\n")
		b.WriteString(m.Remediation)
		b.WriteString("\n\n")
	}

	if len(m.References) > 0 {
		b.WriteString("**References**\n\n")
		for _, ref := range m.References {
			fmt.Fprintf(&b, "- %s\n", ref)
		}
	}

	return strings.TrimRight(b.String(), "\n")
}
