package rules

import "strings"

// vulnclass_infer.go is a TEMPORARY heuristic bridge. The 48 AST_CALL and
// AST_ASSIGN builtin rules carry no explicit `vuln_class` field; the
// engine needs one for Sprint 1.2's dedup canonical key. Sprint 2+ will
// add explicit `vuln_class` to every new rule, and editing the existing
// 48 rules' JSON falls outside Sprint 1.2's scope, so this heuristic
// derives a vuln_class from the rule_id.
//
// **This file should be deleted (or its function reduced to a no-op)
// once every builtin rule sets `vuln_class` explicitly.** The contract
// is intentionally one-way: MigrateInPlace only invokes the heuristic
// when no explicit value is present. Authors who set `vuln_class` (or
// `detection.vuln_class` for legacy taint rules) bypass it entirely.

// vulnClassByRuleIDToken maps the canonical rule_id token (the third
// hyphen-separated segment of a rule_id, e.g. "SQL" in
// "SC-JAVA-SQL-001") to a stable vuln_class identifier. Tokens are
// upper-cased before lookup. Multiple tokens may map to the same
// vuln_class — this is intentional (`SECRET`, `CREDS`, `KEY` all denote
// "hardcoded credential" and must share a vuln_class so they dedup
// against each other).
//
// The vuln_class names use UPPER_SNAKE convention to make them
// distinguishable from `Category` values (which use lowercase) at a
// glance during debugging.
var vulnClassByRuleIDToken = map[string]string{
	// Injection family
	"SQL":   "SQL_INJECTION",
	"SQLI":  "SQL_INJECTION",
	"CMD":   "COMMAND_INJECTION",
	"LDAP":  "LDAP_INJECTION",
	"XPATH": "XPATH_INJECTION",
	"NOSQL": "NOSQL_INJECTION",
	"SSTI":  "TEMPLATE_INJECTION",
	"EL":    "EXPRESSION_INJECTION",
	"EVAL":  "UNSAFE_EVAL",
	"PROTO": "PROTOTYPE_POLLUTION",
	"INJ":   "GENERIC_INJECTION",

	// XSS / output-encoding
	"XSS": "XSS",

	// Path / file
	"PATH":    "PATH_TRAVERSAL",
	"FILE":    "PATH_TRAVERSAL",
	"ZIPSLIP": "PATH_TRAVERSAL",

	// SSRF / redirect
	"SSRF":      "SSRF",
	"REDIRECT":  "OPEN_REDIRECT",
	"OPENREDIR": "OPEN_REDIRECT",

	// XXE / XML
	"XXE": "XXE",
	"XML": "XXE",

	// Crypto / randomness
	"CRYPTO": "WEAK_CRYPTO",
	"HASH":   "WEAK_CRYPTO",
	"CIPHER": "WEAK_CRYPTO",
	"TLS":    "INSECURE_TLS",
	"RAND":   "INSECURE_RANDOM",

	// Auth / session — every "credential / signing key / token" detector
	// collapses to HARDCODED_SECRET so the JWT-secret rule and the
	// generic-secret rule dedup on the same line.
	"SECRET":     "HARDCODED_SECRET",
	"CREDS":      "HARDCODED_SECRET",
	"KEY":        "HARDCODED_SECRET",
	"JWT":        "HARDCODED_SECRET",
	"AUTH":       "AUTH_BYPASS",
	"AUTHZ":      "AUTHZ_BYPASS",
	"AUTHHEADER": "AUTH_HEADER_INJECTION",
	"HEADER":     "HTTP_HEADER_INJECTION",
	"SESSION":    "INSECURE_SESSION",
	"COOKIE":     "INSECURE_COOKIE",
	"CSRF":       "MISSING_CSRF",

	// Deserialization
	"DESER":  "UNSAFE_DESERIALIZATION",
	"SERIAL": "UNSAFE_DESERIALIZATION",
	"PICKLE": "UNSAFE_DESERIALIZATION",
	"YAML":   "UNSAFE_DESERIALIZATION",

	// Logging / privacy / mass-assignment / misc
	"LOG":    "LOG_INJECTION",
	"PII":    "PII_EXPOSURE",
	"PRIV":   "PII_EXPOSURE",
	"MASS":   "MASS_ASSIGNMENT",
	"ERR":    "INFO_DISCLOSURE",
	"MEM":    "MEMORY_SAFETY",
	"BUF":    "MEMORY_SAFETY",
	"NULL":   "NULL_DEREF",
	"RACE":   "RACE_CONDITION",
	"TOCTOU": "RACE_CONDITION",
	"CONC":   "RACE_CONDITION",
	"VAL":    "INPUT_VALIDATION",
}

// InferVulnClass returns a stable vulnerability classification for the
// given rule_id. It tries each segment from index 2 onward (the same
// probe order inferCategoryFromRuleID uses) so legacy IDs like
// `SC-JAVA-DESER-001` (token at index 2) and modern compound IDs like
// `SC-PY-DESER-PICKLE-001` (still index 2 wins) both classify
// correctly.
//
// If no segment matches the heuristic table, the rule's *own* rule_id
// is returned with a `RULE:` prefix. This is deliberate: a sentinel like
// "UNKNOWN" would group every unmappable rule into one bucket and cause
// the dedup pass to silently collapse semantically distinct findings
// from different rules. Returning the rule_id guarantees a rule that
// can't be classified only ever dedups against itself.
//
// Callers should treat the return value as opaque — equal strings mean
// "same vuln_class for dedup purposes", inequality means "keep both".
func InferVulnClass(ruleID string) string {
	parts := strings.Split(ruleID, "-")
	if len(parts) < 3 {
		return "RULE:" + ruleID
	}
	for i := 2; i < len(parts)-1; i++ {
		if vc, ok := vulnClassByRuleIDToken[strings.ToUpper(parts[i])]; ok {
			return vc
		}
	}
	return "RULE:" + ruleID
}
