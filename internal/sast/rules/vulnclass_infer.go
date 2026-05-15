package rules

import (
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/vulnclass"
)

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
//
// Sprint 1.3 P1-4 normalized the heuristic's return values to the
// canonical lowercase snake_case form so that inferred values dedup
// against explicit JSON values. Before this change the heuristic
// returned `SQL_INJECTION` while explicit rules used `sql_injection`,
// silently breaking semantic dedup across those two sources.

// vulnClassByRuleIDToken maps the canonical rule_id token (the third
// hyphen-separated segment of a rule_id, e.g. "SQL" in
// "SC-JAVA-SQL-001") to a stable vuln_class identifier. Tokens are
// upper-cased before lookup. Multiple tokens may map to the same
// vuln_class — this is intentional (`SECRET`, `CREDS`, `KEY` all denote
// "hardcoded credential" and must share a vuln_class so they dedup
// against each other).
//
// Values are vulnclass.VulnClass constants — typed lookup so a new
// vuln_class added here without a corresponding registry entry is a
// compile error rather than a silent dedup hazard.
var vulnClassByRuleIDToken = map[string]vulnclass.VulnClass{
	// Injection family
	"SQL":   vulnclass.SQLInjection,
	"SQLI":  vulnclass.SQLInjection,
	"CMD":   vulnclass.CommandInjection,
	"LDAP":  vulnclass.LDAPInjection,
	"XPATH": vulnclass.XPathInjection,
	"NOSQL": vulnclass.NoSQLInjection,
	"SSTI":  vulnclass.TemplateInjection,
	"EL":    vulnclass.ExpressionInjection,
	"EVAL":  vulnclass.UnsafeEval,
	"PROTO": vulnclass.PrototypePollution,
	"INJ":   vulnclass.GenericInjection,

	// XSS / output-encoding
	"XSS": vulnclass.XSS,

	// Path / file
	"PATH":    vulnclass.PathTraversal,
	"FILE":    vulnclass.PathTraversal,
	"ZIPSLIP": vulnclass.PathTraversal,

	// SSRF / redirect
	"SSRF":      vulnclass.SSRF,
	"REDIRECT":  vulnclass.OpenRedirect,
	"OPENREDIR": vulnclass.OpenRedirect,

	// XXE / XML
	"XXE": vulnclass.XXE,
	"XML": vulnclass.XXE,

	// Crypto / randomness
	"CRYPTO": vulnclass.WeakCrypto,
	"HASH":   vulnclass.WeakCrypto,
	"CIPHER": vulnclass.WeakCrypto,
	"TLS":    vulnclass.InsecureTLS,
	"RAND":   vulnclass.InsecureRandom,

	// Auth / session — every "credential / signing key / token" detector
	// collapses to HardcodedSecret so the JWT-secret rule and the
	// generic-secret rule dedup on the same line.
	"SECRET":     vulnclass.HardcodedSecret,
	"CREDS":      vulnclass.HardcodedSecret,
	"KEY":        vulnclass.HardcodedSecret,
	"JWT":        vulnclass.HardcodedSecret,
	"AUTH":       vulnclass.AuthBypass,
	"AUTHZ":      vulnclass.AuthzBypass,
	"AUTHHEADER": vulnclass.AuthHeaderInjection,
	"HEADER":     vulnclass.HTTPHeaderInjection,
	"SESSION":    vulnclass.InsecureSession,
	"COOKIE":     vulnclass.InsecureCookie,
	"CSRF":       vulnclass.MissingCSRF,

	// Deserialization
	"DESER":  vulnclass.UnsafeDeserialization,
	"SERIAL": vulnclass.UnsafeDeserialization,
	"PICKLE": vulnclass.UnsafeDeserialization,
	"YAML":   vulnclass.UnsafeDeserialization,

	// Logging / privacy / mass-assignment / misc
	"LOG":    vulnclass.LogInjection,
	"PII":    vulnclass.PIIExposure,
	"PRIV":   vulnclass.PIIExposure,
	"MASS":   vulnclass.MassAssignment,
	"ERR":    vulnclass.InfoDisclosure,
	"MEM":    vulnclass.MemorySafety,
	"BUF":    vulnclass.MemorySafety,
	"NULL":   vulnclass.NullDeref,
	"RACE":   vulnclass.RaceCondition,
	"TOCTOU": vulnclass.RaceCondition,
	"CONC":   vulnclass.RaceCondition,
	"VAL":    vulnclass.InputValidation,
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
			return string(vc)
		}
	}
	return "RULE:" + ruleID
}
