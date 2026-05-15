// Package vulnclass owns the canonical SentinelCore vulnerability
// classification registry. Every Finding.VulnClass value the engine
// emits or accepts must be one of the constants defined here.
//
// Sprint 1.3 P1-4 promoted vuln_class from a free-form string field
// (with two coexisting case conventions — lowercase in builtin JSON
// rules, UPPER_SNAKE in the rules/vulnclass_infer.go heuristic) to a
// typed, validated identifier. The canonical form is **lowercase
// snake_case**: it matches the long-standing JSON convention and so
// avoids a corpus-wide migration of the explicit-vuln_class rules.
//
// Authors of new rules pass these constants (as strings) into the
// rule's `vuln_class` JSON field. The rule loader's MigrateInPlace
// pass and the dedup pass both validate against IsValid; any string
// not in the registry causes the loader to reject the rule at startup,
// not silently dedup against itself at scan time.
package vulnclass

// VulnClass is a stable identifier for a class of vulnerabilities. The
// underlying type is string so callers can continue to compare with
// rule JSON fields and database columns without conversion, but every
// value the engine accepts must round-trip through IsValid.
type VulnClass string

// Canonical vulnerability classes. Each constant's string value is the
// stable identifier used in rule JSONs, the severity policy YAML, and
// the findings.findings database column. Names use UPPER_CAMEL on the
// Go side and lowercase snake_case on the string side; lexicographic
// ordering of the consts is by family (injection → output encoding →
// path/file → SSRF → XXE → crypto → auth → deserialization → logging
// → misc) so adding a new class lands next to its peers.
const (
	// --- Injection family ---
	SQLInjection        VulnClass = "sql_injection"
	CommandInjection    VulnClass = "command_injection"
	LDAPInjection       VulnClass = "ldap_injection"
	XPathInjection      VulnClass = "xpath_injection"
	NoSQLInjection      VulnClass = "nosql_injection"
	ExpressionInjection VulnClass = "expression_injection"
	GenericInjection    VulnClass = "generic_injection"
	TemplateInjection   VulnClass = "template_injection"
	UnsafeEval          VulnClass = "unsafe_eval"
	PrototypePollution  VulnClass = "prototype_pollution"

	// --- Output encoding ---
	XSS VulnClass = "xss"

	// --- Path / file ---
	PathTraversal VulnClass = "path_traversal"

	// --- SSRF / redirect ---
	SSRF         VulnClass = "ssrf"
	OpenRedirect VulnClass = "open_redirect"

	// --- XML ---
	XXE VulnClass = "xxe"

	// --- Crypto / randomness ---
	WeakCrypto     VulnClass = "weak_crypto"
	InsecureTLS    VulnClass = "insecure_tls"
	InsecureRandom VulnClass = "insecure_random"

	// --- Auth / session / cookie ---
	HardcodedSecret     VulnClass = "hardcoded_secret"
	AuthBypass          VulnClass = "auth_bypass"
	AuthzBypass         VulnClass = "authz_bypass"
	AuthHeaderInjection VulnClass = "auth_header_injection"
	HTTPHeaderInjection VulnClass = "http_header_injection"
	InsecureSession     VulnClass = "insecure_session"
	InsecureCookie      VulnClass = "insecure_cookie"
	MissingCSRF         VulnClass = "missing_csrf"

	// --- Deserialization ---
	UnsafeDeserialization VulnClass = "unsafe_deserialization"

	// --- Logging / privacy / misc ---
	LogInjection     VulnClass = "log_injection"
	SensitiveLogging VulnClass = "sensitive_logging"
	PIIExposure      VulnClass = "pii_exposure"
	MassAssignment   VulnClass = "mass_assignment"
	InfoDisclosure   VulnClass = "info_disclosure"
	MemorySafety     VulnClass = "memory_safety"
	NullDeref        VulnClass = "null_deref"
	RaceCondition    VulnClass = "race_condition"
	InputValidation  VulnClass = "input_validation"
)

// all enumerates every canonical VulnClass in stable order. Used by
// IsValid and by callers that need to iterate the registry (severity
// policy validator, scorecard generator, schema export).
var all = []VulnClass{
	SQLInjection,
	CommandInjection,
	LDAPInjection,
	XPathInjection,
	NoSQLInjection,
	ExpressionInjection,
	GenericInjection,
	TemplateInjection,
	UnsafeEval,
	PrototypePollution,
	XSS,
	PathTraversal,
	SSRF,
	OpenRedirect,
	XXE,
	WeakCrypto,
	InsecureTLS,
	InsecureRandom,
	HardcodedSecret,
	AuthBypass,
	AuthzBypass,
	AuthHeaderInjection,
	HTTPHeaderInjection,
	InsecureSession,
	InsecureCookie,
	MissingCSRF,
	UnsafeDeserialization,
	LogInjection,
	SensitiveLogging,
	PIIExposure,
	MassAssignment,
	InfoDisclosure,
	MemorySafety,
	NullDeref,
	RaceCondition,
	InputValidation,
}

// validSet is the registry as a lookup map. Initialized once at
// package load; never mutated. Reads are concurrency-safe without a
// lock.
var validSet = func() map[VulnClass]struct{} {
	m := make(map[VulnClass]struct{}, len(all))
	for _, v := range all {
		m[v] = struct{}{}
	}
	return m
}()

// IsValid reports whether vc is in the canonical registry. Use this in
// validation paths — rule loaders, dedup pre-checks, severity policy
// loader — to reject unrecognized vuln_class values at the boundary
// rather than letting them pollute dedup keys or findings storage.
func IsValid(vc VulnClass) bool {
	_, ok := validSet[vc]
	return ok
}

// IsValidString is a convenience wrapper for callers that hold the
// vuln_class as a plain string (e.g. JSON decoders, DB row scanners).
// Equivalent to IsValid(VulnClass(s)).
func IsValidString(s string) bool {
	return IsValid(VulnClass(s))
}

// All returns a copy of the registry. The slice is freshly allocated
// so callers may sort or mutate it without affecting the canonical
// order. Order is stable across calls.
func All() []VulnClass {
	out := make([]VulnClass, len(all))
	copy(out, all)
	return out
}

// scorecardOrder lists the high-signal vuln_classes that the SAST
// benchmark scorecard prints, in display priority order. It is a
// curated subset of All() — classes with zero or minimal bench corpus
// coverage are omitted so the scorecard stays readable. When new bench
// corpus cases land for a class, add it here. When a class moves from
// curated to canonical-all, this stays small intentionally.
var scorecardOrder = []VulnClass{
	SQLInjection,
	CommandInjection,
	PathTraversal,
	WeakCrypto,
	HardcodedSecret,
	SSRF,
	OpenRedirect,
	XSS,
	UnsafeEval,
	UnsafeDeserialization,
}

// ScorecardOrder returns a copy of the curated scorecard display
// order. Used by internal/sast/bench/bench.go's PrintScorecard and
// ScorecardMarkdown so the order list isn't duplicated and so new
// vuln_classes added to the bench corpus auto-flow into the report by
// changing one slice here.
func ScorecardOrder() []VulnClass {
	out := make([]VulnClass, len(scorecardOrder))
	copy(out, scorecardOrder)
	return out
}
