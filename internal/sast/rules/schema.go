// Package rules defines the SentinelCore SAST rule schema and loader.
//
// Rules are JSON documents with stable metadata (CWE, OWASP, severity,
// remediation text) and a detection specification. Chunk SAST-1 supports
// only one detection kind — `ast_call` — which matches method-call
// instructions in the IR by (receiver_type, callee, argument patterns).
// Later chunks add:
//
//   - `ast_new`         — constructor pattern matching
//   - `taint`           — source→sink with sanitizer list (Chunk SAST-3)
//   - `ast_field_assign` — hardcoded-credential patterns (Chunk SAST-2)
//
// Every rule carries enough metadata that a finding emitted by the engine
// can round-trip into the existing findings.findings table without the
// engine knowing anything about the database.
package rules

// Rule is the top-level rule document.
type Rule struct {
	RuleID      string              `json:"rule_id"`
	Name        string              `json:"name"`
	Language    string              `json:"language"`
	CWE         []string            `json:"cwe,omitempty"`
	OWASP       []string            `json:"owasp,omitempty"`
	Severity    string              `json:"severity"` // critical|high|medium|low|info
	Description string              `json:"description"`
	Remediation string              `json:"remediation"`
	References  []string            `json:"references,omitempty"`
	Detection   Detection           `json:"detection"`
	Confidence  ConfidenceModel     `json:"confidence"`
	Examples    map[string]string   `json:"examples,omitempty"`
}

// Detection describes what the engine should match.
type Detection struct {
	Kind           DetectionKind   `json:"kind"`
	Patterns       []CallPattern   `json:"patterns,omitempty"`        // for ast_call
	AssignPatterns []AssignPattern `json:"assign_patterns,omitempty"` // for ast_assign
	VulnClass      string          `json:"vuln_class,omitempty"`      // for taint
}

// AssignPattern matches Store instructions where the variable name and the
// assigned string value both pass heuristic checks. Used for hardcoded-secret
// detection.
type AssignPattern struct {
	// NameMatchesAny: regex list that the variable/field name must match.
	NameMatchesAny []string `json:"name_matches_any"`
	// MinValueLength: minimum string-literal length to consider.
	MinValueLength int `json:"min_value_length,omitempty"`
	// ValuePrefixesAny: if non-empty, the value must start with one of these.
	ValuePrefixesAny []string `json:"value_prefixes_any,omitempty"`
	// ExcludeValues: values matching these patterns are excluded (placeholders).
	ExcludeValues []string `json:"exclude_values,omitempty"`
	// RequireEntropy: if true, reject low-entropy values (e.g. "test", "admin").
	RequireEntropy bool `json:"require_entropy,omitempty"`
	MessageTemplate string `json:"message_template,omitempty"`
}

// DetectionKind is the discriminator for Detection. New kinds are additive
// — adding a kind does not break existing rules.
type DetectionKind string

const (
	DetectionASTCall   DetectionKind = "ast_call"
	DetectionASTAssign DetectionKind = "ast_assign"
	DetectionTaint     DetectionKind = "taint"
)

// CallPattern matches a Call instruction in the IR. All non-empty fields
// must match; empty fields are wildcards.
//
// ReceiverFQN matches the declared type of the call receiver exactly.
// Callee matches the simple method name.
// If ArgIndex is set and ArgMatchesAny is non-empty, the operand at
// ArgIndex must be a string literal matching at least one of the supplied
// regular expressions.
type CallPattern struct {
	ReceiverFQN   string   `json:"receiver_fqn,omitempty"`
	Callee        string   `json:"callee,omitempty"`
	CalleeFQN     string   `json:"callee_fqn,omitempty"`
	ArgIndex      *int     `json:"arg_index,omitempty"`
	ArgMatchesAny []string `json:"arg_matches_any,omitempty"`
	// MessageTemplate is a human-readable description used in the finding
	// title when this pattern fires. Supports the placeholder {{arg}} which
	// expands to the matched string literal.
	MessageTemplate string `json:"message_template,omitempty"`
}

// ConfidenceModel computes a [0, 1] score per finding from real signals.
// Chunk SAST-1 only uses Base — the engine clamps the output to [0, 1].
// The full confidence model (path length, sanitizer bypass, call-chain
// crossings) lands with the taint engine.
type ConfidenceModel struct {
	Base float64 `json:"base"`
}
